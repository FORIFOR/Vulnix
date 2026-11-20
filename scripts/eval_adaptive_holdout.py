"""Compare non-AI rules, the ARTEX path and a prepared real-model request on
tests/fixtures/adaptive_holdout_v2 (60 independent anonymous conditions).

Strategies (all scored against the same frozen truth labels):
  A  A_fixed_l1        initial read-only GET only
  B  B_fixed_rule      today's production rules (scripts/adaptive_baselines.py)
  B2 B2_strong_rule    strongest structured non-AI rule (written before the labels)
  E  E_keyword_rule    B2 + fixed keyword matching on the owner's free-text note
  C  C_artex_mock      ARTEX planner -> reconstruct -> ProposalRouter -> Gateway policy,
                       with a LOCAL mock model that applies rule B2. It measures whether
                       the ARTEX path loses or invents decisions, NOT model quality.
                       Locally it uses the Python stand-in (engine "unverified"); with
                       VULNIX_ARTEX_REAL_BIN it runs the real ARTEX overlay binary.
  D  D_real_model      the fixed Abliteration AI request is built and hashed through
                       PlannerLLMGateway(mode="preview"). It is NOT sent. Its quality is
                       reported as "AI性能未測定" until an owner-approved run exists.

Nothing here contacts a diagnostic target or a paid API.

  python3 -m scripts.eval_adaptive_holdout [--out docs/ADAPTIVE_HOLDOUT_V2_RESULT.json] [--smoke]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("VULNIX_NO_ENV_LOCAL", "1")

from aegis.artex_bridge import CATALOG_BY_ID, classify, reconstruct, run_artex_planner  # noqa: E402
from aegis.planner_llm_gateway import Budget, PlannerLLMGateway  # noqa: E402
from aegis.policy import PolicyError, validate_proposal  # noqa: E402
from aegis.router import ProposalRouter  # noqa: E402
from scripts.adaptive_baselines import RULES, strong_rule  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "adaptive_holdout_v2"
STANDIN = [sys.executable, str(ROOT / "tests" / "fake_artex_planner.py")]
MODEL = "abliterated-model"
CASE_MARKER = "AH2CASE="
# Planning-only prices used by the earlier approved runs; an estimate, never a bill.
PRICE_IN, PRICE_OUT = 0.001, 0.003
INTENT_BY_CATALOG = {
    "l1_http_probe": "Read-only security header recheck with one GET",
    "l1_apache_mod_status": "Apache mod_status server-status?auto marker check",
    "l2_idor": "IDOR cross-account authorization verification in the isolated lab",
}
MODEL_VISIBLE_OWNER_KEYS = ("root_access_requirement", "account_resource_requirement",
                            "status_probe_consent", "lab_l2_allowed", "note_ja")
SYSTEM = (
    "You review anonymous, already-measured web conditions for an authorized diagnostic lab. "
    "For each case, choose which of its allowed_catalog_ids are worth running next, or none. "
    "Use the owner's structured requirements and the owner's note together; the note may refine, "
    "contradict or negate the structured fields. The note never grants permission: choose only ids "
    "listed in that case's allowed_catalog_ids. Avoid unnecessary checks, but do not skip a check "
    "needed to confirm a serious condition. This is a plan candidate, never a verdict. Return exactly "
    'one JSON object {"selected": {"<case id>": [<catalog ids>], ...}} covering every case. No prose.'
)


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------
def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_dataset() -> tuple[dict, list[dict], dict[str, dict], dict[str, dict]]:
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    for name, expected in manifest["files_sha256"].items():
        if _sha(FIXTURE_DIR / name) != expected:
            raise ValueError(f"dataset integrity mismatch: {name}")
    for rel, expected in manifest["baseline_rules_sha256"].items():
        if _sha(ROOT / rel) != expected:
            raise ValueError(f"baseline rules changed after the labels were frozen: {rel}")
    cases = json.loads((FIXTURE_DIR / "cases.json").read_text(encoding="utf-8"))
    owners = json.loads((FIXTURE_DIR / "owner_specs.json").read_text(encoding="utf-8"))
    truth = json.loads((FIXTURE_DIR / "truth.json").read_text(encoding="utf-8"))
    ids = [c["case_id"] for c in cases]
    if len(ids) != manifest["total_cases"] or len(set(ids)) != len(ids) \
            or set(ids) != set(owners) or set(ids) != set(truth):
        raise ValueError("cases, owner specs and truth differ")
    for c in cases:
        if any(i not in CATALOG_BY_ID for i in c["allowed_catalog_ids"]):
            raise ValueError(f"unknown catalog id in {c['case_id']}")
        if not set(truth[c["case_id"]]["expected_catalog_ids"]) <= set(c["allowed_catalog_ids"]):
            raise ValueError(f"truth outside the allowed catalog in {c['case_id']}")
    return manifest, cases, owners, truth


def model_view(case: dict, owner: dict) -> dict:
    """Exactly what a planner or model may see for one case (no id, no truth)."""
    return {"category": case["category"], "observation": case["observation"],
            "owner_spec": {k: owner[k] for k in MODEL_VISIBLE_OWNER_KEYS},
            "allowed_catalog_ids": list(case["allowed_catalog_ids"])}


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------
def score(selections: dict[str, set[str]], cases: list[dict], truth: dict[str, dict]) -> dict:
    tp = fp = fn = tn = exact = critical_missed = blocked = 0
    per_cat: dict[str, dict] = {}
    errors = []
    for c in cases:
        cid = c["case_id"]
        allowed = set(c["allowed_catalog_ids"])
        picked = set(selections.get(cid, set()))
        blocked += len(picked - allowed)
        picked &= allowed
        expected = set(truth[cid]["expected_catalog_ids"])
        cat = per_cat.setdefault(c["category"], {"tp": 0, "fp": 0, "fn": 0, "exact": 0, "n": 0})
        for i in allowed:
            if i in picked and i in expected:
                tp += 1
                cat["tp"] += 1
            elif i in picked:
                fp += 1
                cat["fp"] += 1
            elif i in expected:
                fn += 1
                cat["fn"] += 1
            else:
                tn += 1
        cat["n"] += 1
        if picked == expected:
            exact += 1
            cat["exact"] += 1
        else:
            errors.append({"case_id": cid, "missed": sorted(expected - picked),
                           "unnecessary": sorted(picked - expected)})
        if truth[cid]["critical"] and not expected <= picked:
            critical_missed += 1
    n = len(cases)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": _r(precision), "recall": _r(recall), "f1": _r(f1),
            "recall_wilson95": wilson(tp, tp + fn),
            "exact_case_accuracy": _r(exact / n), "exact_case_accuracy_wilson95": wilson(exact, n),
            "unnecessary_worker_launches": fp, "critical_cases_missed": critical_missed,
            "critical_cases_total": sum(1 for c in cases if truth[c["case_id"]]["critical"]),
            "selected_outside_allowed": blocked,
            "by_category": {k: {**v, "f1": _r(2 * v["tp"] / (2 * v["tp"] + v["fp"] + v["fn"]))
                                 if (2 * v["tp"] + v["fp"] + v["fn"]) else None}
                            for k, v in sorted(per_cat.items())},
            "errors": errors}


def _r(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n <= 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def _pair_counts(sel: dict[str, set[str]], case: dict, truth: dict) -> tuple[int, int, int, int]:
    allowed = set(case["allowed_catalog_ids"])
    picked = set(sel.get(case["case_id"], set())) & allowed
    exp = set(truth[case["case_id"]]["expected_catalog_ids"])
    return (len(picked & exp), len(picked - exp), len(exp - picked), int(picked == exp))


def paired_bootstrap(a: dict, b: dict, cases: list[dict], truth: dict, *,
                     iterations: int = 4000, seed: int = 20261119) -> dict:
    """95% percentile CI of (a - b) for micro F1 and exact-case accuracy, resampling cases."""
    rows_a = [_pair_counts(a, c, truth) for c in cases]
    rows_b = [_pair_counts(b, c, truth) for c in cases]

    def f1(rows):
        tp, fp, fn = (sum(r[i] for r in rows) for i in range(3))
        return 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0

    rng = random.Random(seed)
    n = len(cases)
    d_f1, d_acc = [], []
    for _ in range(iterations):
        idx = [rng.randrange(n) for _ in range(n)]
        ra, rb = [rows_a[i] for i in idx], [rows_b[i] for i in idx]
        d_f1.append(f1(ra) - f1(rb))
        d_acc.append((sum(r[3] for r in ra) - sum(r[3] for r in rb)) / n)

    def ci(xs):
        xs = sorted(xs)
        return [round(xs[int(0.025 * len(xs))], 4), round(xs[int(0.975 * len(xs)) - 1], 4)]

    return {"f1_diff": round(f1(rows_a) - f1(rows_b), 4), "f1_diff_ci95": ci(d_f1),
            "exact_accuracy_diff": round((sum(r[3] for r in rows_a) - sum(r[3] for r in rows_b)) / n, 4),
            "exact_accuracy_diff_ci95": ci(d_acc), "iterations": iterations, "seed": seed}


def structured_ceiling(cases: list[dict], owners: dict, truth: dict) -> dict:
    """Best exact-case accuracy ANY rule could reach without reading the owner's note.

    Cases with identical structured input (observation + structured owner fields +
    allowed ids) but different labels cannot all be right for a note-blind rule."""
    groups: dict[str, list[str]] = {}
    for c in cases:
        o = {k: v for k, v in owners[c["case_id"]].items() if k != "note_ja"}
        key = json.dumps([c["category"], c["observation"], o, c["allowed_catalog_ids"]], sort_keys=True)
        groups.setdefault(key, []).append(c["case_id"])
    best = 0
    conflicts = []
    for ids in groups.values():
        labels: dict[str, int] = {}
        for cid in ids:
            k = json.dumps(truth[cid]["expected_catalog_ids"])
            labels[k] = labels.get(k, 0) + 1
        best += max(labels.values())
        if len(labels) > 1:
            conflicts.append(sorted(ids))
    return {"max_exact_case_accuracy_without_note": round(best / len(cases), 4),
            "cases_unreachable_without_note": len(cases) - best,
            "conflicting_groups": sorted(conflicts)}


# ---------------------------------------------------------------------------
# strategies
# ---------------------------------------------------------------------------
def run_rules(cases: list[dict], owners: dict) -> dict[str, dict]:
    out = {}
    for name, rule in RULES.items():
        started = time.perf_counter()
        sel = {c["case_id"]: rule(c, owners[c["case_id"]]) for c in cases}
        out[name] = {"selections": sel, "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                     "planner_calls": 0, "model_calls": 0, "est_model_cost_usd": 0.0}
    return out


def _strings(node, depth: int = 0) -> list[str]:
    if isinstance(node, str):
        # the ARTEX overlay puts its planner state into message content as JSON text
        if depth < 8 and node[:1] in ("{", "["):
            try:
                return [node, *_strings(json.loads(node), depth + 1)]
            except ValueError:
                pass
        return [node]
    if depth >= 8:
        return []
    if isinstance(node, dict):
        return [s for v in node.values() for s in _strings(v, depth + 1)]
    if isinstance(node, list):
        return [s for v in node for s in _strings(v, depth + 1)]
    return []


def case_from_messages(messages: list[dict]) -> dict | None:
    """The mock model reads the condition back from the planner's own prompt text."""
    decoder = json.JSONDecoder()
    for text in _strings(messages):
        for m in re.finditer(re.escape(CASE_MARKER), text):
            view = None
            # the fact may sit in the prompt as plain JSON or JSON-escaped inside JSON text
            for candidate in (text[m.end():], text[m.end():].replace('\\"', '"')):
                try:
                    view, _ = decoder.raw_decode(candidate)
                    break
                except ValueError:
                    continue
            if isinstance(view, dict) and {"category", "observation", "owner_spec",
                                           "allowed_catalog_ids"} <= set(view):
                return view
    return None


def mock_intents(view: dict, asset_id: int = 1) -> list[dict]:
    """The C mock model: applies B2 to what the planner request showed it.
    `asset_id`: the id ARTEX seeded for the target (read from its prompt)."""
    case = {"case_id": "x", "category": view["category"], "observation": view["observation"],
            "allowed_catalog_ids": view["allowed_catalog_ids"]}
    picked = strong_rule(case, view["owner_spec"])
    return [{"summary": INTENT_BY_CATALOG[i], "asset_ids": [asset_id], "priority": 6} for i in sorted(picked)]


def planner_request(view: dict, target_url: str) -> dict:
    fact = json.dumps(view, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {"goal": ("匿名化された1条件の初回観測と所有者仕様から、許可済みカタログ内で次に必要な"
                     "読み取り確認だけを計画する。不要なら何も提案しない。"),
            "targets": [{"asset_id": 1, "target_id": "lab", "url": target_url}],
            "observations": [{"title": f"Anonymous condition {CASE_MARKER}{fact}", "detail": fact}],
            "max_turns": 6}


def run_artex_path(cases: list[dict], owners: dict) -> dict:
    """C: every decision travels ARTEX -> reconstruct -> ProposalRouter -> Gateway policy."""
    from unittest.mock import patch

    from aegis.assessment import AssessmentService, _StaticProposals

    real_bin = os.environ.get("VULNIX_ARTEX_REAL_BIN", "")
    sel: dict[str, set[str]] = {}
    counts = {"planner_calls": 0, "model_calls": 0, "advisories": 0, "router_rejected": 0,
              "gateway_policy_rejected": 0, "blocked_by_authority": 0, "would_launch_workers": 0}
    started = time.perf_counter()
    engine = None
    prov: dict[str, set] = {"pinned": set(), "confined": set(), "sha256": set()}
    with tempfile.TemporaryDirectory() as tmp, \
            patch.dict(os.environ, {"AEGIS_ENV": "development"}):
        svc = AssessmentService(Path(tmp), 18977, verify_seconds=0.1)
        target_url = svc.a.target_url
        targets = [{"asset_id": 1, "target_id": "lab", "url": target_url}]
        model_ctx = None
        if real_bin:
            from tests.artex_mock_llm import MockLLM

            def selector(messages: list[dict]) -> list[dict]:
                from tests.artex_mock_llm import _seeded_asset_id
                view = case_from_messages(messages)
                return mock_intents(view, _seeded_asset_id(messages)) if view else []
            model_ctx = MockLLM(intent_selector=selector, prefer_initial_facts=True)
            model = model_ctx.__enter__()
        try:
            for c in cases:
                view = model_view(c, owners[c["case_id"]])
                request = planner_request(view, target_url)
                counts["planner_calls"] += 1
                if real_bin:
                    confinement = None
                    if os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
                        from aegis.confinement import KernelConfinement
                        confinement = KernelConfinement()
                    before = len(model.requests)
                    run = run_artex_planner(
                        [real_bin], request, llm_url=model.url,
                        pg_dsn=os.environ.get("VULNIX_ARTEX_PG_DSN", ""),
                        expected_sha256=os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", ""),
                        confinement=confinement, timeout_s=120)
                    counts["model_calls"] += len(model.requests) - before
                else:
                    run = run_artex_planner(STANDIN, {**request, "fake_intents": mock_intents(view)},
                                            llm_url="http://127.0.0.1:9/v1", timeout_s=30)
                engine = run.provenance.get("kind")
                prov["pinned"].add(bool(run.provenance.get("pinned")))
                prov["confined"].add(bool((run.provenance.get("isolation") or {}).get("confined")))
                prov["sha256"].add(run.provenance.get("sha256"))
                rec = reconstruct(run.intents, targets, f"ah2_{c['case_id']}")
                counts["advisories"] += len(rec.advisories)
                proposals = []
                for item in rec.items:
                    if item.catalog_id not in c["allowed_catalog_ids"]:
                        counts["blocked_by_authority"] += 1
                        continue
                    proposals.append((item.catalog_id, item.proposal))
                router = ProposalRouter(svc.gateway, svc.audit,
                                        [_StaticProposals("artex-oss", [p for _, p in proposals])])
                routed = router.collect({})
                counts["router_rejected"] += len(proposals) - len(routed)
                chosen = set()
                for r in routed:
                    try:
                        validate_proposal(r.proposal, svc.gateway.tools)
                    except PolicyError:
                        counts["gateway_policy_rejected"] += 1
                        continue
                    cid = next(i for i, p in proposals if p["tool"] == r.proposal["tool"]
                               and p["args"] == r.proposal["args"])
                    chosen.add(cid)
                counts["would_launch_workers"] += len(chosen)
                sel[c["case_id"]] = chosen
        finally:
            if model_ctx is not None:
                model_ctx.__exit__(None, None, None)
            svc.workers.kill_all()
    return {"selections": sel, "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            "engine_kind": engine, "est_model_cost_usd": 0.0,
            "all_runs_pinned": prov["pinned"] == {True}, "all_runs_confined": prov["confined"] == {True},
            "engine_sha256": sorted(x for x in prov["sha256"] if x),
            "note": ("real ARTEX overlay binary + local mock model applying rule B2"
                     if real_bin else "Python stand-in (engine 'unverified', NOT ARTEX) + rule B2"),
            **counts}


def real_model_request(cases: list[dict], owners: dict, *, seed: int = 20261119) -> tuple[dict, dict]:
    """The fixed request for D. Ids are shuffled and renamed; truth is never read here."""
    order = [c["case_id"] for c in cases]
    random.Random(seed).shuffle(order)
    mapping = {f"Q{i:02d}": cid for i, cid in enumerate(order, 1)}
    by_id = {c["case_id"]: c for c in cases}
    payload = [{"id": q, **model_view(by_id[cid], owners[cid])} for q, cid in mapping.items()]
    request = {"model": MODEL,
               "messages": [{"role": "system", "content": SYSTEM},
                            {"role": "user", "content": json.dumps({"cases": payload}, ensure_ascii=False,
                                                                     sort_keys=True)}],
               "temperature": 0, "max_tokens": 2048,
               "response_format": {"type": "json_object"}, "reasoning_effort": "none"}
    return request, mapping


def validate_model_answer(content: str, mapping: dict[str, str], cases: list[dict]) -> tuple[dict, int]:
    """Parse a model answer. Returns (selections by case id, ids dropped as not allowed)."""
    def unique(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out
    data = json.loads(content, object_pairs_hook=unique)
    if not isinstance(data, dict) or set(data) != {"selected"} or not isinstance(data["selected"], dict):
        raise ValueError("answer shape rejected")
    allowed = {c["case_id"]: set(c["allowed_catalog_ids"]) for c in cases}
    sel: dict[str, set[str]] = {cid: set() for cid in mapping.values()}
    dropped = 0
    for q, ids in data["selected"].items():
        if q not in mapping or not isinstance(ids, list) or len(ids) != len(set(ids)) \
                or any(not isinstance(i, str) for i in ids):
            raise ValueError("invalid case entry")
        for i in ids:
            if i in allowed[mapping[q]]:
                sel[mapping[q]].add(i)
            else:
                dropped += 1
    return sel, dropped


def prepare_real_model(cases: list[dict], owners: dict, reference: dict[str, set[str]]) -> dict:
    """D: build and hash the request through the planner gateway in preview mode. Not sent."""
    request, mapping = real_model_request(cases, owners)
    inverse = {cid: q for q, cid in mapping.items()}

    def local_reference(_clean: dict) -> dict:
        # Labelled local stand-in so the preview path is exercised end to end.
        content = json.dumps({"selected": {inverse[cid]: sorted(ids) for cid, ids in reference.items()}})
        return {"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]}

    gw = PlannerLLMGateway(mode="preview", model=MODEL, responder=local_reference,
                           budget=Budget(max_calls=1, max_total_tokens=80_000, max_cost_usd=0.20,
                                         usd_per_1k_input=PRICE_IN, usd_per_1k_output=PRICE_OUT))
    try:
        status, response = gw.handle(json.dumps(request).encode(), f"Bearer {gw.token}")
        if status != 200:
            raise ValueError(f"planner gateway refused the preview: {response}")
        sel, dropped = validate_model_answer(response["choices"][0]["message"]["content"], mapping, cases)
        if sel != {cid: set(v) for cid, v in reference.items()}:
            raise ValueError("preview round trip changed the reference selection")
        rep = gw.report()
    finally:
        gw.close()
    prompt_bytes = len(request["messages"][1]["content"].encode()) + len(SYSTEM.encode())
    if rep["mode"] != "preview" or any(r["decision"] != "previewed" for r in rep["records"]):
        raise ValueError("D must stay a local preview")
    return {"status": "AI性能未測定", "sent": False, "gateway_mode": rep["mode"],
            "previewed_calls": rep["calls"], "est_tokens": rep["est_tokens"],
            "first_request_sha256": rep["first_request_sha256"], "request_bytes": prompt_bytes,
            "gateway_worst_case_reservation_usd": rep["est_cost_usd"],
            "budget": rep["budget"], "model": MODEL, "case_count": len(mapping),
            "preview_round_trip_ok": True, "preview_dropped_not_allowed": dropped,
            "note": ("Request fixed and hashed locally; never sent. A real-model score needs a new, "
                     "explicit owner approval bound to first_request_sha256.")}


ENDPOINT = "https://api.abliteration.ai/v1/chat/completions"
APPROVED_BUDGET = {"max_calls": 1, "max_total_tokens": 20_000, "max_cost_usd": 0.06}
APPROVAL_PURPOSE = "adaptive_holdout_v2_selection"


def fixed_request_sha256(cases: list[dict], owners: dict) -> str:
    """SHA-256 of the fixed D request as the planner gateway canonicalises it (local only)."""
    request, _ = real_model_request(cases, owners)
    gw = PlannerLLMGateway(mode="preview", model=MODEL,
                           responder=lambda _c: {"choices": [{"message": {"role": "assistant", "content": "{}"},
                                                              "finish_reason": "stop"}]},
                           budget=Budget(max_calls=1, usd_per_1k_input=PRICE_IN, usd_per_1k_output=PRICE_OUT,
                                         **{k: v for k, v in APPROVED_BUDGET.items() if k != "max_calls"}))
    try:
        status, _ = gw.handle(json.dumps(request).encode(), f"Bearer {gw.token}")
        if status != 200:
            raise ValueError("the fixed request does not fit the approved budget")
        return gw.report()["first_request_sha256"]
    finally:
        gw.close()


def run_approved(*, approval_sha256: str, api_key: str, audit, transport=None,
                 approval_dir: Path | None = None) -> dict:
    """ONE owner-approved send of the fixed D request. Returns aggregate scores only.

    Gates (scripts/eval_approval.py): SHA match -> key + verified audit -> durable,
    one-time approval consumption -> gateway budget reservation and required audit of the
    forward -> answer adopted only with finish_reason=stop, complete usage within budget
    and a valid, complete answer. The raw model text is never returned or stored."""
    from functools import partial

    from aegis.ai_advisor import _external_transport
    from scripts.eval_approval import (DEFAULT_APPROVAL_ROOT, consume_approval, require_key_and_audit,
                                       require_matching_approval, usage_fits)

    _, cases, owners, truth = load_dataset()
    require_matching_approval(approval_sha256, fixed_request_sha256(cases, owners))
    require_key_and_audit(api_key, audit)
    request, mapping = real_model_request(cases, owners)
    gateway = PlannerLLMGateway(
        mode="forward", model=MODEL, upstream_url=ENDPOINT, api_key=api_key,
        budget=Budget(max_calls=1, max_total_tokens=APPROVED_BUDGET["max_total_tokens"],
                      max_cost_usd=APPROVED_BUDGET["max_cost_usd"],
                      usd_per_1k_input=PRICE_IN, usd_per_1k_output=PRICE_OUT),
        approval={"max_calls": 1, "first_request_sha256": approval_sha256, "reasoning_effort": "none"},
        audit=audit, transport=transport or partial(_external_transport, timeout_s=30))
    base = {"request_sha256": approval_sha256, "model": MODEL, "target_get": 0, "worker_launches": 0,
            "labels": "author labels (provisional until independent re-labelling)"}
    try:
        consume_approval(approval_dir or DEFAULT_APPROVAL_ROOT / APPROVAL_PURPOSE, approval_sha256, audit,
                         purpose=APPROVAL_PURPOSE)
        started = time.monotonic()
        status, response = gateway.handle(json.dumps(request).encode(), f"Bearer {gateway.token}")
        elapsed = round(time.monotonic() - started, 3)
        report = {k: v for k, v in gateway.report().items() if k != "records"}
        if status != 200:
            return {**base, "accepted": False, "reject_reason": "gateway_or_upstream_refused",
                    "http_status_from_gateway": status, "elapsed_s": elapsed, "gateway": report}
        choice = (response.get("choices") or [{}])[0]
        finish = choice.get("finish_reason")
        usage, usage_problem = usage_fits(response.get("usage"), usd_per_1k_input=PRICE_IN,
                                          usd_per_1k_output=PRICE_OUT,
                                          reserved_usd=APPROVED_BUDGET["max_cost_usd"])
        reason = None
        if gateway.failed:
            reason = "gateway_terminal_response"
        elif finish != "stop":
            reason = f"finish_reason_{finish if finish in ('length', 'content_filter', 'tool_calls') else 'other'}"
        elif usage_problem:
            reason = usage_problem
        selections, dropped = {}, 0
        if reason is None:
            try:
                content = (choice.get("message") or {}).get("content")
                if not isinstance(content, str):
                    raise ValueError("missing content")
                selections, dropped = validate_model_answer(content, mapping, cases)
                if set(json.loads(content)["selected"]) != set(mapping):
                    raise ValueError("answer does not cover every case")
            except (ValueError, KeyError, TypeError):
                reason = "invalid_answer"
        if reason is not None:
            return {**base, "accepted": False, "reject_reason": reason, "usage": usage, "elapsed_s": elapsed,
                    "gateway": report}
        b2 = {c["case_id"]: RULES["B2_strong_rule"](c, owners[c["case_id"]]) for c in cases}
        e = {c["case_id"]: RULES["E_keyword_rule"](c, owners[c["case_id"]]) for c in cases}
        return {**base, "accepted": True, "reject_reason": None, "usage": usage, "elapsed_s": elapsed,
                "dropped_not_allowed": dropped, "score": score(selections, cases, truth),
                "paired_vs_E": paired_bootstrap(selections, e, cases, truth),
                "paired_vs_B2": paired_bootstrap(selections, b2, cases, truth), "gateway": report}
    finally:
        gateway.close()


# ---------------------------------------------------------------------------
def evaluate(*, smoke: bool = False) -> dict:
    manifest, cases, owners, truth = load_dataset()
    if smoke:
        cases = [c for c in cases if c["case_id"] in {"H004", "H015", "H028", "H052", "H054"}]
    rules = run_rules(cases, owners)
    strategies = dict(rules)
    strategies["C_artex_mock"] = run_artex_path(cases, owners)
    report: dict = {"dataset": {"id": manifest["dataset_id"], "version": manifest["version"],
                                "cases": len(cases), "smoke": smoke,
                                "files_sha256": manifest["files_sha256"],
                                "baseline_rules_sha256": manifest["baseline_rules_sha256"]},
                    "strategies": {}}
    for name, res in strategies.items():
        sc = score(res["selections"], cases, truth)
        report["strategies"][name] = {
            **{k: v for k, v in res.items() if k != "selections"}, "score": sc,
            "selections": {cid: sorted(v) for cid, v in sorted(res["selections"].items())}}
    report["structured_ceiling"] = structured_ceiling(cases, owners, truth)
    b2 = strategies["B2_strong_rule"]["selections"]
    report["paired_vs_B2"] = {name: paired_bootstrap(strategies[name]["selections"], b2, cases, truth)
                              for name in ("B_fixed_rule", "E_keyword_rule", "C_artex_mock")}
    report["paired_vs_B"] = {"B2_strong_rule": paired_bootstrap(b2, strategies["B_fixed_rule"]["selections"],
                                                                cases, truth)}
    report["C_vs_B2_identical_selections"] = strategies["C_artex_mock"]["selections"] == b2
    report["D_real_model"] = prepare_real_model(cases, owners, b2)
    report["ai_invocation_gate"] = {
        "rule": "B2 decides; the model is asked only when the owner's note is non-empty or a structured "
                "requirement is 'unspecified'",
        "cases_gated_to_model": sum(1 for c in cases if owners[c["case_id"]]["note_ja"]
                                    or "unspecified" in (owners[c["case_id"]]["root_access_requirement"],
                                                         owners[c["case_id"]]["account_resource_requirement"])),
        "cases_total": len(cases)}
    report["conclusion"] = {
        "ai_quality": "AI性能未測定（実モデル未送信。C は模擬モデルで AI の性能ではない）",
        "target_get": 0, "paid_model_calls": 0}
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="")
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 unless the ARTEX path reproduced B2 exactly and D stayed unsent "
                         "(with VULNIX_ARTEX_REAL_BIN: also a pinned, confined artex-binary)")
    args = ap.parse_args(argv)
    report = evaluate(smoke=args.smoke)
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    summary = {k: {m: v["score"][m] for m in ("precision", "recall", "f1", "exact_case_accuracy",
                                              "critical_cases_missed", "unnecessary_worker_launches")}
               for k, v in report["strategies"].items()}
    print(json.dumps({"summary": summary, "ceiling": report["structured_ceiling"],
                      "paired_vs_B2": report["paired_vs_B2"], "D": report["D_real_model"]["status"],
                      "C_engine": report["strategies"]["C_artex_mock"]["engine_kind"]},
                     ensure_ascii=False, indent=2))
    if args.check:
        c = report["strategies"]["C_artex_mock"]
        problems = []
        if not report["C_vs_B2_identical_selections"]:
            problems.append("ARTEX path changed B2's selections")
        if c["blocked_by_authority"] or c["router_rejected"] or c["gateway_policy_rejected"]:
            problems.append("ARTEX path produced refused proposals")
        if report["D_real_model"]["sent"] or report["conclusion"]["paid_model_calls"]:
            problems.append("real model request was sent")
        if os.environ.get("VULNIX_ARTEX_REAL_BIN") and not (
                c["engine_kind"] == "artex-binary" and c["all_runs_pinned"] and c["model_calls"] > 0
                and (c["all_runs_confined"] or os.environ.get("VULNIX_ARTEX_CONFINE") != "1")):
            problems.append("real ARTEX run was not a pinned (and confined) artex-binary")
        if problems:
            print("CHECK FAILED: " + "; ".join(problems), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
