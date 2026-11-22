"""Vulnix's fixed judge and proposer for the diagnosis loop (docs/DIAGNOSIS_LOOP_PLAN.md).

Only this module decides what a check result means for a hypothesis. It reads
Vulnix's own parsed Worker output and the owner's written specification - never
a planner's or a model's words. A `Verdict` can only be made here; the diagnosis
state refuses anything else (DiagnosisState.apply).

Rules (fixed, ordered; the first that matches decides):

A check was run and the owner's spec says the resource is public -> contradicted (intended_public)

other_account_read  x  l2_idor
    the owner control did not establish the resource       -> inconclusive (control_failed)
    reproduction proven (aegis.evidence.reproduction_verdict), or
    B's record measured in A's answer (aegis.evidence.owner_record_read_by_other_account:
        the Worker sent it as acct_A, B's control established in the same run, 200 read
        whole, the control's resource id AND confidential marker both present after the
        normalisations below, and the answer is not another resource / A's own)
        owner spec: authentication_required                -> supported   (cross_account_read)
        owner spec: public                                 -> contradicted (intended_public)
        owner spec missing / unspecified                   -> needs_spec  (spec_missing)
        (the second way decides "supported" only here; a finding becomes 実証成功 only when
         reproduction_verdict, which also requires this match, says proven -
         docs/evaluation/JUDGE_IDENTITY_MATCH.md)
    acct_A gets 401/403/404 while the owner gets 200       -> contradicted (denied)
    acct_A gets 200 with its own resource (no marker)      -> contradicted (own_resource_only)
    acct_A gets 200 carrying none of the owner control's identifiers (resource id,
        secret marker) nor the owner's account name, read whole (the Worker's own
        response_truncated is False), and the body is only a refusal: an error-only JSON
        object or a page that is nothing but a sign-in form / a refusal heading
                                                            -> contradicted (owner_record_absent)
        (JSON data, a page with other content, or an envelope with data stays inconclusive:
         "not vulnerable" is never inferred from the absence of identifiers alone)
    anything else                                          -> inconclusive (unrecognised_answer)

unauthenticated_exposure  x  l1_http_probe (one GET without any account)
    401/403/404                                            -> contradicted (denied_without_auth)
    200, the same comparison with the lab owner's control
        identifiers and account name                       -> contradicted (owner_record_absent_without_auth)
    200 otherwise                                          -> inconclusive (answered_without_auth_unverified)
        (a status alone does not show that the protected resource itself was served; the
        owner's identifiers in the answer are not taken as proof either: nothing here supports)
    anything else                                          -> inconclusive (unrecognised_answer)

The two owner-record rules only ever contradict. Their risk is a miss: an answer with the
owner's data stripped of every identifier and of the owner's name, as JSON, is closed
(docs/evaluation/JUDGE_OWNER_RECORD.md).

A check that does not test the claim                       -> inconclusive (check_not_relevant)
"""
from __future__ import annotations

import json
import re
import weakref
from dataclasses import dataclass

from .diagnosis_state import DiagnosisState
from .evidence import REPRODUCTION_MARKERS, normalised_texts, owner_record_read_by_other_account, reproduction_verdict

_ISSUER = object()          # only this module holds it
# The verdict objects this module made. A copy (dataclasses.replace, copy.copy) carries the
# token but is a different object, so it is not in here and is refused.
_ISSUED: "weakref.WeakSet[Verdict]" = weakref.WeakSet()
DENIED = (401, 403, 404)
REQUIREMENTS = frozenset({"authentication_required", "public", "unspecified"})

# The owner control of the registered lab. The lab Worker accepts B's control only when it
# carries exactly these (aegis/workers/reproduction_probe.py run_lab_check), and the
# diagnosis loop runs only on that lab, so an L1 GET is compared with them.
LAB_OWNER_IDENTIFIERS = ("res_b_001", REPRODUCTION_MARKERS["idor"])
LAB_OWNER_ACCOUNTS = ("acct_B",)
L2_EXCERPT = 4096           # characters of A's answer the lab Worker keeps
L1_BODY_CAP = 4096          # bytes of the body the L1 probe reads
# body kinds an absent owner record may be read from (everything else stays unsettled)
# Only answers that are themselves a refusal or a sign-in page count as "the owner's record is
# absent". Arbitrary JSON data without the owner's identifiers does NOT: it may still be the
# owner's data in another shape (holdout-v2-006), and calling that "not vulnerable" would be a
# confident miss. Such answers stay inconclusive.
ABSENCE_BODY_KINDS = ("json_refusal", "html_login", "html_refusal")
# words a sign-in page uses
_SIGN_IN = ("sign in", "log in", "login", "signin", "ログイン", "サインイン")
# words a refusal page's own title / h1 uses
_REFUSAL = ("forbidden", "access denied", "unauthorized", "unauthorised", "permission denied", "not authorized",
            "403", "401", "アクセスが拒否", "権限がありません")
_REFUSAL_WORDS = ("forbidden", "denied", "unauthorized", "unauthorised", "not allowed", "not permitted",
                  "permission denied", "no permission", "access_denied", "not_authenticated", "login required")


def _json_refusal(parsed) -> bool:
    """A JSON body that is only an error / refusal object - never data in an envelope.
    Every value must be a short scalar (or, for `errors`, a list of {code, message}
    scalars), success flags must not say success, and the refusal words are looked for
    in the error fields only (a word inside data, e.g. "permission": "admin", is data)."""
    if not isinstance(parsed, dict) or not parsed:
        return False
    allowed = {"error", "errors", "message", "detail", "code", "status", "error_description", "request_id",
               "ok", "success", "reason"}
    if set(map(str, parsed)) - allowed:
        return False
    scalar = (str, int, float, bool, type(None))
    for k, v in parsed.items():
        if k == "errors":
            if not (isinstance(v, list) and all(isinstance(e, dict) and set(map(str, e)) <= {"code", "message", "detail"}
                                                and all(isinstance(x, scalar) for x in e.values()) for e in v)):
                return False
        elif not isinstance(v, scalar) or (isinstance(v, str) and len(v) > 200):
            return False
    if parsed.get("ok") is True or parsed.get("success") is True:
        return False
    words = [str(parsed.get(k, "")).lower() for k in ("error", "message", "detail", "reason", "error_description",
                                                       "status", "code")]
    words += [str(x).lower() for e in parsed.get("errors") or [] for x in e.values()]
    text = " ".join(words)
    return any(w in text for w in _REFUSAL_WORDS) or any(str(parsed.get(k)) in ("401", "403")
                                                          for k in ("code", "status"))


@dataclass(frozen=True, eq=False)
class Verdict:
    hypothesis_id: str
    to: str
    evidence: tuple[str, ...]
    rule: str
    _issuer: object = None

    def issued_by_judge(self) -> bool:
        return self._issuer is _ISSUER and self in _ISSUED


def _verdict(hid: str, to: str, evidence, rule: str) -> Verdict:
    v = Verdict(hid, to, tuple(evidence), rule, _ISSUER)
    _ISSUED.add(v)
    return v


# ---- fixed parsers: Worker output -> short observation attributes -------------------
def _texts(body) -> list[str]:
    """The answer as lower-case text, also with HTML entities, %-escapes and JSON escapes
    undone, so an identifier hidden by an encoding still counts as present."""
    return normalised_texts(body)


def _mentions(body, needles) -> bool:
    texts = _texts(body)
    return any(n.lower() in t for n in needles for t in texts)


def _body_kind(body, complete: bool) -> str:
    """json_refusal | json_data | html_login | html_refusal | html_other | text | empty | partial."""
    if not complete:
        return "partial"
    if isinstance(body, str):
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            body = parsed
    if isinstance(body, (dict, list)):
        return "json_refusal" if _json_refusal(body) else "json_data"
    if not isinstance(body, str) or not body.strip():
        return "empty"
    low = body.strip().lower()
    if not (low.startswith("<") and ("<html" in low or "<!doctype html" in low)):
        return "text"
    # The page must BE a sign-in or refusal page, not merely contain one (a profile page
    # with a "change password" form, "Last login: ..." text, a heading that mentions
    # "unauthorized"): one form with a password field and little else, or a refusal
    # heading with little else. Anything more stays html_other (not decided).
    forms = re.findall(r"<form\b[^>]*>(.*?)(?:</form>|$)", low, re.S)
    outside = re.sub(r"<form\b.*?(?:</form>|$)", " ", low, flags=re.S)
    outside = re.sub(r"<(script|style)\b.*?</\1>", " ", outside, flags=re.S)
    visible = " ".join(re.sub(r"<[^>]+>", " ", outside).split())
    if len(forms) == 1 and len(visible) <= 300:
        form = forms[0]
        password = re.search(r"""type\s*=\s*["']?password""", form)
        # a sign-in form asks who you are (a user / email field, or says sign in / log in);
        # a "change password" form on someone's own page does not
        who = (re.search(r"""<input\b(?![^>]*type\s*=\s*["']?(?:password|hidden|submit))[^>]*>""", form)
               or any(w in form + " " + visible for w in _SIGN_IN))
        changing = any(w in form for w in ("change password", "new password", "current password",
                                           "パスワードの変更", "新しいパスワード"))
        if password and who and not changing:
            return "html_login"
    heading = " ".join(re.findall(r"<(?:title|h1)[^>]*>(.*?)</(?:title|h1)>", low, re.S))
    if not forms and any(w in heading for w in _REFUSAL) and len(visible) <= 300:
        return "html_refusal"
    return "html_other"


def _owner_facts(body, complete: bool, identifiers, accounts):
    """(owner identifiers present, owner account name present, body kind) of one answer."""
    return _mentions(body, identifiers), _mentions(body, accounts), _body_kind(body, complete)


def _control_identifiers(control) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The identifiers and account names of the owner's own control answer (Worker output)."""
    if not isinstance(control, dict):
        return (), ()
    ids = tuple(v for v in (control.get("resource_id"), control.get("confidential_marker"))
                if isinstance(v, str) and v.strip())
    accounts = tuple(v for v in (control.get("resource_owner"), control.get("caller_account"))
                     if isinstance(v, str) and v.strip())
    return ids, accounts


def check_attrs(catalog_id: str, result: dict) -> dict:
    """The facts a check result adds, in words and small integers only.

    The owner-record facts are read only from the Worker's own result: the answer and,
    for l2_idor, the owner's control answer in the same result. They are added for a 200
    answer that is neither a proven reproduction nor the requester's own resource (the
    only answers the owner-record rules read), which also keeps the planner input within
    its token cap."""
    if not isinstance(result, dict):
        return {"answer": "unreadable"}
    status = result.get("status") if isinstance(result.get("status"), int) else None
    if catalog_id == "l1_http_probe":
        attrs = {"status": status, "auth": "none"}
        body = result.get("body_prefix")
        if status == 200 and isinstance(body, str):
            n = len(body.encode("utf-8"))
            headers = result.get("headers") if isinstance(result.get("headers"), dict) else {}
            length = next((v for k, v in headers.items() if str(k).lower() == "content-length"), None)
            complete = (str(length).strip() == str(n)) if length is not None else n < L1_BODY_CAP
            present, named, kind = _owner_facts(body, complete, LAB_OWNER_IDENTIFIERS, LAB_OWNER_ACCOUNTS)
            attrs.update({"owner_identifiers_present": present, "owner_account_present": named,
                          "body_kind": kind})
        return attrs
    if catalog_id == "l2_idor":
        response = result.get("response")
        own = (isinstance(response, dict) and response.get("caller_account") == "acct_A"
               and response.get("resource_owner") == "acct_A")
        reproduction = reproduction_verdict(result, "idor")
        attrs = {"status": status, "auth": "other_account",
                 "control": "established" if result.get("control_verified") is True else "missing",
                 "reproduction": reproduction,
                 "own_resource": bool(own)}
        ids, accounts = _control_identifiers(result.get("control_response"))
        if (status == 200 and reproduction != "proven" and not own and result.get("control_verified") is True
                and ids and accounts and "response" in result):
            # whole only when the Worker says it kept the whole body (an older result
            # without the flag is never read as complete)
            complete = result.get("response_truncated") is False
            present, named, kind = _owner_facts(response, complete, ids, accounts)
            attrs.update({"owner_identifiers_present": present, "owner_account_present": named,
                          "body_kind": kind,
                          "owner_record_match": owner_record_read_by_other_account(result)})
        return attrs
    return {"status": status}


def _owner_record_absent(a: dict) -> bool:
    """The answer was read completely, is JSON or an HTML sign-in / refusal page, and
    names neither the owner's control identifiers nor the owner's account."""
    return (a.get("owner_identifiers_present") is False and a.get("owner_account_present") is False
            and a.get("body_kind") in ABSENCE_BODY_KINDS)


def _requirement(state: DiagnosisState, target_ref: str, generation: int) -> tuple[str, list[str]]:
    specs = [o for o in state.observations(target_ref=target_ref, generation=generation)
             if o["source"] == "owner_spec" and o["kind"] == "owner_spec"]
    if not specs:
        return "unspecified", []
    req = specs[-1]["attrs"].get("requirement")
    return (req if req in REQUIREMENTS else "unspecified"), [specs[-1]["evidence_id"]]


def judge(state: DiagnosisState, hypothesis_id: str, catalog_id: str, evidence_id: str) -> Verdict:
    """Decide what the check observation `evidence_id` means for the hypothesis."""
    h = state.hypothesis(hypothesis_id)
    obs = state.observation(evidence_id)
    if obs["source"] != "check" or obs["target_ref"] != h["target_ref"]:
        raise ValueError("the judge reads a check result on the hypothesis's own target")
    if obs.get("catalog_id") != catalog_id:
        # the observation names the check that produced it; reading an L1 status as an
        # IDOR reproduction (or the reverse) would decide on the wrong evidence
        raise ValueError("the check result was produced by another check")
    a = obs["attrs"]
    status = a.get("status")
    requirement, spec_ev = _requirement(state, h["target_ref"], h["generation"])
    ev = [evidence_id]

    def by_spec(rule_ok: str) -> Verdict:
        if requirement == "authentication_required":
            return _verdict(hypothesis_id, "supported", ev + spec_ev, rule_ok)
        if requirement == "public":
            return _verdict(hypothesis_id, "contradicted", ev + spec_ev, "intended_public")
        return _verdict(hypothesis_id, "needs_spec", ev + spec_ev, "spec_missing")

    relevant = (h["claim"], catalog_id) in (("other_account_read", "l2_idor"),
                                            ("unauthenticated_exposure", "l1_http_probe"))
    if relevant and requirement == "public":
        return _verdict(hypothesis_id, "contradicted", ev + spec_ev, "intended_public")
    if h["claim"] == "other_account_read" and catalog_id == "l2_idor":
        if a.get("control") != "established":
            return _verdict(hypothesis_id, "inconclusive", ev, "control_failed")
        if a.get("reproduction") == "proven":
            return by_spec("cross_account_read")
        if status == 200 and a.get("own_resource") is False and a.get("owner_record_match") is True:
            # B's record, measured against B's own control in the same Worker run (案2)
            return by_spec("cross_account_read")
        if status in DENIED:
            return _verdict(hypothesis_id, "contradicted", ev, "denied")
        if status == 200 and a.get("own_resource") is True:
            return _verdict(hypothesis_id, "contradicted", ev, "own_resource_only")
        if status == 200 and a.get("own_resource") is False and _owner_record_absent(a):
            return _verdict(hypothesis_id, "contradicted", ev, "owner_record_absent")
        return _verdict(hypothesis_id, "inconclusive", ev, "unrecognised_answer")
    if h["claim"] == "unauthenticated_exposure" and catalog_id == "l1_http_probe":
        if status in DENIED:
            return _verdict(hypothesis_id, "contradicted", ev, "denied_without_auth")
        if status == 200 and _owner_record_absent(a):
            return _verdict(hypothesis_id, "contradicted", ev, "owner_record_absent_without_auth")
        if status == 200:
            return _verdict(hypothesis_id, "inconclusive", ev, "answered_without_auth_unverified")
        return _verdict(hypothesis_id, "inconclusive", ev, "unrecognised_answer")
    return _verdict(hypothesis_id, "inconclusive", ev, "check_not_relevant")


# ---- fixed proposer: observations -> hypotheses -------------------------------------
def propose_hypotheses(state: DiagnosisState) -> list[str]:
    """Open the hypotheses the current observations call for (fixed rules, idempotent).

    An account resource the target itself links to (measured by the fixed L1) may be
    readable without authentication, or by another account."""
    made = []
    # A claim already diagnosed in an earlier generation is not reopened here: after
    # a fix only a supported one is re-checked, through begin_fix_check/confirm_fix.
    existing = {(h["claim"], h["target_ref"]) for h in state.hypotheses()}
    for o in state.observations(generation=state.generation):
        if o["source"] != "l1" or o["kind"] != "account_resource_link" or o["attrs"].get("present") is not True:
            continue
        for claim in ("unauthenticated_exposure", "other_account_read"):
            if (claim, o["target_ref"]) not in existing:
                made.append(state.propose(claim=claim, target_ref=o["target_ref"], basis=[o["evidence_id"]]))
                existing.add((claim, o["target_ref"]))
    return made


# The fixed-rule planner used for the comparison (same catalog, same budget as ARTEX).
FIXED_CHECK_FOR_CLAIM = {"unauthenticated_exposure": "l1_http_probe", "other_account_read": "l2_idor"}


def fixed_rule_steps(view: dict) -> list[dict]:
    """One step per testable hypothesis, in hypothesis order, from a fixed table.
    The runner executes the first one the contract accepts."""
    steps = []
    for h in view["hypotheses"]:
        if h["state"] not in ("open", "inconclusive") or h["generation"] != view["generation"]:
            continue
        refs = [o["evidence_id"] for o in view["observations"]
                if o["target_ref"] == h["target_ref"] and o["generation"] == view["generation"]]
        steps.append({"hypothesis_id": h["id"], "catalog_id": FIXED_CHECK_FOR_CLAIM[h["claim"]],
                      "target_ref": h["target_ref"], "evidence_refs": refs,
                      "reason": "confirm_fix" if h["purpose"] == "confirm_fix" else "test_hypothesis"})
    return steps


__all__ = ["DENIED", "FIXED_CHECK_FOR_CLAIM", "Verdict", "check_attrs", "fixed_rule_steps", "judge",
           "propose_hypotheses"]
