"""Observation steps around the diagnosis loop, for the registered local lab only.

- `observe_lab_root`: the fixed L1 root GET (the same automatic L1 policy as an
  initial run), recorded as observations tied to its audit hash. If the root links
  to the lab's account resource, that link becomes an observation about target T2.
- `record_owner_spec`: the owner's written requirement for a target (an input to
  the fixed judge, never something a planner states).
- `begin_fix_check`: after the owner reports a fix - a new generation, a fresh
  root observation and owner spec, and one `confirm_fix` hypothesis for every
  supported finding candidate, built only on the new observations.

Nothing here talks to a real service: every function refuses unless Vulnix itself
lists diagnosis targets (AssessmentService.diagnosis_targets is empty otherwise).
"""
from __future__ import annotations

from .diagnosis_state import DiagnosisState

REQUIREMENTS = ("authentication_required", "public", "unspecified")


def observe_lab_root(svc, state: DiagnosisState, *, request_authorized=None) -> list[str]:
    """The fixed L1 root GET, under the same guards as any other check: the asset is
    pinned for the call, a stop / reset / revocation drops the result, and nothing is
    sent unless Vulnix lists the registered lab as a diagnosis target."""
    from .assessment import _Stopped
    svc._begin_operation()                     # the active asset cannot be switched meanwhile
    prev_gen = getattr(svc._tls, "gen", None)
    prev_auth = getattr(svc._tls, "request_authorized", None)
    svc._tls.request_authorized = request_authorized
    try:
        if request_authorized is not None and not request_authorized():
            raise ValueError("要求者の権限が失効したため、観測を開始しません")
        with svc._lock:
            svc._refuse_after_stop_locked()
            if not any(t["target_id"] == "T1" for t in svc._diagnosis_targets_locked()):
                raise ValueError("診断ループは登録済みのローカル検証ラボでのみ使用できます")
            svc._ensure_active_window_locked()
            gen = svc._tls.gen = svc._run_generation
            url = svc.a.target_url
            state.bind((gen, url))             # a state never mixes runs or targets
        res, ev = svc._exec("http_probe", "read_only_probe", {"url": url, "method": "GET"},
                            approval_actor="policy:auto-L1")
        if res is None or not ev:
            raise ValueError("初期観測（L1）を記録できませんでした")
        with svc._lock:
            if gen != svc._run_generation or svc.a.target_url != url:
                raise ValueError("停止・リセット・対象の変更があったため、この観測は記録しません")
            svc._analyze(res, ev)
            targets = {t["target_id"]: t for t in svc._diagnosis_targets_locked()}
    except _Stopped:
        raise ValueError("停止またはリセットされたため、観測を中止しました") from None
    finally:
        svc._tls.gen = prev_gen
        svc._tls.request_authorized = prev_auth
        svc._end_operation()
    if "T1" not in targets:
        raise ValueError("診断ループは登録済みのローカル検証ラボでのみ使用できます")
    status = res.get("status") if isinstance(res.get("status"), int) else None
    made = [state.observe(kind="root_response", target_ref="T1", source="l1", audit_hash=ev["audit_hash"],
                          attrs={"status": status, "account_link": "T2" in targets})]
    if "T2" in targets:
        made.append(state.observe(kind="account_resource_link", target_ref="T2", source="l1",
                                  audit_hash=ev["audit_hash"], attrs={"present": True}))
    return made


def record_owner_spec(state: DiagnosisState, target_ref: str, requirement: str, *,
                      actor: str | None = None) -> str:
    """The owner's written requirement. With a service-owned state it is audited
    (`diagnosis.observed`, with who wrote it) before it takes effect."""
    if requirement not in REQUIREMENTS:
        requirement = "unspecified"
    return state.observe(kind="owner_spec", target_ref=target_ref, source="owner_spec",
                         attrs={"requirement": requirement}, recorded_by=actor)


def begin_fix_check(svc, state: DiagnosisState, owner_specs: dict[str, str], *,
                    request_authorized=None, actor: str | None = None) -> list[str]:
    """Start the after-fix re-check. Returns the new confirm_fix hypothesis ids."""
    supported = [h for h in state.hypotheses() if h["state"] == "supported" and h["purpose"] == "diagnose"]
    state.begin_generation()
    try:
        observe_lab_root(svc, state, request_authorized=request_authorized)
    except Exception:
        state.abandon_generation()             # nothing measured: keep the earlier generation usable
        raise
    for ref, req in owner_specs.items():
        record_owner_spec(state, ref, req, actor=actor)
    made = []
    for h in supported:
        basis = [o["evidence_id"] for o in state.observations(target_ref=h["target_ref"],
                                                               generation=state.generation)
                 if o["source"] == "l1"]
        if basis:
            made.append(state.reopen_for_fix(h["id"], basis=basis))
    return made


__all__ = ["begin_fix_check", "observe_lab_root", "record_owner_spec"]
