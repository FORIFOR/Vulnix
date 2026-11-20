"""Non-AI selection rules for the adaptive_holdout_v2 evaluation.

These rules were written and hashed BEFORE the truth labels of
tests/fixtures/adaptive_holdout_v2 existed (manifest.json pins this file's
SHA-256 together with the labels). Changing a rule after seeing the results
changes the hash and fails tests/test_adaptive_holdout.py on purpose.

Every rule reads only the model-visible case (observation + owner spec +
allowed catalog ids). None of them can see truth.json.

  A  fixed_l1          the initial read-only GET only; never an extra check.
  B  fixed_rule        the rules that exist in production today:
                       - l1_apache_mod_status: aegis.artex_bridge.initial_real_site_extra_checks
                       - l2_idor: the access-control reference rule used by
                         scripts/eval_selection_model.py (link observed AND the owner's
                         structured account requirement is authentication_required)
                       - l1_http_probe: never repeated (production marks it "observed"
                         because the baseline GET already satisfied it).
  B2 strong_rule       B plus structured extensions a careful engineer would add
                       without AI: an "unspecified" account requirement is treated
                       conservatively (check when a link is observed), and one read-only
                       recheck is chosen when the initial evidence for a reportable
                       condition was inconsistent or a session cookie is duplicated with
                       conflicting attributes.
  E  keyword_rule      B2's structured part plus fixed keyword matching on the owner's
                       free-text note. It is the cheap non-AI way to "read" the note and
                       is the control for "is an LLM needed at all".
"""
from __future__ import annotations

from aegis.artex_bridge import initial_real_site_extra_checks

STRATEGY_RULES = ("A_fixed_l1", "B_fixed_rule", "B2_strong_rule", "E_keyword_rule")


def _fingerprint(obs: dict) -> dict:
    return {"scheme": obs["scheme"], "status_class": f"{obs['status'] // 100}xx",
            "server_family": obs["server_family"], "tls_present": obs["tls_verified"],
            "hsts_present": obs["hsts_present"], "csp_present": False}


def _allowed(case: dict, picked: set[str]) -> set[str]:
    return picked & set(case["allowed_catalog_ids"])


def fixed_l1(case: dict, owner: dict) -> set[str]:
    return set()


def fixed_rule(case: dict, owner: dict) -> set[str]:
    obs = case["observation"]
    picked: set[str] = set()
    picked |= initial_real_site_extra_checks(
        _fingerprint(obs), status_consent=owner["status_probe_consent"] is True,
        root_observed=isinstance(obs["status"], int))
    if (obs["account_resource_link_observed"]
            and owner["account_resource_requirement"] == "authentication_required"):
        picked.add("l2_idor")
    return _allowed(case, picked)


def _reportable(case: dict, owner: dict) -> bool:
    """Would the initial observation alone be reported as a detected issue?"""
    obs, cat = case["observation"], case["category"]
    if cat == "auth_session":
        return (obs["body_shape"] == "account_fields"
                and owner["root_access_requirement"] == "authentication_required")
    if cat == "cors":
        return obs["cors"]["acao"] == "reflected" and obs["cors"]["credentials"]
    if cat == "cookie":
        return obs["scheme"] == "https" and any(
            c["purpose"] == "session" and (not c["secure"] or not c["httponly"]
                                           or (c["samesite"] == "none" and not c["secure"]))
            for c in obs["cookies"])
    if cat == "info_tls":
        return ((obs["scheme"] == "https" and not obs["hsts_present"])
                or obs["version_disclosed"] or not obs["tls_verified"])
    return False


def strong_rule(case: dict, owner: dict) -> set[str]:
    obs = case["observation"]
    picked = set(fixed_rule(case, owner))
    if (obs["account_resource_link_observed"]
            and owner["account_resource_requirement"] == "unspecified"):
        picked.add("l2_idor")
    if obs["initial_gets_consistent"] is False and _reportable(case, owner):
        picked.add("l1_http_probe")
    if any(c["purpose"] == "session" and c["duplicate_conflicting"] for c in obs["cookies"]):
        picked.add("l1_http_probe")
    return _allowed(case, picked)


# Fixed keyword lists, frozen with the rules above.
_IDOR_KEYWORDS = ("本人", "自分の", "他人", "owner only")
_STATUS_SKIP_KEYWORDS = ("意図的", "受容", "公開している")
_STATUS_SELECT_KEYWORDS = ("apache",)
_RECHECK_KEYWORDS = ("切り替え", "切替", "移行", "不安定", "修正済")


def keyword_rule(case: dict, owner: dict) -> set[str]:
    obs = case["observation"]
    note = (owner.get("note_ja") or "").lower()
    picked = set(strong_rule(case, owner))
    if obs["account_resource_link_observed"] and any(k in note for k in _IDOR_KEYWORDS):
        picked.add("l2_idor")
    if owner["status_probe_consent"] is True and any(k in note for k in _STATUS_SELECT_KEYWORDS):
        picked.add("l1_apache_mod_status")
    if any(k in note for k in _STATUS_SKIP_KEYWORDS):
        picked.discard("l1_apache_mod_status")
    if any(k in note for k in _RECHECK_KEYWORDS):
        picked.add("l1_http_probe")
    return _allowed(case, picked)


RULES = {"A_fixed_l1": fixed_l1, "B_fixed_rule": fixed_rule,
         "B2_strong_rule": strong_rule, "E_keyword_rule": keyword_rule}
