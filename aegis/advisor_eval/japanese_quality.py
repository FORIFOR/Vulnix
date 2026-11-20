"""Japanese advice quality: automatic checks on advice that already passed the validator.

The product validator (aegis/ai_advisor.validate_advice) decides what may be shown:
schema, catalog ids, claim level vs verdict, leaks, overclaims, unsupported impact
claims and remediation that weakens a control. This module scores what remains on
the axes of aegis/advisor_eval/japanese_quality_rubric.json. Readability is only
approximated here; the rubric requires human review for it.

  python3 -m scripts.eval_japanese_advice [--out report.json]
"""
from __future__ import annotations

import re

from .. import advisor_catalog as catalog
from ..ai_advisor import leak_reasons

UNRESOLVED_PURPOSES = frozenset({"confirm_fix", "confirm_current_state", "collect_evidence"})
_HEDGE = re.compile(r"可能性|おそれ|恐れ|疑い|未確認|確かめていません|確認できていません|かもしれ|推定|判断でき|検出段階")
_DEFINITIVE = re.compile(r"脆弱です|脆弱性があります|確実に|間違いなく|必ず(?:悪用|侵入|漏)")
_STALE_HEDGE = re.compile(r"まだ確かめていません|確かめていません|検出段階|未確認です")
_RESOLVED_WORDS = re.compile(r"再現しませんでした|再現しなかった|再現されませんでした|解消")
_STILL_OPEN = re.compile(r"現在も残って|残っている可能性|すぐに対策")
_SENTENCE = re.compile(r"[^。！？!?]+[。！？!?]?")
_ASCII_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*")
# acronyms a beginner can be expected to look up once; anything else in ASCII counts as jargon
_KNOWN_TERMS = frozenset({"cookie", "api", "json", "http", "https", "tls", "cors", "url", "secure", "httponly",
                          "samesite", "apache", "nginx", "csp", "hsts", "waf", "l1", "l2", "cve", "id"})


def readability(text: str) -> dict:
    sentences = [s for s in _SENTENCE.findall(text) if s.strip()]
    lengths = [len(s) for s in sentences] or [0]
    words = _ASCII_WORD.findall(text)
    jargon = [w for w in words if w.lower().rstrip(".") not in _KNOWN_TERMS and not re.fullmatch(r"CVE-\d{4}-\d+", w)]
    ascii_chars = sum(len(w) for w in words)
    return {"sentences": len(sentences), "avg_sentence_chars": round(sum(lengths) / len(lengths), 1),
            "max_sentence_chars": max(lengths), "ascii_ratio": round(ascii_chars / max(1, len(text)), 3),
            "jargon_terms": len(jargon)}


def score(advice: dict, verdict: str, rule: str) -> dict:
    """`advice`: one accepted item of AdviceResult.to_dict()["advice"]. Returns axis -> bool."""
    text = advice["risk_explanation"]
    resolved = verdict in ("fixed", "not_reproduced")
    hedge_needed = verdict in ("candidate", "unverified") or (
        verdict == "detected" and rule in catalog.L2_ONLY_RULES)
    if verdict == "proven":
        state_ok = not _STALE_HEDGE.search(text)
    elif resolved:
        state_ok = bool(_RESOLVED_WORDS.search(text)) and not _STILL_OPEN.search(text)
    elif hedge_needed:
        state_ok = bool(_HEDGE.search(text)) and not _DEFINITIVE.search(text)
    else:
        state_ok = not _DEFINITIVE.search(text) or verdict == "proven"
    purposes = {c["purpose"] for c in advice.get("next_checks") or []}
    fixes = {r["fix"] for r in advice.get("remediation") or []}
    retest_ok = (("keep_regression_check" in fixes or "regression_watch" in purposes) if resolved
                 else bool(purposes & UNRESOLVED_PURPOSES))
    read = readability(text)
    readable = read["max_sentence_chars"] <= 100 and read["ascii_ratio"] <= 0.35 and read["jargon_terms"] <= 3
    all_text = " ".join([text] + [r.get("detail", "") for r in advice.get("remediation") or []])
    return {"verdict_state": state_ok, "retest": retest_ok, "readability_auto": readable,
            "no_secret": not leak_reasons(all_text), "readability": read}


AXES = ("verdict_state", "retest", "readability_auto", "no_secret")
