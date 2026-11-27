"""CVE impact chain: from "the version matches" to "the impact is confirmed", one link at a time.

A version match only makes a CVE a candidate. Each further link is recorded with where it came
from - the configuration a CVE needs, whether the vulnerable path is reachable, a reproduction
in a reviewed isolated lab - and the status never runs ahead of its evidence:

  not_affected         the observed version is outside every affected range (fixed or older)
  version_match        product and version match; nothing else is known  (candidate)
  conditions_unmet     a required configuration or the path was observed absent (still a candidate)
  conditions_met       configuration and reachability observed, not reproduced (candidate)
  reproduced           reproduced in a reviewed isolated lab (impact confirmed there)
  not_reproduced       the lab reproduction ran and did not succeed (not "safe": the lab is not
                       the deployment)

No exploit code is fetched or run here; reproductions exist only for individually reviewed
lab checks (aegis.real_software_cve, the lab's reproduction probe).
"""
from __future__ import annotations

from .cve import CVE, parse_version, version_in_range

# Preconditions the advisory states beyond the version (reviewed entries only).
CONDITIONS = {
    "CVE-2021-41773": {"configuration": "ファイルシステム全体への `Require all denied` がない（パス・トラバーサル）。"
                                        "CGI が有効だとコード実行に至る",
                       "path": "/cgi-bin/ または公開ディレクトリ配下の正規化前パス",
                       "lab_check": "cve_2021_41773"},
    "CVE-2021-42013": {"configuration": "CVE-2021-41773 と同じ条件（2.4.50 の不完全な修正）",
                       "path": "/cgi-bin/ 配下の二重エンコードされたパス",
                       "lab_check": None},
}
LABELS = {"not_affected": "影響を受ける版ではない", "version_match": "版が一致（候補）",
          "conditions_unmet": "前提条件を満たさない（候補）", "conditions_met": "前提条件を満たす（未実証）",
          "reproduced": "隔離ラボで影響を確認", "not_reproduced": "隔離ラボで再現せず（安全の判定ではない）"}


def fixed_versions(cve: CVE) -> list[str]:
    """The first fixed versions the ranges name (an exclusive upper bound, `lt`)."""
    return sorted({r["lt"] for r in cve.affected if r.get("lt")},
                  key=parse_version)


def impact_chain(cve: CVE, *, product: str, version: str, version_source: str, in_kev: bool = False,
                 configuration: bool | None = None, reachable: bool | None = None,
                 reproduction: str | None = None) -> dict:
    """`configuration` / `reachable`: True or False only when observed; None = not observed.
    `reproduction`: the lab verdict for this CVE's reviewed check (proven / not_reproduced)."""
    affected = any(version_in_range(version, r) for r in cve.affected)
    cond = CONDITIONS.get(cve.id, {})
    if not affected:
        status = "not_affected"
    elif reproduction == "proven":
        status = "reproduced"
    elif reproduction == "not_reproduced":
        status = "not_reproduced"
    elif configuration is False or reachable is False:
        status = "conditions_unmet"
    elif configuration is True and reachable is True:
        status = "conditions_met"
    else:
        status = "version_match"
    return {
        "cve": cve.id, "product": product, "version": version, "version_source": version_source,
        "affected_ranges": [dict(r) for r in cve.affected], "fixed_in": fixed_versions(cve), "kev": in_kev,
        "configuration": {"required": cond.get("configuration") or "勧告に記載の条件を確認（未登録）",
                          "observed": configuration},
        "reachability": {"path": cond.get("path"), "observed": reachable},
        "lab_check": cond.get("lab_check"), "reproduction": reproduction,
        "status": status, "status_label": LABELS[status],
        "confirmed_impact": status == "reproduced",
    }


def with_reproduction(entry: dict, verdict: str | None) -> dict:
    """The same chain after its reviewed lab check ran (proven / not_reproduced); other verdicts
    (detected, candidate, unverified) leave the reproduction link empty."""
    if not entry.get("lab_check") or entry["status"] == "not_affected":
        return entry
    rep = verdict if verdict in ("proven", "not_reproduced") else None
    if rep == entry.get("reproduction"):
        return entry
    base = {"configuration": entry["configuration"]["observed"], "reachable": entry["reachability"]["observed"]}
    status = ("reproduced" if rep == "proven" else "not_reproduced" if rep == "not_reproduced" else
              "conditions_unmet" if False in base.values() else
              "conditions_met" if all(v is True for v in base.values()) else "version_match")
    history = list(entry.get("lab_history") or [])
    if rep:
        history.append(rep)        # kept, so "reproduced, then not after the fix" stays visible
    return {**entry, "reproduction": rep, "status": status, "status_label": LABELS[status],
            "confirmed_impact": status == "reproduced", "lab_history": history[-10:],
            "fixed_after_reproduction": rep == "not_reproduced" and "proven" in history[:-1]}


__all__ = ["CONDITIONS", "LABELS", "fixed_versions", "impact_chain", "with_reproduction"]
