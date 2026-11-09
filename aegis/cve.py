"""CVE intelligence (P2): match observed evidence to known CVEs.

This engine turns an observation (e.g. a server banner) into *candidate*
findings. It embodies the project's first principle — separate detection from
proof. A match here is "detected (unverified)"; it is NEVER "proven". Proving a
finding is a separate, non-destructive confirmation step and is not done here.

The catalog holds descriptive metadata only (id, affected versions, severity,
remediation, references). It contains NO exploit code or payloads; matching a
CVE does not attempt, and cannot perform, any exploitation.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


def parse_version(v: str) -> tuple[int, ...]:
    parts = []
    for chunk in v.split("."):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    va, vb = parse_version(a), parse_version(b)
    n = max(len(va), len(vb))
    va += (0,) * (n - len(va))
    vb += (0,) * (n - len(vb))
    return (va > vb) - (va < vb)


def version_in_range(version: str, rng: dict) -> bool:
    """rng keys: eq, ge, gt, le, lt (any subset). All present must hold."""
    if "eq" in rng and _cmp(version, rng["eq"]) != 0:
        return False
    if "ge" in rng and _cmp(version, rng["ge"]) < 0:
        return False
    if "gt" in rng and _cmp(version, rng["gt"]) <= 0:
        return False
    if "le" in rng and _cmp(version, rng["le"]) > 0:
        return False
    if "lt" in rng and _cmp(version, rng["lt"]) >= 0:
        return False
    return True


@dataclass(frozen=True)
class CVE:
    id: str
    product: str                      # lowercased product key, e.g. "apache"
    title: str
    severity: str                     # critical|high|medium|low|info
    cwe: str
    affected: tuple[dict, ...]        # version ranges; any match => affected
    description: str
    remediation: str
    references: tuple[str, ...] = ()

    def applies_to(self, version: str) -> bool:
        return any(version_in_range(version, r) for r in self.affected)


@dataclass(frozen=True)
class Candidate:
    """A CVE matched to an observation. Detection only — not proof."""
    cve: CVE
    product: str
    version: str
    source: str                       # where the observation came from
    verdict: str = "detected"         # never "proven" from this engine
    verified: bool = False


# Banner product names differ from NVD CPE product keys (CPE uses vendor:product,
# e.g. apache:http_server). Map what a Server header says to the catalog key.
PRODUCT_ALIASES = {"apache": "http_server", "apache-coyote": "tomcat"}

# Minimal fallback used only if no feed file is present. Catalog keys match NVD
# CPE product ("http_server"), so banner "Apache" resolves via PRODUCT_ALIASES.
_BUILTIN: tuple[CVE, ...] = (
    CVE(id="CVE-2021-41773", product="http_server",
        title="Apache HTTP Server 2.4.49 パストラバーサル／RCE",
        severity="high", cwe="CWE-22", affected=({"eq": "2.4.49"},),
        description="2.4.49 の正規化処理の不備によるパストラバーサル（条件次第でRCE）。",
        remediation="2.4.51 以降へ更新し、既定の Require all denied を確認する。",
        references=("https://httpd.apache.org/security/vulnerabilities_24.html",)),
    CVE(id="CVE-2021-42013", product="http_server",
        title="Apache HTTP Server 2.4.49/2.4.50 パストラバーサル（修正不完全）",
        severity="critical", cwe="CWE-22", affected=({"ge": "2.4.49", "le": "2.4.50"},),
        description="CVE-2021-41773 の修正が不完全で 2.4.50 でも回避可能だった問題。",
        remediation="2.4.51 以降へ更新する。",
        references=("https://httpd.apache.org/security/vulnerabilities_24.html",)),
)

FEED_PATH = Path(__file__).parent / "feeds" / "nvd-recent.json"

_BANNER = re.compile(r"([A-Za-z][\w-]*)/(\d+(?:\.\d+)+)")

_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "NONE": "info"}


def _nvd_severity(cve_obj: dict) -> str:
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            sev = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity")
            if sev:
                return _SEV.get(sev.upper(), "info")
    return "info"


def _nvd_cwe(cve_obj: dict) -> str:
    for w in cve_obj.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):
                return v
    return "CWE-0"


def _nvd_ranges(cve_obj: dict) -> tuple[str, tuple[dict, ...]]:
    """Return (product, affected-ranges) from the first application cpeMatch."""
    product, ranges = "", []
    for cfg in cve_obj.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable", True):
                    continue
                parts = cm.get("criteria", "").split(":")
                if len(parts) < 6 or parts[2] != "a":
                    continue
                product = product or parts[4]
                r: dict = {}
                if cm.get("versionStartIncluding"):
                    r["ge"] = cm["versionStartIncluding"]
                if cm.get("versionStartExcluding"):
                    r["gt"] = cm["versionStartExcluding"]
                if cm.get("versionEndIncluding"):
                    r["le"] = cm["versionEndIncluding"]
                if cm.get("versionEndExcluding"):
                    r["lt"] = cm["versionEndExcluding"]
                if not r and parts[5] not in ("*", "-", ""):
                    r["eq"] = parts[5]          # exact version pinned in the CPE
                if r:
                    ranges.append(r)
    return product, tuple(ranges)


def load_nvd(obj: dict) -> list[CVE]:
    """Parse NVD CVE API 2.0 JSON into CVE records (application CPEs only).

    This is the ingestion path for a real feed: point it at a downloaded NVD
    JSON file or API response. It performs NO network I/O itself — the caller
    supplies the already-fetched object — so it is fully testable offline."""
    out: list[CVE] = []
    for v in obj.get("vulnerabilities", []):
        c = v.get("cve", {})
        cid = c.get("id")
        if not cid:
            continue
        product, ranges = _nvd_ranges(c)
        if not product or not ranges:
            continue                            # no usable application version range
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append(CVE(
            id=cid, product=product.lower(),
            title=(desc[:80] or cid),
            severity=_nvd_severity(c), cwe=_nvd_cwe(c),
            affected=ranges, description=desc,
            remediation="影響を受けないバージョンへ更新してください（ベンダー勧告を参照）。",
            references=tuple(r["url"] for r in c.get("references", []) if r.get("url"))[:5],
        ))
    return out


def match(product: str, version: str, catalog: tuple[CVE, ...] | None = None) -> list[CVE]:
    cat = CATALOG if catalog is None else catalog
    product = product.lower()
    return [c for c in cat if c.product == product and c.applies_to(version)]


def load_feed(path: Path = FEED_PATH) -> list[CVE]:
    """Ingest an NVD-format feed file from disk (no network). Returns [] if the
    file is absent or unreadable, so startup falls back to the built-in set."""
    try:
        return load_nvd(json.loads(path.read_text()))
    except (OSError, ValueError):
        return []


def build_catalog() -> tuple[CVE, ...]:
    feed = load_feed()
    return tuple(feed) if feed else _BUILTIN


# Catalog is ingested from the NVD-format feed at import; built-in is the fallback.
CATALOG: tuple[CVE, ...] = build_catalog()


def detect_from_banner(banner: str, *, source: str = "banner",
                       catalog: tuple[CVE, ...] | None = None) -> list[Candidate]:
    """Parse a 'Product/x.y.z' banner and return candidate CVEs (unverified)."""
    cat = CATALOG if catalog is None else catalog
    out: list[Candidate] = []
    for m in _BANNER.finditer(banner or ""):
        raw_product, version = m.group(1).lower(), m.group(2)
        product = PRODUCT_ALIASES.get(raw_product, raw_product)
        for cve in match(product, version, cat):
            out.append(Candidate(cve=cve, product=product, version=version, source=source))
    return out
