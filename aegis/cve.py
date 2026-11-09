"""CVE intelligence & continuous monitoring (P2): NVD CVE 2.0 + CISA KEV.

This engine turns an observation (e.g. a server banner) into *candidate*
findings and correlates them with CISA Known Exploited Vulnerabilities (KEV).
It embodies the project's first principle — separate detection from proof:
  * A match here is "detected (unverified)"; it is NEVER "proven".
  * Proving a finding requires an authorized L2 reproduction worker execution
    through the Gateway (`reproduction_probe`).
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


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
    product: str                      # lowercased product key, e.g. "http_server"
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
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    ransomware_use: str
    required_action: str


@dataclass(frozen=True)
class Candidate:
    """A CVE matched to an observation. Detection only — not proof."""
    cve: CVE
    product: str
    version: str
    source: str                       # where the observation came from
    verdict: str = "detected"         # never "proven" from this engine
    verified: bool = False
    in_kev: bool = False


PRODUCT_ALIASES = {"apache": "http_server", "apache-coyote": "tomcat"}

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
KEV_PATH = Path(__file__).parent / "feeds" / "cisa-kev.json"

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
    """Parse NVD CVE API 2.0 JSON into CVE records (application CPEs only)."""
    out: list[CVE] = []
    for v in obj.get("vulnerabilities", []):
        c = v.get("cve", {})
        cid = c.get("id")
        if not cid:
            continue
        product, ranges = _nvd_ranges(c)
        if not product or not ranges:
            continue
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


def load_cisa_kev(obj: dict) -> dict[str, KevEntry]:
    """Parse CISA Known Exploited Vulnerabilities (KEV) JSON into a dict by CVE ID."""
    out: dict[str, KevEntry] = {}
    for item in obj.get("vulnerabilities", []):
        cid = item.get("cveID")
        if not cid:
            continue
        out[cid] = KevEntry(
            cve_id=cid,
            vendor=str(item.get("vendorProject", "")),
            product=str(item.get("product", "")),
            name=str(item.get("vulnerabilityName", cid)),
            date_added=str(item.get("dateAdded", "")),
            due_date=str(item.get("dueDate", "")),
            ransomware_use=str(item.get("knownRansomwareCampaignUse", "Unknown")),
            required_action=str(item.get("requiredAction", "")),
        )
    return out


def load_kev_feed(path: Path = KEV_PATH) -> dict[str, KevEntry]:
    try:
        return load_cisa_kev(json.loads(path.read_text()))
    except (OSError, ValueError):
        return {}


def match(product: str, version: str, catalog: tuple[CVE, ...] | None = None) -> list[CVE]:
    cat = CATALOG if catalog is None else catalog
    product = product.lower()
    return [c for c in cat if c.product == product and c.applies_to(version)]


def load_feed(path: Path = FEED_PATH) -> list[CVE]:
    try:
        return load_nvd(json.loads(path.read_text()))
    except (OSError, ValueError):
        return []


def build_catalog() -> tuple[CVE, ...]:
    feed = load_feed()
    return tuple(feed) if feed else _BUILTIN


CATALOG: tuple[CVE, ...] = build_catalog()
KEV_CATALOG: dict[str, KevEntry] = load_kev_feed()


def detect_from_banner(banner: str, *, source: str = "banner",
                       catalog: tuple[CVE, ...] | None = None,
                       kev: dict[str, KevEntry] | None = None) -> list[Candidate]:
    """Parse a 'Product/x.y.z' banner and return candidate CVEs (unverified)."""
    cat = CATALOG if catalog is None else catalog
    kev_map = KEV_CATALOG if kev is None else kev
    out: list[Candidate] = []
    for m in _BANNER.finditer(banner or ""):
        raw_product, version = m.group(1).lower(), m.group(2)
        product = PRODUCT_ALIASES.get(raw_product, raw_product)
        for cve in match(product, version, cat):
            out.append(Candidate(
                cve=cve,
                product=product,
                version=version,
                source=source,
                in_kev=(cve.id in kev_map),
            ))
    return out


def _default_fetcher(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "vulnix-cve-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:    # pragma: no cover
        return r.read()


class FeedMonitor:
    """Continuous CVE & CISA KEV feed monitor and asset vulnerability correlator."""

    def __init__(self, *, catalog: tuple[CVE, ...] | None = None,
                 kev: dict[str, KevEntry] | None = None,
                 fetcher: Callable[[str], bytes] | None = None):
        self.catalog: tuple[CVE, ...] = catalog if catalog is not None else CATALOG
        self.kev: dict[str, KevEntry] = dict(kev if kev is not None else KEV_CATALOG)
        self._fetcher = fetcher or _default_fetcher
        self.last_synced_at: float = time.time()
        self.sync_source: str = "bundled_nvd_and_cisa_kev"
        self.sync_count: int = 0

    def ingest_payloads(self, *, nvd_obj: dict | None = None, kev_obj: dict | None = None,
                        source: str = "manual_ingest") -> dict:
        if nvd_obj is not None:
            parsed = load_nvd(nvd_obj)
            if parsed:
                by_id = {c.id: c for c in self.catalog}
                for c in parsed:
                    by_id[c.id] = c
                self.catalog = tuple(by_id.values())
        if kev_obj is not None:
            self.kev.update(load_cisa_kev(kev_obj))
        self.last_synced_at = time.time()
        self.sync_source = source
        self.sync_count += 1
        return self.status()

    def sync_from_urls(self, *, nvd_url: str | None = None, kev_url: str | None = None,
                       fetcher: Callable[[str], bytes] | None = None) -> dict:
        fn = fetcher or self._fetcher
        nvd_obj = json.loads(fn(nvd_url)) if nvd_url else None
        kev_obj = json.loads(fn(kev_url)) if kev_url else None
        return self.ingest_payloads(nvd_obj=nvd_obj, kev_obj=kev_obj, source="remote_feed_sync")

    def correlate_assets(self, asset_banners: dict[str, str] | list[dict]) -> dict[str, list[dict]] | list[dict]:
        """Match asset banners against the active CVE + KEV catalogs."""
        if isinstance(asset_banners, list):
            by_id: dict[str, list[dict]] = {}
            for item in asset_banners:
                aid = str(item.get("id", ""))
                banner = str(item.get("banner", ""))
                cands = detect_from_banner(banner, source=f"asset:{aid}",
                                           catalog=self.catalog, kev=self.kev)
                by_id[aid] = [
                    {
                        "id": c.cve.id,
                        "severity": c.cve.severity,
                        "in_kev": c.in_kev,
                        "kev_exploited": c.in_kev,
                        "verdict": c.verdict,
                        "verified": c.verified,
                        "ransomware_use": self.kev[c.cve.id].ransomware_use if c.in_kev else "Unknown",
                        "due_date": self.kev[c.cve.id].due_date if c.in_kev else None,
                    }
                    for c in cands
                ]
            return by_id

        results: list[dict] = []
        for aid, banner in asset_banners.items():
            cands = detect_from_banner(banner, source=f"asset:{aid}",
                                       catalog=self.catalog, kev=self.kev)
            results.append({
                "asset_id": aid,
                "banner": banner,
                "matched_cves": [
                    {
                        "id": c.cve.id,
                        "severity": c.cve.severity,
                        "in_kev": c.in_kev,
                        "kev_exploited": c.in_kev,
                        "verdict": c.verdict,
                        "verified": c.verified,
                        "ransomware_use": self.kev[c.cve.id].ransomware_use if c.in_kev else "Unknown",
                        "due_date": self.kev[c.cve.id].due_date if c.in_kev else None,
                    }
                    for c in cands
                ],
            })
        return results

    def status(self) -> dict:
        return {
            "cve_count": len(self.catalog),
            "kev_count": len(self.kev),
            "last_synced_at": self.last_synced_at,
            "sync_source": self.sync_source,
            "sync_count": self.sync_count,
            "cves": [
                {
                    "id": c.id,
                    "product": c.product,
                    "severity": c.severity,
                    "cwe": c.cwe,
                    "in_kev": c.id in self.kev,
                }
                for c in self.catalog
            ],
        }
