"""Match package inventories against the official OSV bulk data, offline.

usage: python3 -I match_osv.py CACHE_DIR inventory.json > result.json
inventory.json: [{"eco": "PyPI"|"npm", "name": ..., "version": ..., "where": ...}]
Nothing is sent anywhere: the OSV zip files were downloaded once and are read locally.
"""
import json
import re
import sys
import zipfile
from pathlib import Path

from packaging.version import InvalidVersion, Version


def npm_key(v):
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", v)
    if not m:
        return None
    pre = m.group(4)
    parts = []
    if pre:
        for p in pre.split("."):
            parts.append((0, int(p), "") if p.isdigit() else (1, 0, p))
    # a release sorts after its pre-releases
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, tuple(parts))


def key(eco, v):
    if eco == "PyPI":
        try:
            return Version(v)
        except InvalidVersion:
            return None
    return npm_key(v)


def affected(eco, name, version, vuln):
    k = key(eco, version)
    hits = []
    for a in vuln.get("affected", []):
        pkg = a.get("package", {})
        if pkg.get("ecosystem") != eco:
            continue
        pn = pkg.get("name", "")
        if (pn.lower().replace("_", "-") if eco == "PyPI" else pn) != (name.lower().replace("_", "-") if eco == "PyPI" else name):
            continue
        if version in a.get("versions", []):
            hits.append(a)
            continue
        if k is None:
            continue
        for r in a.get("ranges", []):
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            lo, inside = None, False
            for ev in r.get("events", []):
                if "introduced" in ev:
                    lo = ev["introduced"]
                    lk = key(eco, lo) if lo != "0" else None
                    inside = lo == "0" or (lk is not None and lk <= k)
                elif "fixed" in ev and inside:
                    fk = key(eco, ev["fixed"])
                    if fk is not None and k < fk:
                        hits.append(a)
                    inside = False
                elif "last_affected" in ev and inside:
                    fk = key(eco, ev["last_affected"])
                    if fk is not None and k <= fk:
                        hits.append(a)
                    inside = False
            if inside:              # introduced with no fix yet
                hits.append(a)
    return hits


def fixed_versions(hits):
    out = set()
    for a in hits:
        for r in a.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    out.add(ev["fixed"])
    return sorted(out)


def main():
    cache, inv_path = Path(sys.argv[1]), Path(sys.argv[2])
    inventory = json.loads(inv_path.read_text())
    kev = {v["cveID"] for v in json.loads((cache / "cisa-kev.json").read_text())["vulnerabilities"]}
    wanted = {}
    for row in inventory:
        n = row["name"].lower().replace("_", "-") if row["eco"] == "PyPI" else row["name"]
        wanted.setdefault((row["eco"], n), []).append(row)
    results = []
    for eco in sorted({r["eco"] for r in inventory}):
        with zipfile.ZipFile(cache / f"osv-{eco}.zip") as z:
            for info in z.infolist():
                vuln = json.loads(z.read(info))
                if vuln.get("withdrawn"):
                    continue
                names = {(a.get("package", {}).get("name", "").lower().replace("_", "-") if eco == "PyPI"
                          else a.get("package", {}).get("name", "")) for a in vuln.get("affected", [])}
                for n in names:
                    for row in wanted.get((eco, n), []):
                        hits = affected(eco, row["name"], row["version"], vuln)
                        if not hits:
                            continue
                        aliases = [a for a in [vuln["id"], *vuln.get("aliases", [])] if a.startswith("CVE-")]
                        sev = (vuln.get("database_specific") or {}).get("severity")
                        results.append({"eco": eco, "name": row["name"], "version": row["version"], "where": row.get("where"),
                                        "id": vuln["id"], "cve": aliases, "severity": sev,
                                        "kev": any(c in kev for c in aliases), "fixed": fixed_versions(hits),
                                        "summary": (vuln.get("summary") or "")[:160]})
    json.dump(sorted(results, key=lambda r: (r["eco"], r["name"], r["id"])), sys.stdout, ensure_ascii=False, indent=1)


main()
