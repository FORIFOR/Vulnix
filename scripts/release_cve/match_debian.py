"""Installed Debian packages vs the Debian security tracker (offline copy).

usage: python3 match_debian.py CACHE_DIR deb-packages.txt RELEASE > result.json
"""
import json
import re
import sys
from pathlib import Path


def _order(c):
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256 if c else 0


def _cmp_part(a, b):
    while a or b:
        na = re.match(r"^\D*", a).group(0)
        nb = re.match(r"^\D*", b).group(0)
        a, b = a[len(na):], b[len(nb):]
        for i in range(max(len(na), len(nb))):
            ca = _order(na[i] if i < len(na) else "")
            cb = _order(nb[i] if i < len(nb) else "")
            if ca != cb:
                return -1 if ca < cb else 1
        da = re.match(r"^\d*", a).group(0)
        db = re.match(r"^\d*", b).group(0)
        a, b = a[len(da):], b[len(db):]
        ia, ib = int(da or 0), int(db or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


def dpkg_cmp(x, y):
    def split(v):
        epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
        up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "0")
        return int(epoch or 0), up, rev
    ex, ux, rx = split(x)
    ey, uy, ry = split(y)
    if ex != ey:
        return -1 if ex < ey else 1
    return _cmp_part(ux, uy) or _cmp_part(rx, ry)


def main():
    cache, pk, release = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    tracker = json.loads((cache / "debian-tracker.json").read_text())
    kev = {v["cveID"] for v in json.loads((cache / "cisa-kev.json").read_text())["vulnerabilities"]}
    sources = {}
    for line in pk.read_text().splitlines()[2:]:
        parts = line.split()
        if len(parts) >= 5 and parts[4].startswith("ii"):
            if parts[1].startswith("linux-signed"):
                # the signed image is built from the "linux" source at the image's version
                if parts[0].startswith("linux-image-") and parts[0].endswith("cloud-arm64") and "+deb" in parts[0]:
                    sources.setdefault(f"linux@{parts[3]}", parts[3])
                continue
            sources.setdefault(parts[1], parts[2])
    out = []
    for src, ver in sorted(sources.items()):
        for cve, info in (tracker.get(src.split("@")[0]) or {}).items():
            rel = (info.get("releases") or {}).get(release)
            if not rel:
                continue
            status, fixed, urg = rel.get("status"), rel.get("fixed_version"), rel.get("urgency", "")
            row = {"source": src, "installed": ver, "cve": cve, "urgency": urg, "kev": cve in kev,
                   "fixed": fixed, "nodsa": rel.get("nodsa"), "desc": (info.get("description") or "")[:140]}
            if status == "open":
                out.append({**row, "state": "open_in_debian"})
            elif status == "resolved" and fixed and fixed != "0" and dpkg_cmp(ver, fixed) < 0:
                out.append({**row, "state": "fix_not_installed"})
            elif status == "undetermined":
                out.append({**row, "state": "undetermined"})
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)


assert dpkg_cmp("6.12.118-1", "6.12.119-1") < 0 and dpkg_cmp("1:1.0", "2.0") > 0 and dpkg_cmp("1.0~rc1", "1.0") < 0
assert dpkg_cmp("3.0.15-1~deb12u1", "3.0.15-1") < 0 and dpkg_cmp("2.36-9+deb12u10", "2.36-9+deb12u9") > 0
main()
