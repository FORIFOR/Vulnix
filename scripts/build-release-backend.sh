#!/bin/sh
# Build the private Linux arm64 backend release archive from ONE committed snapshot, with
# no network: the dependencies come from a local wheelhouse checked against its SHA256SUMS,
# pinned by a lock file (Python 3.13, manylinux aarch64 wheels only, nothing compiled).
#
#   scripts/build-release-backend.sh SHA WHEELHOUSE LOCK_FILE BUILD_PYTHON OUTPUT_DIR
#
# OUTPUT_DIR gets backend-linux-arm64.private.tar.gz (backend/ + source-sha.txt) and
# backend.cdx.json (CycloneDX 1.5: every vendored distribution with its wheel SHA-256).
set -eu
if [ "$#" -ne 5 ]; then
    sed -n '2,10p' "$0" >&2
    exit 2
fi
sha=$1
wheels=$(cd "$2" && pwd)
lock=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
python=$4
out=$(cd "$5" && pwd)
repo=$(cd "$(dirname "$0")/.." && pwd)
echo "$sha" | grep -Eq '^[0-9a-f]{40}$' || { echo 'SHA must be a full commit id' >&2; exit 2; }
umask 077
(cd "$wheels" && shasum -a 256 -c SHA256SUMS >/dev/null) || { echo 'wheelhouse does not match its SHA256SUMS' >&2; exit 1; }
work=$(mktemp -d "${TMPDIR:-/tmp}/vulnix-backend-$sha.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/backend/vendor"
git -C "$repo" archive --format=tar "$sha" aegis requirements-oidc.txt LICENSE > "$work/source.tar"
test "$(git get-tar-commit-id < "$work/source.tar")" = "$sha"
if tar -tf "$work/source.tar" | grep -Eq '(^|/)\.env[^/]*$|(^|/)data[^/]*/|\.key$|initial-credentials'; then
    echo 'Protected paths found in the release source tree' >&2
    exit 2
fi
tar -xf "$work/source.tar" -C "$work/backend"
cp "$lock" "$work/backend/requirements-prod.txt"
PIP_CONFIG_FILE=/dev/null "$python" -m pip --isolated --disable-pip-version-check install \
    --no-index --find-links "$wheels" --only-binary=:all: \
    --platform manylinux_2_28_aarch64 --platform manylinux2014_aarch64 \
    --implementation cp --python-version 3.13 --target "$work/backend/vendor" \
    --no-compile -r "$work/backend/requirements-prod.txt" >/dev/null
find "$work/backend" -name __pycache__ -prune -exec rm -rf {} +
printf '%s\n' "$sha" > "$work/source-sha.txt"
if tar --version 2>/dev/null | grep -q bsdtar; then
    xattrs="--no-xattrs --no-mac-metadata"         # macOS: no provenance attributes in the archive
else
    xattrs="--no-xattrs"
fi
# shellcheck disable=SC2086
(cd "$work" && COPYFILE_DISABLE=1 tar $xattrs -czf "$out/backend-linux-arm64.private.tar.gz" backend source-sha.txt)
"$python" - "$work/backend/vendor" "$wheels" "$sha" > "$out/backend.cdx.json" <<'PY'
import hashlib, json, re, sys, uuid
from pathlib import Path
vendor, wheels, sha = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
digests = {}
for w in wheels.glob("*.whl"):
    digests[w.name.split("-")[0].lower().replace("_", "-")] = (w.name, hashlib.sha256(w.read_bytes()).hexdigest())
comps = []
for meta in sorted(vendor.glob("*.dist-info/METADATA")):
    text = meta.read_text(errors="replace")
    name = re.search(r"^Name: (.+)$", text, re.M).group(1).strip()
    version = re.search(r"^Version: (.+)$", text, re.M).group(1).strip()
    key = name.lower().replace("_", "-")
    c = {"type": "library", "name": name, "version": version, "purl": f"pkg:pypi/{key}@{version}"}
    if key in digests:
        c["hashes"] = [{"alg": "SHA-256", "content": digests[key][1]}]
        c["properties"] = [{"name": "wheel", "value": digests[key][0]}]
    comps.append(c)
print(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                  "version": 1, "metadata": {"component": {"type": "application", "name": "vulnix-backend",
                                                           "version": sha}},
                  "components": comps}, indent=1))
PY
chmod 600 "$out/backend-linux-arm64.private.tar.gz" "$out/backend.cdx.json"
echo "$out/backend-linux-arm64.private.tar.gz"
