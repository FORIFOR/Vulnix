#!/bin/sh
# Build the private Linux arm64 web release candidate from a committed snapshot.
# The Linux counterpart of build-release-web.sh. Only `npm ci` reaches the network
# (the npm registry, every package checked against the lock file's integrity hash);
# the lock check, the build and the SBOM run with no network (unshare -rn).
set -eu
if [ "$#" -ne 3 ]; then
    echo 'Usage: scripts/build-release-web-linux.sh SOURCE_TAR NEXT_16_4_5_UPSTREAM_LOCK OUTPUT_PARENT' >&2
    echo '  VULNIX_RELEASE_SHA=<full sha>; SOURCE_TAR: git archive of that SHA (web aegis/feeds/nvd-recent.json aegis/public_catalog.py scripts/release-web-inventory.mjs)' >&2
    exit 2
fi
src_tar=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
lock=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
parent=$(cd "$3" && pwd)
# git archive writes the commit id into the tar header; it must be the SHA named here
sha=${VULNIX_RELEASE_SHA:-}
echo "$sha" | grep -Eq '^[0-9a-f]{40}$' || { echo 'Set VULNIX_RELEASE_SHA to the full commit SHA of the archive' >&2; exit 2; }
if command -v git >/dev/null; then
    test "$(git get-tar-commit-id < "$src_tar")" = "$sha" || { echo 'The archive is not of VULNIX_RELEASE_SHA' >&2; exit 2; }
fi
if tar -tf "$src_tar" | grep -Eq '(^|/)\.env[^/]*$|(^|/)data[^/]*/|\.key$|initial-credentials'; then
    echo 'Protected paths found in the release source tree' >&2
    exit 2
fi
node_bin=$(command -v node)
test "$(node -p 'process.platform + "/" + process.arch + "/" + process.version')" = linux/arm64/v22.23.5
command -v unshare >/dev/null
umask 077
work=$(mktemp -d "$parent/vulnix-web-$sha.XXXXXXXX")
mkdir -p "$work/source" "$work/runtime" "$work/tmp" "$parent/npm-cache"
touch "$work/npm-user" "$work/npm-global"
printf '%s\n' "$sha" > "$work/source-sha.txt"
cp "$src_tar" "$work/source.tar"
tar -xf "$work/source.tar" -C "$work/source"
cd "$work/source/web"

offline() {
    unshare -rn env -i PATH="$PATH" HOME="$work/tmp" TMPDIR="$work/tmp" NEXT_TELEMETRY_DISABLED=1 \
        VULNIX_RELEASE_BUILD=1 VULNIX_RELEASE_SHA="$sha" "$@"
}
# the one networked step: packages pinned by the lock file, install scripts not run
env -i PATH="$PATH" HOME="$work/tmp" TMPDIR="$work/tmp" npm --userconfig="$work/npm-user" \
    --globalconfig="$work/npm-global" --cache="$parent/npm-cache" ci --ignore-scripts --no-audit --no-fund
offline node ../scripts/release-web-inventory.mjs check-lock "$lock"
offline node node_modules/next/dist/bin/next build --webpack
cp -R .next/standalone/. "$work/runtime/"
cp -R public "$work/runtime/public"
cp -R .next/static "$work/runtime/.next/static"
test -f "$work/runtime/server.js"
mkdir "$work/runtime/catalog"
cp ../aegis/public_catalog.py "$work/runtime/catalog/public_catalog.py"
offline node ../scripts/release-web-inventory.mjs "$lock" "$work/runtime" "$work/web.cdx.json"

sha256sum package-lock.json next.config.ts "$lock" "$node_bin" "$work/runtime/catalog/public_catalog.py" "$work/web.cdx.json" > "$work/build-inputs.sha256"
{
    node -p 'JSON.stringify(process.versions)'
    npm --version
    uname -srm
    cat /etc/debian_version 2>/dev/null || true
} > "$work/build-runtime.txt"
tar -C "$work/runtime" --sort=name -czf "$work/web-linux-arm64.private.tar.gz" .
(cd "$work" && sha256sum web-linux-arm64.private.tar.gz web.cdx.json > SHA256SUMS)
printf 'Private server artifact and evidence: %s\n' "$work"
