#!/bin/sh
# Build the private macOS arm64 release candidate from a committed snapshot.
set -eu
if [ "$#" -ne 2 ]; then
    echo 'Usage: scripts/build-release-web.sh NEXT_16_4_5_UPSTREAM_LOCK OUTPUT_PARENT' >&2
    exit 2
fi

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
sha=$(git -C "$root" rev-parse HEAD)
lock=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
parent=$(cd "$2" && pwd)
node_bin=$(command -v node)
test "$(node -p 'process.platform + "/" + process.arch + "/" + process.version')" = darwin/arm64/v22.23.5
umask 077
work=$(mktemp -d "$parent/vulnix-web-$sha.XXXXXXXX")
mkdir "$work/source" "$work/runtime" "$work/tmp"
touch "$work/npm-user" "$work/npm-global"
printf '%s\n' "$sha" > "$work/source-sha.txt"

git -C "$root" archive --output="$work/source.tar" "$sha" web aegis/feeds/nvd-recent.json scripts/release-web-inventory.mjs
tar -xf "$work/source.tar" -C "$work/source"
cd "$work/source/web"

offline() {
    /usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' \
        env -i PATH="$PATH" TMPDIR="$work/tmp" NEXT_TELEMETRY_DISABLED=1 \
        VULNIX_RELEASE_BUILD=1 VULNIX_RELEASE_SHA="$sha" "$@"
}
offline npm --userconfig="$work/npm-user" --globalconfig="$work/npm-global" \
    --cache="$HOME/.npm" ci --offline --ignore-scripts --no-audit --no-fund
offline node ../scripts/release-web-inventory.mjs check-lock "$lock"
offline node node_modules/next/dist/bin/next build --webpack
cp -R .next/standalone/. "$work/runtime/"
cp -R public "$work/runtime/public"
cp -R .next/static "$work/runtime/.next/static"
test -f "$work/runtime/server.js"
offline node ../scripts/release-web-inventory.mjs "$lock" "$work/runtime" "$work/web.cdx.json"

shasum -a 256 package-lock.json next.config.ts "$lock" "$node_bin" "$work/web.cdx.json" > "$work/build-inputs.sha256"
{
    node -p 'JSON.stringify(process.versions)'
    npm --version
    sw_vers
} > "$work/build-runtime.txt"
COPYFILE_DISABLE=1 tar -C "$work/runtime" -czf "$work/web-darwin-arm64.private.tar.gz" .
(cd "$work" && shasum -a 256 web-darwin-arm64.private.tar.gz web.cdx.json > SHA256SUMS)
printf 'Private server artifact and evidence: %s\n' "$work"
