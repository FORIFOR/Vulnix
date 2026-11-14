#!/bin/sh
# Public beta (view-only landing page) through a Cloudflare Quick Tunnel.
#
#   scripts/public-beta.sh start    build if needed, start the public instance on 127.0.0.1:3100
#                                   (VULNIX_PUBLIC_MODE=1) and a Quick Tunnel to it; prints the URL
#   scripts/public-beta.sh stop     stop the tunnel and the public instance
#   scripts/public-beta.sh status   show whether they run and the current URL
#
# The public instance serves the landing page and its media only: every /api path is
# 404 and every other page redirects to "/". Its API upstream points at a closed port,
# so even a bypass of that guard reaches no control plane. The local operator UI
# (port 3000) and the control plane (8787) are not exposed.
# A Quick Tunnel URL changes on every start; a fixed hostname needs a named tunnel.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUN=${VULNIX_PUBLIC_RUN_DIR:-"$HOME/.vulnix-public-beta"}
PORT=${VULNIX_PUBLIC_PORT:-3100}
mkdir -p "$RUN"

running() { [ -f "$RUN/$1.pid" ] && kill -0 "$(cat "$RUN/$1.pid")" 2>/dev/null; }

case "${1:-}" in
start)
  command -v cloudflared >/dev/null || { echo "cloudflared がありません: brew install cloudflared"; exit 1; }
  cd "$ROOT/web"
  [ -f .next/BUILD_ID ] || npm run build
  if ! running web; then
    VULNIX_PUBLIC_MODE=1 AEGIS_API=http://127.0.0.1:9 nohup npx next start -p "$PORT" -H 127.0.0.1 \
      >"$RUN/web.log" 2>&1 &
    echo $! >"$RUN/web.pid"
    sleep 4
  fi
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/api/health" || true)
  [ "$code" = "404" ] || { echo "公開モードの確認に失敗しました (/api/health -> $code)。停止します"; "$0" stop; exit 1; }
  if ! running tunnel; then
    nohup cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >"$RUN/tunnel.log" 2>&1 &
    echo $! >"$RUN/tunnel.pid"
  fi
  for _ in $(seq 1 30); do
    url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$RUN/tunnel.log" | head -1 || true)
    [ -n "$url" ] && break
    sleep 1
  done
  echo "${url:-URL を取得できませんでした（$RUN/tunnel.log を確認してください）}"
  ;;
stop)
  for p in tunnel web; do
    if running "$p"; then kill "$(cat "$RUN/$p.pid")"; fi
    rm -f "$RUN/$p.pid"
  done
  echo "停止しました"
  ;;
status)
  for p in web tunnel; do
    if running "$p"; then echo "$p: 稼働中"; else echo "$p: 停止"; fi
  done
  grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$RUN/tunnel.log" 2>/dev/null | head -1 || true
  ;;
*)
  echo "usage: $0 start|stop|status"; exit 2 ;;
esac
