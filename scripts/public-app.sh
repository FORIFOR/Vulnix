#!/bin/sh
# Public beta of the working app (sign-up, sign-in, organizations, sites, history, AI
# explanations) through a Cloudflare Quick Tunnel.
#
#   scripts/public-app.sh start    tunnel -> 127.0.0.1:3200 (Next.js production build) -> control plane
#   scripts/public-app.sh stop
#   scripts/public-app.sh status
#
# Requires the public control plane (VM: ~/vmscripts/start_public.sh) on 127.0.0.1:8788,
# started with VULNIX_PUBLIC_SIGNUP=1 VULNIX_REAL_SERVICE_DIAGNOSIS=0 (see docs/PUBLIC_BETA.md).
# Only this UI is exposed; the control plane, ARTEX, workers and databases are not.
# The Quick Tunnel URL changes on every start.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUN=${VULNIX_APP_RUN_DIR:-"$HOME/.vulnix-public-app"}
PORT=${VULNIX_APP_PORT:-3200}
API=${VULNIX_APP_API:-http://127.0.0.1:8788}
mkdir -p "$RUN"
running() { [ -f "$RUN/$1.pid" ] && kill -0 "$(cat "$RUN/$1.pid")" 2>/dev/null; }

case "${1:-}" in
start)
  command -v cloudflared >/dev/null || { echo "cloudflared がありません: brew install cloudflared"; exit 1; }
  curl -s -o /dev/null "$API/api/health" || { echo "コントロールプレーン（$API）が起動していません"; exit 1; }
  me=$(curl -s "$API/api/auth/me")
  echo "$me" | grep -q '"multi_tenant": true' || { echo "組織分離が無効なコントロールプレーンは公開しません"; exit 1; }
  echo "$me" | grep -q '"real_service_diagnosis": false' || { echo "実サイトへの通信が有効なコントロールプレーンは公開しません（VULNIX_REAL_SERVICE_DIAGNOSIS=0 が必要）"; exit 1; }
  echo "$me" | grep -q '"development": false' || { echo "開発モードのコントロールプレーンは公開しません"; exit 1; }
  if ! running tunnel; then
    nohup cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >"$RUN/tunnel.log" 2>&1 &
    echo $! >"$RUN/tunnel.pid"
  fi
  url=""
  for _ in $(seq 1 30); do
    url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$RUN/tunnel.log" | head -1 || true)
    [ -n "$url" ] && break
    sleep 1
  done
  [ -n "$url" ] || { echo "トンネルの URL を取得できませんでした（$RUN/tunnel.log）"; exit 1; }
  host=${url#https://}
  cd "$ROOT/web"
  [ -f .next/BUILD_ID ] || npm run build
  if running web; then kill "$(cat "$RUN/web.pid")"; sleep 1; fi
  # the proxy answers only for this host name (and loopback), and sends API calls to the
  # public control plane only
  VULNIX_APP_LANDING=1 AEGIS_UI_ALLOWED_HOSTS="$host" AEGIS_API="$API" nohup npx next start -p "$PORT" -H 127.0.0.1 \
    >"$RUN/web.log" 2>&1 &
  echo $! >"$RUN/web.pid"
  echo "$url" >"$RUN/url"
  sleep 5
  echo "$url"
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
  cat "$RUN/url" 2>/dev/null || true
  ;;
*)
  echo "usage: $0 start|stop|status"; exit 2 ;;
esac
