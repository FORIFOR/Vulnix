#!/bin/sh
# Public beta of the working app (sign-up, sign-in, organizations, sites, history, AI
# explanations) through a Cloudflare Quick Tunnel.
#
#   scripts/public-app.sh start    tunnel -> 127.0.0.1:3200 (Next.js production build) -> control plane
#   scripts/public-app.sh stop
#   scripts/public-app.sh status
#
# Requires the public control plane (VM: ~/vmscripts/start_public.sh) on 127.0.0.1:8788,
# started with VULNIX_PUBLIC_SIGNUP=1 and VULNIX_REAL_SERVICE_DIAGNOSIS=0 or l1 (read-only diagnosis of
# ownership-proven sites only; see docs/PUBLIC_BETA.md).
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
  echo "$me" | grep -q '"real_service_diagnosis": false' || { echo "実サイトへの通信が有効なコントロールプレーンは公開しません（VULNIX_REAL_SERVICE_DIAGNOSIS=0 または l1 が必要）"; exit 1; }
  echo "$me" | grep -q '"development": false' || { echo "開発モードのコントロールプレーンは公開しません"; exit 1; }
  if ! running web && curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/"; then
    echo "ポート $PORT は別のプロセスが使用中です。既存の Web サーバーを確認してください"
    exit 1
  fi
  cd "$ROOT/web"
  npm run build
  new_tunnel=0
  if ! running tunnel; then
    nohup cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >"$RUN/tunnel.log" 2>&1 &
    echo $! >"$RUN/tunnel.pid"
    new_tunnel=1
  fi
  url=""
  if [ "$new_tunnel" = 0 ] && [ -f "$RUN/url" ]; then
    url=$(grep -E '^https://[a-z0-9-]+\.trycloudflare\.com$' "$RUN/url" | head -1 || true)
  fi
  if [ -z "$url" ]; then
    for _ in $(seq 1 30); do
      url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$RUN/tunnel.log" | tail -1 || true)
      [ -n "$url" ] && break
      sleep 1
    done
  fi
  if [ -z "$url" ]; then
    [ "$new_tunnel" = 0 ] || { kill "$(cat "$RUN/tunnel.pid")" 2>/dev/null || true; rm -f "$RUN/tunnel.pid"; }
    echo "トンネルの URL を取得できませんでした（$RUN/tunnel.log）"
    exit 1
  fi
  host=${url#https://}
  if running web; then kill "$(cat "$RUN/web.pid")"; sleep 1; fi
  if curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/"; then
    echo "ポート $PORT はまだ使用中です。既存の Web サーバーを確認してください"
    exit 1
  fi
  # the proxy answers only for this host name (and loopback), and sends API calls to the
  # public control plane only
  VULNIX_APP_LANDING=1 AEGIS_UI_ALLOWED_HOSTS="$host" AEGIS_API="$API" nohup node node_modules/next/dist/bin/next start -p "$PORT" -H 127.0.0.1 \
    >"$RUN/web.log" 2>&1 &
  echo $! >"$RUN/web.pid"
  ready=0
  for _ in $(seq 1 10); do
    if ! running web; then break; fi
    if curl -fs --max-time 2 -o /dev/null -H "Host: $host" "http://127.0.0.1:$PORT/"; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    if running web; then kill "$(cat "$RUN/web.pid")" 2>/dev/null || true; fi
    rm -f "$RUN/web.pid"
    if [ "$new_tunnel" = 1 ]; then
      kill "$(cat "$RUN/tunnel.pid")" 2>/dev/null || true
      rm -f "$RUN/tunnel.pid"
    fi
    echo "Web サーバーが起動しませんでした（$RUN/web.log を確認してください）"
    exit 1
  fi
  echo "$url" >"$RUN/url"
  echo "$url"
  ;;
stop)
  for p in tunnel web; do
    if running "$p"; then kill "$(cat "$RUN/$p.pid")"; fi
    rm -f "$RUN/$p.pid"
  done
  rm -f "$RUN/url"
  echo "停止しました"
  ;;
status)
  for p in web tunnel; do
    if running "$p"; then echo "$p: 稼働中"; else echo "$p: 停止"; fi
  done
  if running tunnel; then cat "$RUN/url" 2>/dev/null || true; fi
  ;;
*)
  echo "usage: $0 start|stop|status"; exit 2 ;;
esac
