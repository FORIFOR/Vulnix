#!/usr/bin/env bash
# scripts/dev/l2-vm.sh — L2 をカーネル隔離（cgroup v2 + nftables）つきで動かす Linux VM ランナー
set -euo pipefail

command -v limactl >/dev/null || { echo "lima が見つかりません: brew install lima" >&2; exit 2; }

NAME="${VULNIX_L2_VM_NAME:-vulnix-l2}"
PORT="${VULNIX_PORT:-8787}"

if ! limactl list --quiet 2>/dev/null | grep -qx "$NAME"; then
  limactl start --name="$NAME" \
    --vm-type=vz --cpus=4 --memory=4 --disk=20 \
    --mount-only "$PWD:w" \
    --set ".portForwards = [{\"guestIP\":\"127.0.0.1\",\"guestPort\":${PORT},\"hostIP\":\"127.0.0.1\",\"hostPort\":${PORT},\"proto\":\"tcp\"},{\"guestIP\":\"0.0.0.0\",\"guestIPMustBeZero\":false,\"guestPortRange\":[1,65535],\"proto\":\"any\",\"ignore\":true}]" \
    template:ubuntu
else
  limactl start "$NAME" >/dev/null 2>&1 || true
fi

# Refuse to run inside a pre-existing VM whose host access differs from this
# runner's intended one-project mount and explicit loopback-only forwarding.
limactl list --json | python3 -c '
import json, os, sys
name, port, repo = sys.argv[1], int(sys.argv[2]), sys.argv[3]
instances = [json.loads(line) for line in sys.stdin if line.strip()]
vm = next((item for item in instances if item.get("name") == name), None)
if vm is None or vm.get("status") != "Running":
    sys.exit("Lima VM is not running")
config = vm["config"]
mounts = config.get("mounts") or []
rules = config.get("portForwards") or []
if len(mounts) != 1 or mounts[0].get("location") != repo:
    sys.exit("Unexpected VM host mount")
if len(rules) != 2 or rules[0].get("guestIP") != "127.0.0.1" or rules[0].get("guestPort") != port or rules[0].get("hostPort") != port or rules[0].get("hostIP") != "127.0.0.1" or rules[0].get("proto") != "tcp" or not rules[1].get("ignore") or rules[1].get("guestIP") != "0.0.0.0" or rules[1].get("guestIPMustBeZero") is not False or rules[1].get("guestPortRange") != [1, 65535] or rules[1].get("proto") != "any":
    sys.exit("Unexpected VM port forwarding")
' "$NAME" "$PORT" "$PWD"

# データディレクトリは VM 内に置く（virtiofs 越しだと 0700 検証と fsync が崩れるため）
limactl shell "$NAME" -- bash -lc "
  set -euo pipefail
  cd $(printf '%q' "$PWD")
  sudo -n true
  sudo -n nft list ruleset >/dev/null
  test -r /sys/fs/cgroup/cgroup.controllers
  mkdir -p \"\$HOME/vulnix-data\"
  chmod 700 \"\$HOME/vulnix-data\"
  exec env VULNIX_NO_ENV_LOCAL=1 python3 -m aegis.server --port $(printf '%q' "$PORT") --data-dir \"\$HOME/vulnix-data\"
"
