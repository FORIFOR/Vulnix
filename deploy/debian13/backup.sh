#!/bin/sh
# Back up the Vulnix data directory with the services stopped (the ledger, audit logs and
# state are written together; a copy taken while running could be inconsistent).
#   sh backup.sh OUTPUT_DIR      (root; OUTPUT_DIR outside /var/lib/vulnix)
set -eu
out=$(cd "$1" && pwd)
case "$out/" in /var/lib/vulnix/*) echo 'OUTPUT_DIR must be outside the data directory' >&2; exit 2 ;; esac
stamp=$(date -u +%Y%m%dT%H%M%SZ)
systemctl stop vulnix-web vulnix-backend
trap 'systemctl start vulnix-backend; sleep 3; systemctl start vulnix-web' EXIT
umask 077
tar -C /var/lib -czf "$out/vulnix-data-$stamp.tar.gz" vulnix
(cd "$out" && sha256sum "vulnix-data-$stamp.tar.gz" > "vulnix-data-$stamp.tar.gz.sha256")
echo "$out/vulnix-data-$stamp.tar.gz"
