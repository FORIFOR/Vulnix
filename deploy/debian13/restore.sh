#!/bin/sh
# Restore a backup made by backup.sh. The current data directory is kept aside, never
# deleted, so a wrong restore can be undone. The audit logs are verified before start.
#   sh restore.sh BACKUP.tar.gz   (root)
set -eu
b=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
(cd "$(dirname "$b")" && sha256sum -c "$(basename "$b").sha256")
systemctl stop vulnix-web vulnix-backend
aside="/var/lib/vulnix.before-restore.$(date -u +%Y%m%dT%H%M%SZ)"
[ -d /var/lib/vulnix ] && mv /var/lib/vulnix "$aside"
tar -C /var/lib -xzf "$b"
chown -R vulnix:vulnix /var/lib/vulnix && chmod 0700 /var/lib/vulnix
runuser -u vulnix -- env PYTHONPATH=/opt/vulnix/backend/vendor:/opt/vulnix/backend VULNIX_NO_ENV_LOCAL=1 python3 - <<'PY'
from pathlib import Path
from aegis.audit import AuditLog
for name in ("audit.jsonl", "platform-audit.jsonl"):
    p = Path("/var/lib/vulnix") / name
    if p.exists():
        assert AuditLog(p).verify(), f"{name}: the hash chain does not verify"
        print(f"{name}: verified")
PY
systemctl start vulnix-backend
sleep 3
systemctl start vulnix-web
echo "restored; previous data kept in $aside"
