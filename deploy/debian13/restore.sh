#!/bin/sh
# Restore a backup made by backup.sh. The current data directory is kept aside, never
# deleted, so a wrong restore can be undone. Every audit log is verified before start:
# its hash chain, and against the local audit anchor (a separate user's record of each
# log's head, which a backup does not contain).
#
#   sh restore.sh BACKUP.tar.gz                    (root)
#   sh restore.sh BACKUP.tar.gz --accept-rollback  (root; the operator accepts the rollback)
#
# Restoring an older backup IS a rollback of the audit logs. Without --accept-rollback the
# service starts but refuses everything the anchor protects - new diagnoses, approvals,
# verdicts, paid sends, credential and privilege changes - and blocks sign-in of every
# existing account (aegis/operators.py), until an operator decides (exit status 3).
# With it, the anchor forgets the mismatched heads (recorded in the anchor's own chain as
# a reset) and anchoring resumes from the restored state.
set -eu
b=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
accept=${2:-}
[ -z "$accept" ] || [ "$accept" = --accept-rollback ] || { echo "unknown option: $accept" >&2; exit 2; }
(cd "$(dirname "$b")" && sha256sum -c "$(basename "$b").sha256")
systemctl stop vulnix-web vulnix-backend
aside="/var/lib/vulnix.before-restore.$(date -u +%Y%m%dT%H%M%SZ)"
[ -d /var/lib/vulnix ] && mv /var/lib/vulnix "$aside"
tar -C /var/lib -xzf "$b"
chown -R vulnix:vulnix /var/lib/vulnix && chmod 0700 /var/lib/vulnix

check() {
    # as the service user, with the service's anchor settings (read only)
    runuser -u vulnix -g vulnix -G vulnix-anchor -- env $(cat /etc/vulnix/anchor.env) \
        PYTHONPATH=/opt/vulnix/backend/vendor:/opt/vulnix/backend VULNIX_NO_ENV_LOCAL=1 \
        python3 -m aegis.audit_check --data-dir /var/lib/vulnix > /var/lib/vulnix-restore-check.json
}
rc=0; check || rc=$?
if [ "$rc" = 1 ]; then
    cat /var/lib/vulnix-restore-check.json
    echo "an audit hash chain does not verify; the services stay stopped (previous data in $aside)" >&2
    exit 1
fi
if [ "$rc" = 3 ] && [ "$accept" = --accept-rollback ]; then
    for src in $(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["mismatched_sources"]))' /var/lib/vulnix-restore-check.json); do
        runuser -u vulnix-anchor -- python3 -I -B /opt/vulnix-anchor/audit_anchor.py reset \
            --dir /var/lib/vulnix-anchor --source "$src"
    done
    rc=0; check || rc=$?
fi
cat /var/lib/vulnix-restore-check.json
systemctl start vulnix-backend
sleep 3
systemctl start vulnix-web
echo "restored; previous data kept in $aside"
if [ "$rc" != 0 ]; then
    echo "ROLLBACK DETECTED against the audit anchor: diagnoses, approvals, paid sends and sign-in stay refused." >&2
    echo "If this restore is intended, run again with --accept-rollback (the anchor records the reset)." >&2
    exit 3
fi
