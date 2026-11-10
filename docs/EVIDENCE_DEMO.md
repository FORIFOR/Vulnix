# Evidence workspace and safe demo

This change is presentation-only. It does not grant authority, alter Gateway,
change network controls, or bypass approval. The built-in lab is a Python HTTP
simulation, not an actual Apache installation, production SQL database, or external
security assessment. `not_reproduced` is a result under the tested conditions,
not a guarantee of safety.

## Changes

- Each finding gets an `evidence_status`. Candidates without a timestamped,
  audit-linked record are not counted as measured results. Fixtures and interrupted
  checks remain separate.
- SSE finding updates carry the same classification and counters as the snapshot,
  keeping counts live without a page reload.
- Five evidence counters link to filters. The URL preserves filters through
  Back/Forward; invalid tabs and filters fall back safely.
- The actual loaded proposal backends are returned in the snapshot and router
  status. An endpoint configuration is not proof of a working connection.
  The legacy `connected` field remains false; use `external_model_configured` and
  `connection_verified` separately. This version does not perform a health probe.
- The lab banner uses the actual port and explicitly labels simulated behavior.
  Prior-run sample history is labeled fictional. Reports include these limits,
  evidence counts, and an unevaluated risk label before the first scan.
- Report download failures are shown with a retryable state. Long JSON output
  scrolls inside its panel instead of expanding the assessment grid.

## Reproducible isolated capture

Use an isolated worktree, never the user's existing data directory. Choose free
loopback ports. Start the server without model URL/key environment variables so
no external AI requests occur:

```sh
DEMO_DATA="$(mktemp -d)"
env -u AEGIS_MODEL_URL -u AEGIS_MODEL_KEY \
    -u VULNIX_MODEL_URL -u VULNIX_MODEL_KEY \
    -u VULNIX_ABLITERATION_URL -u VULNIX_ABLITERATION_KEY \
    python3 -m aegis.server --port 8877 --lab-port 18181 \
    --verify-seconds 1 --data-dir "$DEMO_DATA"
# Separate shell, after cd web and npm ci:
npm run build
AEGIS_API=http://127.0.0.1:8877 npx next start --hostname 127.0.0.1 --port 3107
```

Read only the newly generated demo credentials locally. Never film, commit or
share the credentials or session files. In a fresh browser profile:

1. Sign in with the generated approver account. Open `/assessments/scan_001`.
   Capture 3 unmeasured candidates, built-in planner status and lab disclosure.
2. Start the diagnosis. Capture pending human approval. The CVE/banner finding
   is detected but not proven. Header/configuration checks can already be proven
   through low-risk observation; the counters need not all be zero.
3. Approve the request. The isolated worker probes produce evidence and update
   the CVE/banner, IDOR and SQL simulation findings to proven.
4. Open a finding's evidence and the audit log. Capture the actual response and
   evidence ID without representing mock markers as real-world exploitation.
5. Select the defense-mode recheck after completion. This switches the built-in
   lab's simulated behavior; it does not patch arbitrary software. Capture the
   actual before/after comparison, not the fictional prior-run sample history.
6. Export Markdown. Verify scope, state counts, caveats and evidence IDs.

## Validation

```sh
python3 -m pytest tests/
cd web && npm test && npm run typecheck && npm run lint && npm run build
```

Optional read-only browser checks use Python Playwright and an installed Chrome,
a fresh browser profile, and only the generated local operator account. They do
not start any diagnostic worker or change the lab mode:

```sh
python3 scripts/check_evidence_ui.py \
  --url http://127.0.0.1:3107 \
  --credentials "$DEMO_DATA/operators.initial-credentials.txt" \
  --screenshots /tmp/vulnix-ui-qa
```

Run the UI check after a completed before/after flow to exercise populated JSON
and comparison layout, then again on a fresh initial snapshot. It covers filter,
reset, Back/Forward, invalid queries, export failure/retry/download, preview
open/close, mobile width, desktop width and browser page errors. Export failure
is injected only inside the test browser.
