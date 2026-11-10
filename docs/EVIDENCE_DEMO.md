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
  The legacy `connected` field and `connection_verified` become true only after a
  valid explanation response. They record a successful response, not continuous
  connection health. Configuration alone is not a successful response.
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

## Response-grounded defense verification

The lab control now points to the actual HTTP server state. A successful defense
recheck requires the observed HTTP response and worker verdict to agree. For the
mock reproduction checks, HTTP 200 with the expected marker means `proven`,
HTTP 403 with a negative worker result means `not_reproduced`, and unknown,
contradictory or missing responses mean `unverified`. A failed mode switch must
not clear an existing finding. Reports and the beginner IDOR card follow the
latest evidence, never an older success after a failed recheck.

The beginner card explains the weak point, possible impact and remediation, then
shows the test caller, resource owner and actual HTTP result. Built-in explanations
are labeled separately from external model answers. Slow model replies merge into
the current snapshot so they cannot restore stale findings.

Manual local model check: Qwen3.5:4b via the OpenAI-compatible adapter produced an
IDOR-defense explanation after warm-up. The cold request timed out at 30 seconds;
the successful request took approximately 22 seconds. No paid API or model download
was used. This does not verify that Qwen or the installed custom model is abliterated.
