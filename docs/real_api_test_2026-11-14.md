# Real-API integration test (2026-11-14, after user approval)

Target: the local mock lab only (`lab.test` → 127.0.0.1). No traffic to real services.
Environment: dedicated Linux VM (Ubuntu 24.04, kernel 6.8) with the real ARTEX (`github.com/Autumn-27/artex` commit `d6964594`, overlay build sha256 `2860b077…`), the Vulnix integration build (PRs #4, #7–#13) and the real Abliteration AI (`abliterated-model`).
Approved limits: at most 7 calls, at most $0.50, stop at the first error with no retry.

## Results

| Check | Result | Evidence |
|---|---|---|
| Preview fingerprint before the real send | Match (`9abde4f1…`), 0 external calls | `planner_llm.call decision=previewed` |
| Multi-turn planning (real ARTEX × real model) | **Succeeded: 3 turns, 0 failures** (completion 2,048 / 937 / 187 tokens, estimated $0.025) | `planner_llm.forwarding` ×3, `failed: 0` |
| ARTEX isolation | Own netns (`lo` only), seccomp=2, host paths hidden, no files left after the run | the plan's `isolation` |
| ARTEX tool use | `add_intent` only; nothing refused | `tool_calls`, `denied_tool_calls` |
| Plan → Gateway | 3 intents → 1 mapped to `l2_idor`; 2 shown as "reference only" (not in the permitted catalog: deeper SQLi exploitation, authentication bypass) | `artex.intent_advisory` |
| Unapproved L2 is refused | `operator`: 403 (approver role required); the plan's requester `approver`: 403 (separation of duties) | `artex.item_denied` ×2 |
| Approved L2 | `approver2` approved → Gateway `allow reproduction_probe` → isolated worker rc=0 → `f_idor` became **proven**, evidence `ev_693d8dfbb730` | `artex.item_approved`, `allow` |
| L1 | Diagnosis start → Gateway `allow http_probe` → scope, public-settings and analysis phases completed, then waits for L2 approval | `allow http_probe` |
| Japanese explanation (real model) | 1 call, `answered_by=external_model`, not withheld, no cautions. Answer in the order problem / basis / risk / fix / how to verify, without assertions. The code-written verdict note is shown above it | `chat.asked` |
| Call count / cost | ARTEX 3 + explanation 1 = **4 calls** (cap 7), well under $0.50 | audit |
| API key | Absent from the logs, audit log, state files and ARTEX DB (checked inside the VM by literal match) | — |
| Audit chain | Valid | `chain_valid: true` |

## Cause of the previous failure (call 2 HTTPError)
In this run, every turn including turn 2 succeeded after the Chat Completions tool-calling shape was normalized (PR #12). The previous run's HTTP status was not recorded, so the cause can't be pinned down, but the shape mismatch is the likely candidate. Any future failure stops at the first error with the status recorded.

## Issues found
- ARTEX's intent descriptions are in Korean (ARTEX's own prompts are Korean). The UI now shows them as "ARTEX original text (AI output, untranslated; does not decide what runs)". What runs is decided by the Japanese catalog label written by Vulnix.
- An ARTEX intent can mention more than the catalog allows (e.g. "whether the resource can be modified"); what actually runs is the catalog's non-destructive read.
