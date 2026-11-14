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

## Real-model explanation quality evaluation (approved: up to 8 calls, cap $0.10)

Questions: 4 each (reason/evidence, risk, fix, how to verify) about `f_powered` (detected, unproven) and `f_idor` (proven by L2). **8 calls, 0 failures.**

| Aspect | Result |
|---|---|
| Accuracy of evidence | All 8 cite the actual evidence ID (`ev_5589efc46f92` / `ev_5fae37b843f8`) or the observed value (`X-Powered-By: PHP/8.1.0`) correctly |
| L1/L2 distinction | All 4 answers about the unproven finding say "can't be confirmed until L2 checks it"; all 4 about the proven one say "reproduced with mock data, not a leak" |
| Fixes | Appropriate: `expose_php = Off`; check the owner on the server and return 403 on mismatch; how to verify after fixing |
| Dangerous suggestions / overclaims | None (automatic check: 0 withheld, 0 cautions; also read by hand) |
| Format | All 8 contain all 5 sections |

Problems found, and the fix (no further calls):
1. One answer translated proven as 「承認済み」 → the prompt now pins the Japanese verdict terms (proven = 実証済み).
2. One answer quoted the whole assessment's risk score (94) as the finding's score → the context now carries `risk_scope` ("whole assessment") and the prompt says to use `severity` for an individual finding.
3. Every answer repeated all five sections whatever was asked (long) → the prompt now says to answer the question directly first and keep it to the relevant sections.

## Re-measurement after the fixes (approved: 4 calls, cap $0.05)

Asked again the questions that showed the problems (`f_idor` proven: reason/evidence and risk; `f_powered` unproven: fix and how to verify). **4 calls, 0 failures, nothing withheld, no cautions.**

| Problem | Before | After |
|---|---|---|
| Translation of proven | 「承認済み」 (1 of 8 answers) | 「実証済み（proven）」; 「承認済み」 appears in none |
| Risk score attribution | Quoted the assessment-wide 94 as the finding's score | 「診断全体のリスクスコア（94）とは異なり、この問題単独の重さは high」 |
| Length / focus | All five sections every time (about 600–900 characters) | Answers the question directly, 118–305 characters |

The L1/L2 distinction (「検出（未実証）」 for the unproven finding, 「模擬データでの実証であり流出ではない」 for the proven one) and the evidence citations were kept.
