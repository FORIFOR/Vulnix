# holdout v4: independent second labels

Labelled blind from `holdout_v4_cases.json` and `holdout_v4_lab.py`. I did not read the author's labels or notes, the judge or the evidence code. Criteria: LABEL_REVIEW_SHEET.md. `authentication_required` means only B may read; `null` or `unspecified` means no reader rule. withhold_ok = the evidence a checker can gather cannot settle the question (no owner control, or rate limited).

| case | other_account_read | unauthenticated_exposure | fix | withhold_ok | rationale |
| --- | --- | --- | --- | --- | --- |
| holdout-v4-001 | contradicted | contradicted | - | False | A gets HTML API docs at the resource URL; marker is a '<string>' placeholder, no B data. |
| holdout-v4-002 | supported | contradicted | fixed | False | A gets a page whose only item is B's record (ownerId acct_B, secretValue = marker). After fix A gets own items. |
| holdout-v4-003 | supported | contradicted | - | False | A gets B's record as XML (owner acct_B, marker). |
| holdout-v4-004 | contradicted | contradicted | - | False | A gets own HTML page (escaped acct_A, A-only marker); B's id only named in text, no B secret. |
| holdout-v4-005 | contradicted | contradicted | - | False | No owner spec, but A is refused 403, so nothing to decide; anon 401. |
| holdout-v4-006 | supported | contradicted | fixed | False | GraphQL node = B's Secret with marker, viewer acct_A. After fix GraphQL FORBIDDEN error with node null. |
| holdout-v4-007 | contradicted | contradicted | - | False | anon and A get 200 GraphQL errors FORBIDDEN, data.node null: refusal disguised as 200. |
| holdout-v4-008 | not_applicable | not_applicable | - | False | Root has no Link header to the resource: out of scope although A would get B's XML. |
| holdout-v4-009 | supported | contradicted | - | True | A gets JSON:API record of B with marker; owner control fails (500) so no comparison is possible; withholding acceptable. |
| holdout-v4-010 | contradicted | contradicted | - | False | 200 body is error not_permitted; B's id appears only split into path parts. |
| holdout-v4-011 | contradicted | contradicted | - | True | A gets only its own items; B's control fails (403 insufficient_scope). No leak seen, but no owner baseline; withholding acceptable. |
| holdout-v4-012 | contradicted | contradicted | - | False | A's own activity log; its read of res_b_001 is recorded as denied. No B data. |
| holdout-v4-013 | contradicted | contradicted | - | False | 200 HTML page in Korean saying access denied (403). |
| holdout-v4-014 | contradicted | contradicted | - | False | anon and A get 200 JSON refusal in Spanish (code 403). |
| holdout-v4-015 | contradicted | contradicted | - | False | 200 status but application/problem+json Forbidden body; refusal. |
| holdout-v4-016 | supported | contradicted | - | True | A gets B's record (owners [acct_B], secret marker, shared false); owner control is 429, so withholding acceptable. |
| holdout-v4-017 | supported | supported | - | False | anon and A both get B's CSV export with marker; spec requires auth (B only). |
| holdout-v4-018 | supported | contradicted | not_fixed | False | A gets B's record; after the fix A still gets B's record (JSON:API layout), so not fixed. |
| holdout-v4-019 | contradicted | contradicted | - | False | A's own invoice with a foreign key to res_b_001; no B confidential data. |
| holdout-v4-020 | supported | contradicted | - | False | B's full record serialised inside a JSON string returned to A. |
| holdout-v4-021 | supported | contradicted | - | False | A gets JSON:API record of B with marker, meta requested_by acct_A. |
| holdout-v4-022 | contradicted | contradicted | - | False | Search echo of res_b_001 with zero results. |
| holdout-v4-023 | needs_spec | contradicted | - | False | A gets B's record but spec is 'unspecified' (no reader rule). |
| holdout-v4-024 | contradicted | contradicted | - | True | A gets a 200 soft rate limit (ok false); A never sees the resource, so undecidable; withhold appropriate. |
| holdout-v4-025 | contradicted | contradicted | - | False | anon and A get an SSO sign-in page (200); no record. |
| holdout-v4-026 | supported | contradicted | - | False | A gets B's record with marker at the start, long history after it (marker within first 4 KB). |
| holdout-v4-027 | contradicted | contradicted | - | True | A always gets 429 problem+json with Retry-After; undecidable; withhold appropriate. |
| holdout-v4-028 | supported | contradicted | fixed | False | A gets B's secret as HTML (owner, id, marker). After fix A gets a sign-in page with no data. |
| holdout-v4-029 | contradicted | contradicted | - | False | Search returns A's own note that mentions acct_B; no B data. |
| holdout-v4-030 | contradicted | contradicted | - | False | Long list of only A's items; nothing of B even past the 4 KB cut. |
| holdout-v4-031 | supported | contradicted | - | False | B's record is the 71st item, past the first 4 KB; A really receives it. A checker reading the full body can decide, so withholding is not ideal (hard case). |
| holdout-v4-032 | supported | contradicted | - | False | Truncated HTML still contains acct_B, res_b_001 and the marker before the cut. |
| holdout-v4-033 | contradicted | contradicted | - | False | Owner spec is public; anon and A get the profile as designed (PII is a spec question for the owner, not a finding here). |
| holdout-v4-034 | supported | contradicted | fixed | False | A gets B's PII profile with marker. After fix A gets 410. |
| holdout-v4-035 | needs_spec | contradicted | - | False | No owner spec written; A gets B's GraphQL secret: needs spec. |
| holdout-v4-036 | contradicted | supported | - | False | Anonymous gets B's HAL record with marker while A is 403; unauthenticated exposure, not cross-account. |
| holdout-v4-037 | supported | contradicted | not_fixed | False | A gets B's CSV; after the fix the answer is unchanged. |
| holdout-v4-038 | supported | contradicted | - | False | A gets B's HAL record with marker. |
| holdout-v4-039 | supported | contradicted | - | False | GraphQL node of B with marker, viewer acct_A. |
| holdout-v4-040 | contradicted | contradicted | - | False | A's own record (A-only marker) listing B as a collaborator; no B secret. |

Hardest: 031 (leak beyond the Worker's 4 KB), 011 (no owner baseline but A sees only own data), 009/016 (leak with a failing owner control), 033 (public spec yet PII), 036 (anonymous read while A is refused).
