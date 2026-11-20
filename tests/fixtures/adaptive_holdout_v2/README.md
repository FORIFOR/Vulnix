# adaptive_holdout_v2

60 local, anonymous selection conditions (12 each: `auth_session`, `idor_bola`, `cors`,
`cookie`, `info_tls`). Each condition asks one question: *after the initial read-only GET,
which allowed catalog checks (if any) are worth running next?*

| File | Who may read it |
| --- | --- |
| `cases.json` | strategies and models: measured observation (enums/booleans only), allowed catalog ids, evidence fields |
| `owner_specs.json` | strategies and models: the owner's structured requirements, consent flags and free-text note |
| `truth.json` | the scorer only: expected catalog ids, `critical`, `deciding_signal`, rationale |
| `manifest.json` | SHA-256 of the three files above and of `scripts/adaptive_baselines.py` |

Rules for the data:

- `allowed_catalog_ids` is derived from **structured authority only** (`status_probe_consent`,
  `lab_l2_allowed`). The owner's free-text note can change whether a check is *needed*,
  never whether it is *permitted*.
- Catalog ids are real `aegis.artex_bridge.CATALOG_BY_ID` ids.
- `requires_additional_check` lives in `truth.json` (in the case file it would leak the label).
- Labelling rubric: see `docs/ADAPTIVE_HOLDOUT_V2.md` §2.
