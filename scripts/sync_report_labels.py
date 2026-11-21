"""Copy the diagnosis words the screen uses (web/src/lib/labels.ts) for the Markdown report.

The report (AssessmentService.report_markdown) must say exactly what the screen says, and
the backend does not ship the web sources. This script writes aegis/report_labels.json
from labels.ts; tests/test_report_labels.py fails when the two differ, so a word changed
on the screen cannot silently differ in the report.

    python3 -m scripts.sync_report_labels          # rewrite aegis/report_labels.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "web/src/lib/labels.ts"
OUT = ROOT / "aegis/report_labels.json"
# table -> which field holds the words (None: the value itself is the string)
TABLES = {"DIAG_CLAIM": None, "DIAG_STATE": "label", "DIAG_FIX_STATE": None, "DIAG_CHECK": None,
          "DIAG_REASON": None, "DIAG_RULE": None, "DIAG_REQUIREMENT": None, "DIAG_END": "text",
          "DIAG_REFUSAL": None, "DIAG_FIX_RESULT": "label", "DIAG_FINDING_STATUS": None,
          "DIAG_PLAN_STATE": None}


def _body(src: str, name: str) -> str:
    m = re.search(rf"export const {name}\b[^=]*= \{{(.*?)\n\}};", src, re.S)
    if m is None:
        raise ValueError(f"{name} is missing from labels.ts")
    return m.group(1)


def extract(src: str) -> dict:
    consts = dict(re.findall(r'^const ([A-Z_]+) = "([^"]*)";', src, re.M))
    out: dict[str, dict[str, str]] = {}
    for name, field in TABLES.items():
        table = {}
        body = _body(src, name)
        keys = re.findall(r"^  ([A-Za-z0-9_]+):", body, re.M)
        for key, value in re.findall(r"^  ([A-Za-z0-9_]+): (.+?),?$", body, re.M):
            if field is None:
                m = re.fullmatch(r'"([^"]*)"', value.strip().rstrip(","))
            else:
                m = re.search(rf'\b{field}: (?:"([^"]*)"|([A-Z_]+))', value)
                if m and m.group(1) is None:
                    m = re.fullmatch(r"(.*)", consts[m.group(2)])
            if m is None:
                raise ValueError(f"{name}.{key}: cannot read {value!r}")
            table[key] = m.group(1)
        if not table or list(table) != keys:
            # a value wrapped onto the next line (or any shape not read) is an error, never a gap
            raise ValueError(f"{name}: read {list(table)}, expected {keys}")
        out[name] = table
    attrs = _body(src, "DIAG_ATTR_VALUE")
    rep = re.search(r"reproduction: \{(.*?)\}", attrs, re.S)
    out["REPRODUCTION"] = dict(re.findall(r'([a-z_]+): "([^"]*)"', rep.group(1)))
    return out


def main() -> int:
    data = extract(LABELS.read_text(encoding="utf-8"))
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({sum(len(v) for v in data.values())} words)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
