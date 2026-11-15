"""Compare the same safe finding with the full and rule-scoped advisor prompt.

No model or target request is made. Bytes are not billed token counts.
"""
from __future__ import annotations

import json

from aegis.ai_advisor import AbliterationAdvisor, SYSTEM_ADVISOR_PROMPT


def main() -> None:
    finding = {
        "id": "f_l1_apache_mod_status",
        "category": "情報公開設定",
        "severity": "medium",
        "verdict": "detected",
        "verdict_basis": "l1_observation",
    }
    advisor = AbliterationAdvisor("http://127.0.0.1:9/v1/chat/completions")
    after, _ = advisor.build_request([finding])
    before_payload = json.loads(after)
    before_payload["messages"][0]["content"] = SYSTEM_ADVISOR_PROMPT
    before = json.dumps(before_payload, ensure_ascii=False).encode("utf-8")
    print(json.dumps({
        "fixture": finding["id"],
        "before_request_bytes": len(before),
        "after_request_bytes": len(after),
        "bytes_saved": len(before) - len(after),
        "relative_reduction_pct": round((len(before) - len(after)) * 100 / len(before), 1),
        "network_calls": 0,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
