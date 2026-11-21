"""The Markdown report: what was checked and why, the rule behind each verdict, the
before/after comparison, what could not be decided, and the line between audited facts
and AI suggestions (docs/PRODUCT_COMPLETION.md D)."""
import re
import unittest
from unittest.mock import patch

from tests.test_diagnosis_actions import ActionsBase, APPROVER, OWNER, REQUESTER


class TestReportOfTheLoop(ActionsBase):
    def report(self):
        return self.svc.report_markdown()

    def test_a_lab_without_a_loop_says_so_and_lists_unmeasured_candidates(self):
        r = self.report()
        self.assertIn("## この報告書の読み方", r)
        self.assertIn("AI（モデル）が書いた説明や提案は、この報告書に含めていません", r)
        self.assertIn("## 4. 診断ループ", r)
        self.assertIn("まだ診断ループを実行していません", r)
        self.assertIn("## 5. 判断できなかった項目", r)
        self.assertIn("「安全」という意味ではありません", r)
        self.assertIn("## 6. 監査チェーン検証", r)

    def test_the_whole_loop_with_the_fix_check_is_reported_from_audited_records(self):
        self.run_to_finding()
        self.lab.mode = "denied_403"
        self.assertEqual(self.op("fix-check", REQUESTER)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        item = self.wait_job("waiting_approval")["waiting_item_id"]
        self.assertEqual(self.op("approve", APPROVER, {"item_id": item})[0], 200)
        self.wait_job("finished")
        r = self.report()
        view = self.svc.diagnosis_view()
        # what was checked, why, who approved, by which rule, with the audit hashes
        self.assertIn("### 何を調べたか・なぜ調べたか", r)
        self.assertIn("別アカウントでの読み取り検査（L2）", r)
        self.assertIn("なぜ: H2 を確かめるため", r)
        self.assertIn("L2・承認者 approver-human", r)
        self.assertIn("判定【固定の規則による判定】: 支持（成立） — 所有者が「認証必須」とした資源を、別のアカウントが読めた", r)
        for s in view["steps"]:
            self.assertIn(s["result_audit_hash"][:16], r)
            self.assertIn(s["judged_audit_hash"][:16], r)
        self.assertIn("世代 2・S1", r)
        # the before/after comparison with the finding
        self.assertIn("### 修正の前後", r)
        self.assertIn("**改善を確認**", r)
        self.assertIn("再現 成立", r)
        self.assertIn("所見 `f_idor` の現在の判定: 再現せず", r)
        self.assertIn("H3 別のアカウントが、B の資源を読めるか（対象 T2・世代 2）: **改善を確認**", r)
        # facts and fixed procedures are labelled; no undefined word slipped through
        self.assertRegex(r, r"  - 【監査済みの事実】 `ev_[0-9a-f]{12}`")
        self.assertNotIn("【監査ログで確認できない記録】 `ev_", r)
        self.assertIn("- **修正方法**【固定の修正手順】:", r)
        self.assertNotIn("未定義の値", r)

    def test_what_could_not_be_decided_is_listed_with_why(self):
        self.assertEqual(self.op("start", REQUESTER)[0], 202)
        self.op("owner-spec", OWNER, {"target_ref": "T2", "requirement": "authentication_required"})
        self.wait_job("waiting_approval")
        self.svc.emergency_stop("qa")                       # the L2 step never runs
        self.wait_job("finished", "failed")
        r = self.report()
        section = r.split("## 5. 判断できなかった項目", 1)[1].split("## 6.", 1)[0]
        self.assertIn("仮説 H2 別のアカウントが、B の資源を読めるか: 確認待ち — まだ検査していません", section)
        self.assertIn("診断ループの終了理由", section)
        self.assertNotIn("\n- ありません。", section)

    def test_an_unverified_record_is_not_reported(self):
        self.run_to_finding()
        with patch.object(type(self.svc), "diagnosis_view",
                          return_value={"status": "unverified", "reason": "audit_chain_invalid"}):
            r = self.report()
        self.assertIn("記録を確かめられないため、診断ループの結果は載せていません（理由：監査ログのハッシュの鎖が壊れています）", r)
        self.assertNotIn("### 何を調べたか", r)
        self.assertNotIn("### 修正の前後", r)

    def test_evidence_is_called_audited_only_when_the_chain_verifies(self):
        self.run_to_finding()
        with patch.object(self.svc.audit, "verified_entries", return_value=([], False)):
            r = self.report()
        self.assertNotRegex(r, r"【監査済みの事実】 `ev_")
        self.assertRegex(r, r"【監査ログで確認できない記録】 `ev_[0-9a-f]{12}`")

    def test_untrusted_text_cannot_become_markup(self):
        from aegis.report_diagnosis import md_text
        out = md_text("Apache [click](https://evil.example) <img src=x>`code`\n# heading")
        self.assertNotIn("\n", out)
        # every markup character is escaped: none is left unescaped
        self.assertIsNone(re.search(r"(?<!\\)[\[\]<>`#]", out), out)
        self.assertIn("\\[click\\]", out)

    def test_a_real_service_has_no_loop_section(self):
        with patch.object(type(self.svc), "diagnosis_view", return_value=None):
            r = self.report()
        self.assertNotIn("## 4. 診断ループ", r)
        self.assertIn("## 5. 判断できなかった項目", r)

    def test_no_model_text_reaches_the_report(self):
        """Advisor answers and planner advisories stay on the screen (marked as AI)."""
        self.run_to_finding()
        r = self.report()
        advisories = [e for e in self.svc.audit.entries() if e["event"] in ("advisor.answer", "artex.advisory")]
        for e in advisories:
            text = str(e["fields"].get("text") or "")
            if text:
                self.assertNotIn(text, r)
        self.assertIsNone(re.search(r"intent|advisory", r, re.I))


if __name__ == "__main__":
    unittest.main()
