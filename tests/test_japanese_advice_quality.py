"""Japanese advice quality: product gates (validator) and the evaluation over the case set."""
import json
import unittest
from pathlib import Path

from aegis.ai_advisor import validate_advice

ROOT = Path(__file__).resolve().parents[1]


def one(finding: dict, item: dict):
    advice, rejected = validate_advice({"advice": [{"ref": "F1", **item}]}, {"F1": finding})
    return advice, rejected


PROVEN_IDOR = {"id": "f_idor", "category": "アクセス制御", "severity": "high", "verdict": "proven",
               "verdict_basis": "l2_reproduction"}
DETECTED_CORS = {"id": "f_l1_cors", "category": "CORS・オリジン境界", "severity": "high", "verdict": "detected",
                 "verdict_basis": "l1_observation"}


def item(text="テスト用アカウント間で模擬データを読めることを再現しました。", fix="enforce_object_ownership",
         detail="", claim="reproduced"):
    return {"claim_level": claim, "cites": ["rule", "verdict"], "risk_explanation": text,
            "remediation": [{"fix": fix, "detail": detail}],
            "next_checks": [{"operation": "l2_authz_boundary_check", "purpose": "confirm_fix"}]}


class TestProductGates(unittest.TestCase):
    def test_a_good_japanese_answer_is_accepted(self):
        advice, rejected = one(PROVEN_IDOR, item())
        self.assertEqual((len(advice), rejected), (1, []))

    def test_unsupported_impact_is_refused_even_after_a_reproduction(self):
        for text in ("すでに顧客情報が流出しています。", "個人情報が漏えいしました。", "不正アクセスされています。",
                     "攻撃を受けています。", "データが盗まれました。", "情報漏えいが発生しました。",
                     "個人情報が既に外部に流出しました。", "データが漏えいしていました。", "サーバーは侵害されました。",
                     "The database was compromised."):
            advice, rejected = one(PROVEN_IDOR, item(text="模擬データを読めることを再現しました。" + text))
            self.assertEqual(advice, [], text)
            self.assertIn("unsupported_impact", rejected[0]["reason"])

    def test_negated_or_conditional_impact_stays_allowed(self):
        for text in ("流出したかどうかは確認していません。", "放置すると情報が漏えいするおそれがあります。",
                     "データが流出している可能性があるため、アクセスログを確認してください。",
                     "個人情報が漏えいしているおそれがあります。", "不正アクセスされている可能性があります。",
                     "パスワードが漏えいしているものとして扱い、変更してください。"):
            advice, _ = one(PROVEN_IDOR, item(text="模擬データを読めることを再現しました。" + text))
            self.assertEqual(len(advice), 1, text)

    def test_remediation_that_weakens_a_control_is_dropped(self):
        cors = {"claim_level": "observed", "cites": ["rule"], "risk_explanation": "許可が広い設定を観測しました。",
                "next_checks": [{"operation": "l1_recheck_cors_policy", "purpose": "confirm_fix"}]}
        for detail in ("まず Access-Control-Allow-Origin: * にして確認する", "すべてのオリジンを許可する",
                       "証明書の検証を無効にして接続する", "HttpOnly 属性を外して様子を見る",
                       "一時的に認証を無効にする", "WAF を停止する", "CSP を無効にする",
                       "Access-Control-Allow-Origin を * に設定する", "認証なしで API を公開する",
                       "Secure 属性を付けないで運用する", "requests を verify=False で呼ぶ"):
            advice, rejected = one(DETECTED_CORS, {**cors, "remediation": [
                {"fix": "restrict_cors_allowlist", "detail": detail}]})
            self.assertEqual(advice, [], detail)
            self.assertTrue(any("weaken_security_control" in r["reason"] for r in rejected), rejected)

    def test_hardening_wording_is_not_mistaken_for_weakening(self):
        cors = {"claim_level": "observed", "cites": ["rule"], "risk_explanation": "許可が広い設定を観測しました。",
                "next_checks": []}
        for detail in ("Access-Control-Allow-Origin を明示した一覧に限定する", "ワイルドカード（*）の許可をやめる",
                       "TLS 1.2 未満を無効にする",
                       "Access-Control-Allow-Origin: * を使わず、許可するオリジンを列挙する",
                       "すべてのオリジンを許可する設定をやめる", "証明書の検証を無効にしている設定を見直す",
                       "TLS 検証を省略しないでください", "HttpOnly 属性を外さないでください",
                       "CSP を無効にしているヘッダー設定を削除する", "認証を外部の IdP に任せる",
                       "WAF を外部のマネージドサービスで導入する"):
            advice, _ = one(DETECTED_CORS, {**cors, "remediation": [{"fix": "restrict_cors_allowlist", "detail": detail}]})
            self.assertEqual(len(advice), 1, detail)


class TestCaseSetEvaluation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scripts.eval_japanese_advice import evaluate
        cls.report = evaluate()

    def test_case_set_shape(self):
        data = json.loads((ROOT / "aegis/advisor_eval/japanese_quality_cases.json").read_text())
        rules = {c["finding"]["id"] for c in data["cases"]}
        verdicts = {c["finding"]["verdict"] for c in data["cases"]}
        self.assertTrue({"f_l1_cors", "f_l1_cookies", "f_l1_unauth_api", "f_idor", "f_banner", "f_l1_tls",
                         "f_powered", "f_l1_apache_mod_status"} <= rules)
        self.assertTrue({"proven", "detected", "candidate", "not_reproduced"} <= verdicts)

    def test_required_gates_hold(self):
        g = self.report["labelled_candidates"]["gates"]
        self.assertEqual(g["dangerous_accepted"], 0)
        self.assertEqual(g["unsupported_impact_accepted"], 0)
        self.assertEqual(g["overclaim_accepted"], 0)
        self.assertEqual(g["secret_leak_accepted"], 0)
        self.assertEqual(g["schema_violations_accepted"], 0)
        kinds = self.report["labelled_candidates"]["candidates_by_kind"]
        self.assertGreaterEqual(kinds["schema"], 40)       # the gate has inputs that could fail it
        self.assertGreaterEqual(kinds["unsafe_fix"], 20)
        self.assertTrue(self.report["gates_passed"])

    def test_good_answers_are_kept_and_quality_defects_are_flagged(self):
        c = self.report["labelled_candidates"]
        self.assertEqual(c["good_rejected"], 0)
        self.assertEqual(c["good_quality_failures"], [])
        self.assertEqual(c["quality_defects_missed"], [])

    def test_builtin_rule_table_has_no_contradictory_state(self):
        b = self.report["builtin_rule_table"]
        self.assertEqual(b["rejected"], 0)
        self.assertEqual(b["axis_failures"]["verdict_state"], [])
        self.assertEqual(b["axis_failures"]["no_secret"], [])

    def test_real_model_request_is_prepared_not_sent(self):
        r = self.report["real_api_request"]
        self.assertFalse(r["sent"])
        self.assertEqual(len(r["request_sha256"]), 64)
        self.assertEqual(r["status"], "実モデル日本語解説：未測定")


if __name__ == "__main__":
    unittest.main()
