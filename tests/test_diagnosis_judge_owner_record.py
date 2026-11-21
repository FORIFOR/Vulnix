"""The owner-record comparison rules (docs/evaluation/FAILURE_ANALYSIS.md, 案1 and 案3;
docs/evaluation/JUDGE_OWNER_RECORD.md).

owner_record_absent              other_account_read x l2_idor
owner_record_absent_without_auth unauthenticated_exposure x l1_http_probe

Both may only ever contradict a hypothesis. Every near miss below must stay unsettled
(and never become "supported"), and every verdict the judge gave before keeps its rule.
"""
import inspect
import itertools
import json
import re
import unittest

from aegis import diagnosis_judge
from aegis.diagnosis_judge import check_attrs, judge
from aegis.diagnosis_state import DiagnosisState

H = "d" * 64
MARKER = "VULNIX_LAB_IDOR_PROVEN"
NEW_RULES = ("owner_record_absent", "owner_record_absent_without_auth")
OWNER = {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B",
         "resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER}
CROSS = {**OWNER, "established": True, "caller_account": "acct_A"}

HTML_LOGIN = "<html><body><form>Sign in</form></body></html>"
HTML_LOGIN_PW = ('<!DOCTYPE html><html><head><title>Welcome</title></head><body><form method="post">'
                 '<input name="u"><input type="password" name="p"></form></body></html>')
HTML_REFUSAL = "<html><head><title>403 Forbidden</title></head><body><h1>Access denied</h1></body></html>"
HTML_LANDING = '<html><body><h1>Welcome</h1><a href="/login">Sign in</a></body></html>'
HTML_B_PAGE = "<html><body><h1>Account settings</h1><p>Notes: travel plans</p></body></html>"
HTML_LOGIN_NAMED = '<html><body><form><p>Welcome back, acct_B</p><input type="password"></form></body></html>'

# A's answers that do not carry B's record and that the rule may close (with a positive owner control)
ABSENT = {
    "html_login_password": HTML_LOGIN_PW,
    "html_refusal": HTML_REFUSAL,
    "json_soft_error": {"error": "forbidden", "ok": False},
    "json_refusal_status": {"status": "denied", "reason": "not permitted"},
    "json_errors": {"errors": [{"code": "FORBIDDEN"}]},
}
# JSON data (not a refusal) without B's identifiers: it may still be B's data in another shape,
# so it is never closed as "not vulnerable" (holdout-v2-006). These stay inconclusive.
JSON_DATA = {
    "json_empty_list": [],
    "json_public_listing": {"directory": "public profile listing", "entries": 3},
    "b_data_without_identifiers": {"notes": "travel plans", "balance": 1200},
}
# Near misses: none of them may be closed by the new rule, and none may become supported
NEAR_MISS = {
    "marker_only": {"message": f"example payload: {MARKER}"},
    "b_resource_id_only": {"id": "res_b_001", "title": "quarterly notes"},
    "b_record_nested": {"caller_account": "acct_A", "data": {"resource_id": "res_b_001",
                                                             "confidential_marker": MARKER}},
    "b_named_without_identifiers": {"owner": "acct_B", "balance_note": "lab-only data"},
    "html_not_a_login_page": HTML_LANDING,
    "html_search_form_and_login_link": ('<html><body><a href="/login">Log in</a><form action="/search">'
                                        '<input name="q"></form><p>Notes: travel plans</p></body></html>'),
    "html_b_page": HTML_B_PAGE,
    "html_login_naming_b": HTML_LOGIN_NAMED,
    "text_plain": "Forbidden",
    "empty_body": "",
    "identifier_case_changed": {"note": "RES_B_001"},
    "identifier_html_entity": "<html><body><form>Sign in res&#95;b&#95;001</form></body></html>",
    "identifier_url_encoded": {"next": "/r/res%5Fb%5F001"},
    "identifier_json_escaped": '{"id": "res\\u005fb\\u005f001"}',
    "truncated_excerpt": "<html><body><form>Sign in" + "x" * 5000,
}


def idor_result(response, *, status=200, control=True, control_response=None, truncated=False):
    """The shape of aegis/workers/reproduction_probe.py run_lab_check for one A request."""
    owner = OWNER if control_response is None else control_response
    if not control:
        return {"check": "idor", "request_path": "/api/accounts/B/secret",
                "request_headers": {"X-Test-Account": "acct_A"}, "status": None, "established": False,
                "verdict": "unverified", "control_status": 500, "control_verified": False,
                "control_response": None}
    proven = status == 200 and response == CROSS
    if isinstance(response, str):
        response = response[:4096]           # the Worker keeps a 4096-character excerpt
    return {"check": "idor", "request_path": "/api/accounts/B/secret",
            "request_headers": {"X-Test-Account": "acct_A"}, "status": status, "established": proven,
            "verdict": "proven" if proven else ("not_reproduced" if status == 403 else "unverified"),
            "deny_statuses": [403], "response": response, "control_status": 200,
            "control_verified": True, "control_response": owner, "response_truncated": truncated}


def probe_result(body, *, status=200, ctype=None, content_length=None):
    """The shape of aegis/workers/http_probe.py for one GET without an account."""
    if body is None:
        return {"status": status}
    text = body if isinstance(body, str) else json.dumps(body)
    raw = text.encode()
    headers = {"Content-Type": ctype or ("text/html" if text.lstrip().startswith("<") else "application/json"),
               "Content-Length": str(len(raw) if content_length is None else content_length)}
    return {"status": status, "headers": headers, "body_prefix": raw[:4096].decode("utf-8", "replace")}


class JudgeCase(unittest.TestCase):
    def verdict(self, claim, catalog, result, spec="authentication_required"):
        s = DiagnosisState()
        s.observe(kind="account_resource_link", target_ref="T2", attrs={"present": True}, source="l1")
        if spec is not None:
            s.observe(kind="owner_spec", target_ref="T2", attrs={"requirement": spec}, source="owner_spec")
        h = s.propose(claim=claim, target_ref="T2", basis=["E1"])
        e = s.observe(kind="check_result", target_ref="T2", attrs=check_attrs(catalog, result),
                      source="check", audit_hash=H, step_id="S1", catalog_id=catalog)
        v = judge(s, h, catalog, e)
        return v.to, v.rule

    def idor(self, response, **kw):
        spec = kw.pop("spec", "authentication_required")
        return self.verdict("other_account_read", "l2_idor", idor_result(response, **kw), spec)

    def l1(self, body, **kw):
        spec = kw.pop("spec", "authentication_required")
        return self.verdict("unauthenticated_exposure", "l1_http_probe", probe_result(body, **kw), spec)


class TestOwnerRecordAbsent(JudgeCase):
    """案1: A's 200 answer carries none of B's control identifiers, nor B's name."""

    def test_answers_without_b_record_are_contradicted(self):
        for name, body in ABSENT.items():
            with self.subTest(name):
                self.assertEqual(self.idor(body), ("contradicted", "owner_record_absent"))

    def test_near_misses_stay_unsettled(self):
        for name, body in NEAR_MISS.items():
            with self.subTest(name):
                self.assertEqual(self.idor(body), ("inconclusive", "unrecognised_answer"))

    def test_identifiers_come_from_the_owner_control_in_the_worker_result(self):
        control = {**OWNER, "resource_id": "zz_custom_77", "confidential_marker": "ZZ_MARK"}
        self.assertEqual(self.idor({"note": "zz_custom_77"}, control_response=control),
                         ("inconclusive", "unrecognised_answer"))
        self.assertEqual(self.idor({"note": "zz_mark here"}, control_response=control),
                         ("inconclusive", "unrecognised_answer"))
        self.assertEqual(self.idor({"error": "forbidden"}, control_response=control),
                         ("contradicted", "owner_record_absent"))
        attrs = check_attrs("l2_idor", idor_result({"note": "zz_custom_77"}, control_response=control))
        self.assertIs(attrs["owner_identifiers_present"], True)

    def test_without_owner_identifiers_nothing_is_compared(self):
        for control in ({**OWNER, "resource_id": "", "confidential_marker": None},
                        {"Check": "idor_cross_account_access"}, "not an object"):
            with self.subTest(control=control):
                self.assertEqual(self.idor({"error": "forbidden"}, control_response=control),
                                 ("inconclusive", "unrecognised_answer"))
                attrs = check_attrs("l2_idor", idor_result({"error": "forbidden"}, control_response=control))
                self.assertNotIn("owner_identifiers_present", attrs)

    def test_only_a_200_with_a_positive_control_is_compared(self):
        self.assertEqual(self.idor({"error": "forbidden"}, control=False), ("inconclusive", "control_failed"))
        for status in (201, 204, 302, 429, 500):
            with self.subTest(status=status):
                self.assertEqual(self.idor({"error": "forbidden"}, status=status),
                                 ("inconclusive", "unrecognised_answer"))

    def test_the_requesters_own_resource_keeps_its_rule(self):
        own = {"caller_account": "acct_A", "resource_owner": "acct_A", "resource_id": "res_a_001"}
        self.assertEqual(self.idor(own), ("contradicted", "own_resource_only"))
        own_with_marker = {"caller_account": "acct_A", "resource_owner": "acct_A", "confidential_marker": MARKER}
        self.assertEqual(self.idor(own_with_marker), ("contradicted", "own_resource_only"))

    def test_the_owner_spec_public_still_decides_first(self):
        self.assertEqual(self.idor(HTML_LOGIN, spec="public"), ("contradicted", "intended_public"))

    def test_json_data_without_identifiers_is_never_closed(self):
        """The miss FAILURE_ANALYSIS 案1 warned about (holdout-v2-006): B's data stripped of every
        identifier and of B's name cannot be told from other JSON, so the rule does not decide it."""
        for name, body in JSON_DATA.items():
            with self.subTest(name):
                verdict = self.idor(body)
                self.assertNotIn(verdict[0], ("contradicted", "supported"), verdict)

    def test_attributes_are_short_words(self):
        attrs = check_attrs("l2_idor", idor_result(HTML_LOGIN_PW))
        self.assertEqual({k: attrs[k] for k in ("owner_identifiers_present", "owner_account_present", "body_kind")},
                         {"owner_identifiers_present": False, "owner_account_present": False,
                          "body_kind": "html_login"})
        s = DiagnosisState()
        s.observe(kind="check_result", target_ref="T2", attrs=attrs, source="check", audit_hash=H,
                  step_id="S1", catalog_id="l2_idor")
        seen = s.planner_view()["observations"][0]["attrs"]
        for k in ("owner_identifiers_present", "owner_account_present", "body_kind"):
            self.assertEqual(seen[k], attrs[k])
        self.assertNotIn("res_b_001", json.dumps(seen))
        self.assertNotIn("acct_", json.dumps(seen))


class TestEnvelopesAndPagesThatCarryData(JudgeCase):
    """The independent review's cases: each carries (or may carry) B's data in a refusal-
    or sign-in-like shape. None may be closed as "not vulnerable"."""
    B_PROFILE_PW = ('<html><body><h1>Profile</h1><p>Email: bob@example.test, plan: premium, notes: travel</p>'
                    '<form><input type="password" name="new"> change password</form></body></html>')
    LAST_LOGIN = '<html><body><form><p>Last login: yesterday</p></form><p>Balance 1200</p></body></html>'
    UNAUTH_LIST = ('<html><head><title>Unauthorized users list</title></head><body>'
                   + "<p>bob@example.test, alice@example.test, carol@example.test</p>" * 20 + '</body></html>')
    JS_ESCAPED = ('<html><body><form><input type="password"></form>'
                  '<script>var r="res\\u005fb\\u005f001"</script></body></html>')
    CASES = {
        "json_envelope_ok_true": {"ok": True, "detail": {"email": "bob@x", "permission": "admin"}},
        "json_envelope_success_detail": {"status": "success", "detail": {"name": "bob", "permissions": ["a"]}},
        "json_error_with_long_detail": {"error": "denied", "detail": "eyJ" + "A" * 300},
        "json_errors_with_data": {"errors": [{"code": "x", "record": {"notes": "travel"}}]},
        "html_profile_with_password_form": B_PROFILE_PW,
        "html_last_login_form": LAST_LOGIN,
        "html_unauthorized_list_with_data": UNAUTH_LIST,
        "html_login_without_password": HTML_LOGIN,
    }

    def test_none_is_closed(self):
        for name, body in self.CASES.items():
            with self.subTest(name):
                verdict = self.idor(body)
                self.assertNotEqual(verdict[0], "contradicted", (name, verdict))
                self.assertNotEqual(verdict[0], "supported", (name, verdict))

    def test_an_identifier_hidden_as_a_javascript_escape_counts_as_present(self):
        verdict = self.idor(self.JS_ESCAPED)
        self.assertNotEqual(verdict[0], "contradicted", verdict)

    def test_a_body_the_worker_cut_short_is_never_read_as_absent(self):
        res = idor_result({"error": "forbidden"}, truncated=True)
        from aegis.diagnosis_judge import check_attrs
        self.assertEqual(check_attrs("l2_idor", res).get("body_kind"), "partial")
        old = {k: v for k, v in idor_result({"error": "forbidden"}).items() if k != "response_truncated"}
        self.assertEqual(check_attrs("l2_idor", old).get("body_kind"), "partial")   # no flag: not whole


class TestOwnerRecordAbsentWithoutAuth(JudgeCase):
    """案3: the L1 GET without an account, compared with the lab owner's identifiers."""

    def test_answers_without_b_record_are_contradicted(self):
        for name, body in ABSENT.items():
            with self.subTest(name):
                self.assertEqual(self.l1(body), ("contradicted", "owner_record_absent_without_auth"))

    def test_near_misses_stay_unsettled(self):
        for name, body in NEAR_MISS.items():
            with self.subTest(name):
                self.assertEqual(self.l1(body), ("inconclusive", "answered_without_auth_unverified"))
        self.assertEqual(self.l1({"owner": "acct_B", "balance_note": "lab-only data"}),
                         ("inconclusive", "answered_without_auth_unverified"))

    def test_b_record_without_auth_is_not_supported_by_this_change(self):
        # identifiers present -> unchanged (inconclusive); the new rules never support
        self.assertEqual(self.l1(OWNER), ("inconclusive", "answered_without_auth_unverified"))

    def test_a_body_not_read_completely_is_not_compared(self):
        self.assertEqual(self.l1({"error": "forbidden"}, content_length=9000),
                         ("inconclusive", "answered_without_auth_unverified"))
        big = {"padding": "x" * 5000, "items": []}
        self.assertEqual(self.l1(big), ("inconclusive", "answered_without_auth_unverified"))

    def test_a_status_alone_is_not_compared(self):
        self.assertEqual(self.l1(None), ("inconclusive", "answered_without_auth_unverified"))

    def test_other_statuses_keep_their_rules(self):
        for status in (401, 403, 404):
            self.assertEqual(self.l1({"error": "x"}, status=status), ("contradicted", "denied_without_auth"))
        self.assertEqual(self.l1({"error": "x"}, status=500), ("inconclusive", "unrecognised_answer"))
        self.assertEqual(self.l1(HTML_LOGIN, spec="public"), ("contradicted", "intended_public"))


class TestTheNewRulesNeverSupport(JudgeCase):
    def test_source_new_rules_are_only_contradictions(self):
        src = re.sub(r"\s+", " ", inspect.getsource(diagnosis_judge))
        for rule in NEW_RULES:
            # every place the module names the rule is one contradiction
            self.assertEqual(src.count(f'"{rule}"'), 1, rule)
            calls = re.findall(rf'_verdict\(hypothesis_id, "(\w+)", [^)]*?"{rule}"\)', src)
            self.assertEqual(calls, ["contradicted"], rule)

    def test_every_combination_never_supports_by_a_new_rule(self):
        bodies = list(ABSENT.values()) + list(NEAR_MISS.values()) + [OWNER, CROSS, None]
        for body, status, spec, control in itertools.product(
                bodies, (200, 403, 500), ("authentication_required", "unspecified", None), (True, False)):
            if body is None:
                continue
            to, rule = self.idor(body, status=status, control=control, spec=spec)
            if rule in NEW_RULES:
                self.assertEqual(to, "contradicted")
            self.assertFalse(to == "supported" and rule != "cross_account_read", (body, rule))
        for body, status, spec in itertools.product(bodies, (200, 401, 500),
                                                    ("authentication_required", "unspecified", None)):
            to, rule = self.l1(body, status=status, spec=spec)
            self.assertNotEqual(to, "supported")
            if rule in NEW_RULES:
                self.assertEqual(to, "contradicted")


class TestExistingVerdictsUnchanged(JudgeCase):
    def test_other_account_read(self):
        self.assertEqual(self.idor(CROSS), ("supported", "cross_account_read"))
        self.assertEqual(self.idor(CROSS, spec=None), ("needs_spec", "spec_missing"))
        self.assertEqual(self.idor(CROSS, spec="unspecified"), ("needs_spec", "spec_missing"))
        self.assertEqual(self.idor(CROSS, spec="public"), ("contradicted", "intended_public"))
        self.assertEqual(self.idor(CROSS, control=False), ("inconclusive", "control_failed"))
        for status in (401, 403, 404):
            self.assertEqual(self.idor({"error": "forbidden"}, status=status), ("contradicted", "denied"))
        self.assertEqual(self.idor({"caller_account": "acct_A", "resource_owner": "acct_A"}),
                         ("contradicted", "own_resource_only"))
        # B's record served to A but announced as B's own answer: still unrecognised (案2 is not implemented)
        self.assertEqual(self.idor(OWNER), ("inconclusive", "unrecognised_answer"))

    def test_unauthenticated_exposure(self):
        for status in (401, 403, 404):
            self.assertEqual(self.l1(None, status=status), ("contradicted", "denied_without_auth"))
        self.assertEqual(self.l1(None), ("inconclusive", "answered_without_auth_unverified"))
        self.assertEqual(self.l1(None, spec="public"), ("contradicted", "intended_public"))

    def test_check_not_relevant(self):
        self.assertEqual(self.verdict("unauthenticated_exposure", "l2_idor", idor_result(HTML_LOGIN)),
                         ("inconclusive", "check_not_relevant"))


if __name__ == "__main__":
    unittest.main()
