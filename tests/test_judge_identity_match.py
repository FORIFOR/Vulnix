"""案2: "another account read B's record" from what Vulnix itself measured
(docs/evaluation/JUDGE_IDENTITY_MATCH.md, docs/evaluation/FAILURE_ANALYSIS.md).

aegis.evidence.owner_record_read_by_other_account decides it from the Worker's own result:
the request was sent as acct_A (fixed by Vulnix), B's control was established in the same
run, A's 200 answer was read whole and carries BOTH the control's resource id AND its
confidential marker (after the absence rule's normalisations), and the answer is not
another resource or A's own. Never from the answer's caller_account / Check / established.

The judge uses it for "supported" (rule cross_account_read). A finding becomes 実証成功 only
through reproduction_verdict, which requires the Worker's verdict, the fixed answer shape AND
this match: a finding is never proven on a weaker test than the judge's.
"""
import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from aegis.diagnosis_judge import check_attrs, judge
from aegis.diagnosis_state import DiagnosisState
from aegis.evidence import owner_record_read_by_other_account, reproduction_verdict
from aegis.workers.reproduction_probe import run_lab_check

H = "e" * 64
MARKER = "VULNIX_LAB_IDOR_PROVEN"
OWNER = {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B",
         "resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER}
CROSS = {**OWNER, "established": True, "caller_account": "acct_A"}

POSITIVE = {
    "enveloped_json": {"data": {"resource_owner": "acct_B", "resource_id": "res_b_001",
                                "confidential_marker": MARKER}, "meta": {"requested_by": "acct_A"}},
    "list_of_results": {"items": [{"id": "res_a_001", "owner": "acct_A", "title": "mine"},
                                  {"id": "res_b_001", "owner": "acct_B", "secret": MARKER}], "total": 2},
    "camel_case_keys": {"resourceId": "res_b_001", "resourceOwner": "acct_B", "confidentialMarker": MARKER,
                        "viewer": "acct_A"},
    "json_escaped_raw": '{"id": "res\\u005fb\\u005f001", "secret": "VULNIX\\u005fLAB\\u005fIDOR\\u005fPROVEN"}',
    "json_escaped_parsed": json.loads('{"id": "res\\u005fb\\u005f001", "secret": "VULNIX\\u005fLAB\\u005fIDOR'
                                      '\\u005fPROVEN"}'),
    "html_table": ("<html><head><title>Record</title></head><body><table>"
                   "<tr><th>ID</th><td>res_b_001</td></tr><tr><th>Secret</th><td>VULNIX_LAB_IDOR_PROVEN</td></tr>"
                   "</table></body></html>"),
    "html_entities_and_case": "<html><body><p>RES&#95;B&#95;001</p><p>vulnix&#x5f;lab_idor_proven</p></body></html>",
    "owner_self_report_says_b": OWNER,          # holdout-030: the server ignores who asked
    "self_report_cross": CROSS,
}

NEAR_MISS = {
    "marker_only_documentation": {"docs": f"When the lab is vulnerable the answer carries {MARKER}."},
    "marker_only_html_documentation": f"<html><body><h1>Help</h1><p>Example marker: {MARKER}</p></body></html>",
    "resource_id_only": {"resource_id": "res_b_001", "title": "quarterly notes"},
    "redacted_marker": {"resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": "[REDACTED]"},
    "a_own_resource_quoting_b": {"resource_owner": "acct_A", "resource_id": "res_a_001",
                                 "note": "copied from res_b_001", "confidential_marker": MARKER},
    "a_own_resource_without_id_field": {"owner": "acct_A", "linked": "res_b_001", "secret": MARKER},
    "a_own_record_envelope": {"resource_owner": "acct_A", "data": {"ref": "res_b_001", "marker": MARKER}},
    "a_own_html_page_quoting_b": f"<html><body><p>acct_A's page. See res_b_001 and {MARKER}.</p></body></html>",
    "different_resource_id_with_marker": {"resource_id": "res_c_001", "confidential_marker": MARKER,
                                          "see_also": "res_b_001"},
    "longer_id_with_marker": {"resource_id": "res_b_0012", "confidential_marker": MARKER},
    "longer_marker_with_id": {"resource_id": "res_b_001", "confidential_marker": MARKER + "_EXAMPLE"},
    "prefixed_id_with_marker": {"resource_id": "xres_b_001", "confidential_marker": MARKER},
    "prefixed_marker_with_id": {"resource_id": "res_b_001", "confidential_marker": "NOT_" + MARKER},
    "owner_field_names_someone_else": {"resource_owner": "acct_C", "resource_id": "res_b_001",
                                       "confidential_marker": MARKER},
    "identifiers_split_across_fields": {"id_prefix": "res_b", "id_suffix": "_001",
                                        "marker_parts": ["VULNIX_LAB", "IDOR_PROVEN"]},
    "identifiers_in_different_items": [{"id": "res_b_001"}, {"note": MARKER}],
    "base64_record": {"blob": base64.b64encode(json.dumps(OWNER).encode()).decode()},
    "numeric_id_field": {"id": 1, "ref": "res_b_001", "secret": MARKER},
}


def lab_result(response, *, status=200, truncated=False, control=True, headers=None, path=None,
               control_response=None, keep_flag=True):
    """The shape of aegis/workers/reproduction_probe.py run_lab_check for one A request."""
    r = {"check": "idor", "request_path": path or "/api/accounts/B/secret",
         "request_headers": {"X-Test-Account": "acct_A"} if headers is None else headers,
         "status": status, "established": status == 200 and response == CROSS,
         "verdict": "proven" if status == 200 and response == CROSS else "unverified",
         "deny_statuses": [403], "response": response, "response_truncated": truncated,
         "control_status": 200 if control else 500, "control_verified": control,
         "control_response": (OWNER if control_response is None else control_response) if control else None}
    if headers == "missing":
        del r["request_headers"]
    if not keep_flag:
        del r["response_truncated"]
    return r


class Case(unittest.TestCase):
    def judged(self, result, spec="authentication_required"):
        s = DiagnosisState()
        s.observe(kind="account_resource_link", target_ref="T2", attrs={"present": True}, source="l1")
        if spec is not None:
            s.observe(kind="owner_spec", target_ref="T2", attrs={"requirement": spec}, source="owner_spec")
        h = s.propose(claim="other_account_read", target_ref="T2", basis=["E1"])
        e = s.observe(kind="check_result", target_ref="T2", attrs=check_attrs("l2_idor", result),
                      source="check", audit_hash=H, step_id="S1", catalog_id="l2_idor")
        v = judge(s, h, "l2_idor", e)
        return v.to, v.rule


class TestPositives(Case):
    def test_b_record_in_other_shapes_is_supported(self):
        for name, body in POSITIVE.items():
            with self.subTest(name):
                self.assertTrue(owner_record_read_by_other_account(lab_result(body)))
                self.assertEqual(self.judged(lab_result(body)), ("supported", "cross_account_read"))

    def test_the_owner_spec_still_decides(self):
        body = POSITIVE["enveloped_json"]
        self.assertEqual(self.judged(lab_result(body), spec="public"), ("contradicted", "intended_public"))
        self.assertEqual(self.judged(lab_result(body), spec="unspecified"), ("needs_spec", "spec_missing"))
        self.assertEqual(self.judged(lab_result(body), spec=None), ("needs_spec", "spec_missing"))

    def test_a_finding_is_not_proven_from_the_match_alone(self):
        # 実証成功 still needs the Worker's own verdict and the fixed answer shape on top of the match
        for name, body in POSITIVE.items():
            if body is CROSS:
                continue
            with self.subTest(name):
                self.assertNotEqual(reproduction_verdict(lab_result(body), "idor"), "proven")
        self.assertEqual(reproduction_verdict(lab_result(CROSS), "idor"), "proven")


class TestNearMisses(Case):
    def assertNotSupported(self, result, name):
        self.assertFalse(owner_record_read_by_other_account(result), name)
        to, _ = self.judged(result)
        self.assertNotEqual(to, "supported", name)
        self.assertNotEqual(reproduction_verdict(result, "idor"), "proven", name)

    def test_near_miss_answers(self):
        for name, body in NEAR_MISS.items():
            with self.subTest(name):
                self.assertNotSupported(lab_result(body), name)

    def test_both_identifiers_without_an_established_control(self):
        self.assertEqual(self.judged(lab_result(OWNER, control=False)), ("inconclusive", "control_failed"))
        for bad in ({**OWNER, "resource_id": "res_b_999"}, {**OWNER, "confidential_marker": "OTHER"},
                    {**OWNER, "resource_owner": "acct_A"}, {**OWNER, "caller_account": "acct_A"}):
            with self.subTest(bad):
                self.assertNotSupported(lab_result(POSITIVE["enveloped_json"], control_response=bad), bad)

    def test_both_identifiers_only_in_a_truncated_body(self):
        for name, body in POSITIVE.items():
            with self.subTest(name):
                self.assertNotSupported(lab_result(body, truncated=True), name)
        # an older result without the flag is never read as whole by the judge's match
        self.assertFalse(owner_record_read_by_other_account(lab_result(OWNER, keep_flag=False)))
        self.assertNotEqual(self.judged(lab_result(OWNER, keep_flag=False))[0], "supported")
        # and the self-report shape in a body the Worker cut short is not 実証成功 either
        self.assertNotEqual(reproduction_verdict(lab_result(CROSS, truncated=True), "idor"), "proven")

    def test_not_sent_as_a(self):
        for headers in ({"X-Test-Account": "acct_B"}, {}, "missing", {"X-Test-Account": "acct_A", "X-Other": "1"},
                        {"X-Test-Account": "acct_a"}):
            with self.subTest(headers):
                self.assertNotSupported(lab_result(OWNER, headers=headers), headers)
                self.assertNotSupported(lab_result(CROSS, headers=headers), headers)
        self.assertNotSupported(lab_result(OWNER, path="/api/accounts/A/secret"), "path")

    def test_other_statuses_and_rules_keep_their_precedence(self):
        for status in (401, 403, 404):
            self.assertEqual(self.judged(lab_result(OWNER, status=status)), ("contradicted", "denied"))
        self.assertEqual(self.judged(lab_result(OWNER, status=500)), ("inconclusive", "unrecognised_answer"))
        self.assertEqual(self.judged(lab_result({"caller_account": "acct_A", "resource_owner": "acct_A"})),
                         ("contradicted", "own_resource_only"))
        self.assertEqual(self.judged(lab_result({"error": "forbidden"})), ("contradicted", "owner_record_absent"))
        self.assertEqual(self.judged(lab_result(OWNER), spec="public"), ("contradicted", "intended_public"))

    def test_proven_always_implies_the_measured_match(self):
        bodies = list(POSITIVE.values()) + list(NEAR_MISS.values())
        for body in bodies:
            for kw in ({}, {"truncated": True}, {"control": False}, {"headers": {"X-Test-Account": "acct_B"}}):
                r = lab_result(body, **kw)
                r.update(established=True, verdict="proven")       # whatever the Worker said
                if reproduction_verdict(r, "idor") == "proven":
                    self.assertTrue(owner_record_read_by_other_account(r), (body, kw))


class _Lab(BaseHTTPRequestHandler):
    answers: dict = {}

    def do_GET(self):  # noqa: N802
        who = self.headers.get("X-Test-Account")
        status, body = self.answers.get(who, (401, {"error": "unauthenticated"}))
        raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html" if isinstance(body, str) else "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


class TestThroughTheLabWorker(Case):
    """The real lab Worker against a loopback server: A's identity is the Worker's fixed
    header, the control is B's own request in the same run."""

    def run_worker(self, a_answer, b_answer=(200, OWNER)):
        handler = type("H", (_Lab,), {"answers": {"acct_B": b_answer, "acct_A": a_answer}})
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            args = SimpleNamespace(scheme="http", host="lab.test", ip="127.0.0.1",
                                   port=srv.server_address[1], check="idor")
            return run_lab_check(args)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_worker_records_a_as_the_requester(self):
        r = self.run_worker((200, POSITIVE["enveloped_json"]))
        self.assertEqual(r["request_headers"], {"X-Test-Account": "acct_A"})
        self.assertIs(r["control_verified"], True)
        self.assertIs(r["response_truncated"], False)
        self.assertEqual(r["verdict"], "unverified")                 # the Worker's own check is unchanged
        self.assertEqual(self.judged(r), ("supported", "cross_account_read"))
        self.assertEqual(reproduction_verdict(r, "idor"), "unverified")

    def test_worker_results_for_near_misses(self):
        for name in ("marker_only_documentation", "resource_id_only", "a_own_resource_quoting_b",
                     "base64_record"):
            with self.subTest(name):
                self.assertNotEqual(self.judged(self.run_worker((200, NEAR_MISS[name])))[0], "supported")
        big = {**OWNER, "padding": "x" * 70000}                     # longer than the Worker's excerpt (64 KiB)
        r = self.run_worker((200, big))
        self.assertIs(r["response_truncated"], True)
        self.assertNotEqual(self.judged(r)[0], "supported")
        # B's control fails: A's copy of B's record is never compared
        r = self.run_worker((200, OWNER), b_answer=(500, {"error": "x"}))
        self.assertEqual(self.judged(r), ("inconclusive", "control_failed"))

    def test_worker_self_report_shape_is_still_proven(self):
        r = self.run_worker((200, CROSS))
        self.assertEqual(reproduction_verdict(r, "idor"), "proven")
        self.assertEqual(self.judged(r), ("supported", "cross_account_read"))


if __name__ == "__main__":
    unittest.main()


class TestReviewFalsePositives(unittest.TestCase):
    """The independent security review's inputs: none may count as B's record read by A."""

    def result(self, response):
        from aegis.evidence import REPRODUCTION_MARKERS
        m = REPRODUCTION_MARKERS["idor"]
        owner = {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B",
                 "resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": m}
        return m, {"check": "idor", "request_path": "/api/accounts/B/secret",
                   "request_headers": {"X-Test-Account": "acct_A"}, "status": 200, "control_status": 200,
                   "control_verified": True, "control_response": owner, "response": response,
                   "response_truncated": False}

    def test_rejected(self):
        import json as _json
        from aegis.evidence import owner_record_read_by_other_account as matched
        m, _ = self.result(None)
        for name, body in {
            "owner_object_naming_A": {"resource_id": "res_b_001", "confidential_marker": m, "owner": {"id": "acct_A"}},
            "owners_list_naming_A": {"resource_id": "res_b_001", "confidential_marker": m, "owners": ["acct_A"]},
            "owner_object_with_a_number": {"resource_id": "res_b_001", "confidential_marker": m, "owner": {"id": 7}},
            "record_as_json_in_a_string": {"data": _json.dumps({"resource_id": "res_b_001", "confidential_marker": m,
                                                                "resource_owner": "acct_A"})},
            "identifiers_in_separate_items": {"items": [{"note": "res_b_001"}, {"note": m}]},
            "identifiers_inside_prose": {"note": f"see res_b_001 and {m} in the docs"},
            # both identifiers only inside one URL: a link, not the record itself
            "identifiers_inside_a_link": {"link": "/r/res%5Fb%5F001?k=VULNIX%5FLAB%5FIDOR%5FPROVEN"},
            "text_naming_A_with_x_escape": "Denied for acct\\x5fA: res_b_001 " + m,
        }.items():
            with self.subTest(name):
                self.assertFalse(matched(self.result(body)[1]), name)

    def test_still_accepted(self):
        from aegis.evidence import owner_record_read_by_other_account as matched
        m, _ = self.result(None)
        for name, body in {
            "owner_object_naming_B": {"resource_id": "res_b_001", "confidential_marker": m, "owner": {"id": "acct_B"}},
            "camel_case_envelope": {"data": {"resourceId": "res_b_001", "confidentialMarker": m, "resourceOwner": "acct_B"}},
        }.items():
            with self.subTest(name):
                self.assertTrue(matched(self.result(body)[1]), name)


class TestFalsePositiveMatrix(TestReviewFalsePositives):
    """PR #111 quality gate: the four families that can turn a non-vulnerable answer into
    "supported" - nested owner data, JSON inside strings, array element correspondence and
    escaped identifiers. Each row says whether B's record was really read by A."""

    def check(self, rows):
        from aegis.evidence import owner_record_read_by_other_account as matched
        for name, (body, expected) in rows.items():
            with self.subTest(name):
                self.assertIs(matched(self.result(body)[1]), expected, name)

    def test_nested_owner_information(self):
        m, _ = self.result(None)
        rec = {"resource_id": "res_b_001", "confidential_marker": m}
        self.check({
            "owner_in_a_parent_names_A": ({"owner": "acct_A", "data": rec}, False),
            "owner_two_levels_down_names_A": ({**rec, "meta": {"owner": {"account": {"id": "acct_A"}}}}, False),
            "owner_list_mixing_A_and_B": ({**rec, "owners": ["acct_B", "acct_A"]}, False),
            "owner_key_case_variants": ({**rec, "OWNER_ID": "acct_A"}, False),
            "owner_key_camel": ({**rec, "ownerAccount": "acct_A"}, False),
            "owner_empty_object": ({**rec, "owner": {}}, False),
            "owner_null": ({**rec, "owner": None}, False),
            "owner_names_B_everywhere": ({"owner": "acct_B", "data": {**rec, "owner": {"id": "acct_B"}}}, True),
        })

    def test_json_inside_strings(self):
        import json as _json
        m, _ = self.result(None)
        rec = {"resource_id": "res_b_001", "confidential_marker": m, "resource_owner": "acct_B"}
        self.check({
            "record_as_a_string_field": ({"payload": _json.dumps(rec)}, False),
            "record_double_encoded": ({"payload": _json.dumps(_json.dumps(rec))}, False),
            "record_string_inside_a_list": ({"items": [_json.dumps(rec)]}, False),
            "whole_answer_is_the_json_text": (_json.dumps(rec), True),        # the body itself is the record
        })

    def test_array_element_correspondence(self):
        m, _ = self.result(None)
        self.check({
            "id_and_marker_in_different_items": ({"items": [{"resource_id": "res_b_001"},
                                                            {"confidential_marker": m}]}, False),
            "id_and_marker_in_different_lists": ({"ids": ["res_b_001"], "markers": [m]}, False),
            "marker_on_another_resource_in_the_list": ({"items": [{"resource_id": "res_b_001"},
                                                                  {"resource_id": "res_a_001",
                                                                   "confidential_marker": m}]}, False),
            "id_field_disagrees": ({"id": "res_a_001", "resource_id": "res_b_001", "confidential_marker": m}, False),
            "b_record_among_other_results": ({"results": [{"resource_id": "res_a_001", "note": "x"},
                                                          {"resource_id": "res_b_001", "confidential_marker": m,
                                                           "owner": "acct_B"}]}, True),
        })

    def test_escaped_identifiers(self):
        m, _ = self.result(None)
        esc = lambda t: "".join(f"\\u{ord(c):04x}" if c == "_" else c for c in t)   # noqa: E731
        self.check({
            # the identifiers escaped are still B's identifiers
            "json_unicode_escapes_in_the_body": ('{"resource_id": "' + esc("res_b_001") + '", "confidential_marker": "'
                                                 + esc(m) + '"}', True),
            "html_entities": (f"<table><td>res&#95;b&#95;001</td><td>{m}</td></table>", True),
            # A named through an escape: never B's record read by A
            "html_names_A_with_entities": (f"<p>acct&#95;A</p><p>res_b_001 {m}</p>", False),
            "html_names_A_with_unicode_escape": (f"<p>acct\\u005fA</p><p>res_b_001 {m}</p>", False),
            "html_names_A_percent_escaped": (f"<p>acct%5FA</p><p>res_b_001 {m}</p>", False),
            # an escape that does not decode to the identifier does not match
            "double_percent_escape": (f"<p>res%255Fb%255F001 {m}</p>", False),
            "lookalike_identifier": (f"<p>res_b_0O1 {m}</p>", False),
        })
