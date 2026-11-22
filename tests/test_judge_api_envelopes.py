"""The v5 judge changes (docs/evaluation/FROZEN_JUDGE_V5.md, V4_MISS_ANALYSIS.md):

1. Standard API envelopes: B's resource id as a field of an object and the confidential
   marker as a field of an object below it reached through dict keys only (JSON:API
   data.attributes, a GraphQL field object, a HAL embedded object) are one record. Every
   earlier guard still applies; a list, a sibling object, a string, prose, a URL or base64
   between the two identifiers never makes one record.
2. GraphQL errors: an `errors` element may also carry `path`, `locations` and `extensions`
   (scalars / lists / dicts of scalars); refusal words only from message / code fields;
   `data` must be null (or an object of nulls only) for a refusal.
3. Long bodies: the lab IDOR Worker keeps 64 KiB of A's answer.
"""
import base64
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

from aegis import diagnosis_judge
from aegis.diagnosis_judge import _body_kind, check_attrs
from aegis.evidence import owner_record_read_by_other_account as matched
from aegis.evidence import reproduction_verdict
from aegis.runtime import MAX_CAPTURE
from aegis.workers import reproduction_probe
from aegis.workers.reproduction_probe import run_lab_check
from tests.test_judge_identity_match import OWNER, Case, _Lab, lab_result

M = "VULNIX_LAB_IDOR_PROVEN"
RID = "res_b_001"


class TestApiEnvelopes(Case):
    def check(self, rows):
        for name, (body, expected) in rows.items():
            with self.subTest(name):
                r = lab_result(body)
                self.assertIs(matched(r), expected, name)
                to, _ = self.judged(r)
                self.assertEqual(to == "supported", expected, name)
                self.assertNotEqual(reproduction_verdict(r, "idor"), "proven", name)

    def test_standard_envelopes_are_one_record(self):
        self.check({
            "jsonapi_data_attributes": ({"data": {"type": "secrets", "id": RID,
                                                  "attributes": {"confidential_marker": M, "label": "tax"}},
                                         "meta": {"requested_by": "acct_A"}}, True),
            "jsonapi_relationship_owner_names_b": ({"data": {"type": "secrets", "id": RID,
                                                             "attributes": {"confidential_marker": M},
                                                             "relationships": {"owner": {"data": {"id": "acct_B"}}}}},
                                                   True),
            "graphql_field_object": ({"data": {"account": {"id": RID, "secret": {"value": M}}}}, True),
            "graphql_viewer_sibling": ({"data": {"viewer": {"id": "acct_A"},
                                                 "account": {"id": RID, "secret": {"value": M}}}}, True),
            "hal_embedded_object": ({"resource_id": RID, "_links": {"self": {"href": "/api/accounts/B/secret"}},
                                     "_embedded": {"secret": {"confidential_marker": M}}}, True),
            "two_levels_of_keys": ({"data": {"id": RID, "attributes": {"secret": {"value": M}}}}, True),
            # a list between the enclosing page and the record still separates them (unchanged)
            "record_in_a_list_under_a_page_id": ({"id": "page_1", "results": [{"resource_id": RID,
                                                                              "confidential_marker": M}]}, True),
        })

    def test_identifiers_split_across_structures_do_not_match(self):
        self.check({
            "id_in_parent_marker_in_a_list_item": ({"id": RID, "items": [{"confidential_marker": M}]}, False),
            "id_in_parent_marker_in_a_list_below_a_child": ({"id": RID, "attributes": {"history": [{"secret": M}]}},
                                                            False),
            "id_in_parent_marker_in_a_list_of_values": ({"id": RID, "attributes": {"secrets": [M]}}, False),
            "id_in_one_sibling_marker_in_another": ({"data": {"a": {"id": RID}, "b": {"secret": M}}}, False),
            "marker_in_parent_id_in_child": ({"confidential_marker": M, "attributes": {"id": RID}}, False),
            "id_only_inside_a_list_of_ids": ({"ids": [RID], "attributes": {"secret": M}}, False),
            "id_inside_prose": ({"ref": f"see {RID}", "attributes": {"secret": M}}, False),
        })

    def test_marker_in_an_encoded_child_does_not_match(self):
        self.check({
            "child_marker_in_a_json_string": ({"id": RID, "attributes": {"blob": json.dumps({"secret": M})}}, False),
            "child_marker_in_prose": ({"id": RID, "attributes": {"note": f"the secret is {M}"}}, False),
            "child_marker_in_a_url": ({"id": RID, "_links": {"secret": {"href": f"/s?m={M}"}}}, False),
            "child_marker_base64": ({"id": RID, "attributes": {"secret": base64.b64encode(M.encode()).decode()}},
                                    False),
        })

    def test_another_resource_or_a_own_record_does_not_match(self):
        self.check({
            "parent_id_names_another_resource": ({"id": "res_a_001", "resource_id": RID,
                                                  "attributes": {"secret": M}}, False),
            "enclosing_object_is_another_resource": ({"id": "res_a_001",
                                                      "data": {"resource_id": RID, "confidential_marker": M}},
                                                     False),
            "child_is_another_resource": ({"id": RID, "related": {"id": "res_c_001", "secret": M}}, False),
            "child_with_a_numeric_id": ({"id": RID, "attributes": {"id": 5, "secret": M}}, False),
            "child_object_names_owner_a": ({"data": {"id": RID, "attributes": {"secret": M, "owner": "acct_A"}}},
                                           False),
            "relationship_owner_names_a": ({"data": {"id": RID, "attributes": {"secret": M},
                                                     "relationships": {"owner": {"data": {"id": "acct_A"}}}}},
                                           False),
            "enclosing_owner_names_a": ({"owner": "acct_A", "data": {"id": RID, "attributes": {"secret": M}}},
                                        False),
            "owner_list_mixing_a_and_b": ({"id": RID, "owners": ["acct_B", "acct_A"], "attributes": {"secret": M}},
                                          False),
            # an owner object that carries anything but B's name (a type tag, a handle, a link)
            # still fails the owner guard: unchanged, stays undecided
            "owner_object_with_a_type_tag": ({"data": {"id": RID, "attributes": {"secret": M},
                                                       "relationships": {"owner": {"data": {"type": "accounts",
                                                                                            "id": "acct_B"}}}}},
                                             False),
        })

    def test_truncated_or_uncontrolled_envelopes_still_do_not_match(self):
        body = {"data": {"id": RID, "attributes": {"confidential_marker": M}}}
        self.assertFalse(matched(lab_result(body, truncated=True)))
        self.assertFalse(matched(lab_result(body, keep_flag=False)))
        self.assertEqual(self.judged(lab_result(body, control=False)), ("inconclusive", "control_failed"))
        self.assertFalse(matched(lab_result(body, headers={"X-Test-Account": "acct_B"})))


GQL_DENIED = {"message": "Not authorised to access Secret", "path": ["node"],
              "locations": [{"line": 1, "column": 3}], "extensions": {"code": "FORBIDDEN"}}


class TestGraphqlErrors(Case):
    def kind(self, body):
        return _body_kind(body, True)

    def test_graphql_refusals(self):
        for name, body in {
            "data_null": {"data": None, "errors": [GQL_DENIED]},
            "data_absent": {"errors": [GQL_DENIED]},
            "data_of_nulls": {"data": {"node": None}, "errors": [GQL_DENIED]},
            "message_only_word": {"data": None, "errors": [{"message": "Access denied", "path": ["node", 0]}]},
        }.items():
            with self.subTest(name):
                self.assertEqual(self.kind(body), "json_refusal")
                self.assertEqual(self.judged(lab_result(body)), ("contradicted", "owner_record_absent"))

    def test_graphql_answers_that_are_not_refusals(self):
        for name, body in {
            "b_data_with_an_error": {"data": {"account": {"id": RID, "secret": {"value": M}}}, "errors": [GQL_DENIED]},
            "data_without_identifiers": {"data": {"account": {"label": "tax documents"}}, "errors": [GQL_DENIED]},
            "data_partly_resolved": {"data": {"node": None, "other": "x"}, "errors": [GQL_DENIED]},
            "data_a_list": {"data": [], "errors": [GQL_DENIED]},
            "data_a_string": {"data": "x", "errors": [GQL_DENIED]},
            "data_nested_nulls": {"data": {"node": {"secret": None}}, "errors": [GQL_DENIED]},
            "word_only_in_path": {"errors": [{"message": "Something happened", "path": ["forbidden"]}]},
            "word_only_in_other_extension": {"errors": [{"message": "Something happened",
                                                         "extensions": {"reason": "forbidden"}}]},
            "nested_extensions": {"errors": [{**GQL_DENIED, "extensions": {"exception": {"stack": ["a"]}}}]},
            "long_extension_string": {"errors": [{**GQL_DENIED, "extensions": {"code": "FORBIDDEN",
                                                                               "trace": "x" * 300}}]},
            "path_with_objects": {"errors": [{**GQL_DENIED, "path": [{"a": 1}]}]},
            "locations_nested_deeper": {"errors": [{**GQL_DENIED, "locations": [{"line": [1]}]}]},
            "unknown_error_key": {"errors": [{**GQL_DENIED, "data": {"x": 1}}]},
            "success_flag": {"success": True, "errors": [GQL_DENIED]},
        }.items():
            with self.subTest(name):
                self.assertEqual(self.kind(body), "json_data", name)
                self.assertNotEqual(self.judged(lab_result(body))[1], "owner_record_absent", name)

    def test_b_data_with_an_error_is_b_record(self):
        body = {"data": {"account": {"id": RID, "secret": {"value": M}}}, "errors": [GQL_DENIED]}
        self.assertEqual(self.judged(lab_result(body)), ("supported", "cross_account_read"))

    def test_b_identifiers_in_an_error_are_never_absence(self):
        body = {"data": None, "errors": [{**GQL_DENIED, "extensions": {"code": "FORBIDDEN", "id": RID}}]}
        self.assertEqual(self.kind(body), "json_refusal")
        self.assertEqual(self.judged(lab_result(body)), ("inconclusive", "unrecognised_answer"))
        body = {"data": None, "errors": [{**GQL_DENIED, "message": "acct_B only"}]}
        self.assertEqual(self.judged(lab_result(body)), ("inconclusive", "unrecognised_answer"))

    def test_a_cut_graphql_refusal_is_not_read(self):
        body = {"data": None, "errors": [GQL_DENIED]}
        self.assertEqual(self.judged(lab_result(body, truncated=True)), ("inconclusive", "unrecognised_answer"))


class TestLongBodies(Case):
    def run_worker(self, a_answer, check="idor"):
        handler = type("H", (_Lab,), {"answers": {"acct_B": (200, OWNER), "acct_A": a_answer}})
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            return run_lab_check(SimpleNamespace(scheme="http", host="lab.test", ip="127.0.0.1",
                                                 port=srv.server_address[1], check=check))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_the_limits_agree(self):
        self.assertEqual(reproduction_probe.LAB_IDOR_EXCERPT, 65536)
        self.assertEqual(diagnosis_judge.L2_EXCERPT, reproduction_probe.LAB_IDOR_EXCERPT)
        # the bytes read always decode to at least the characters kept
        self.assertGreaterEqual(reproduction_probe.MAX_BODY, 4 * reproduction_probe.LAB_IDOR_EXCERPT)
        self.assertEqual(reproduction_probe.EXCERPT, 4096)          # other checks and rules unchanged

    def test_b_record_first_in_a_long_answer(self):
        history = [{"at": f"2026-10-01T08:{i % 60:02d}:00Z", "event": "viewed", "by": "acct_B"} for i in range(200)]
        r = self.run_worker((200, {**OWNER, "history": history}))
        self.assertGreater(len(json.dumps(r["response"])), 4096)
        self.assertIs(r["response_truncated"], False)
        self.assertEqual(self.judged(r), ("supported", "cross_account_read"))

    def test_b_record_late_in_a_long_list(self):
        items = [{"id": f"res_a_{i:03d}", "owner": "acct_A", "title": f"my note {i}"} for i in range(2, 200)]
        r = self.run_worker((200, {"items": items + [{"resource_id": RID, "owner": "acct_B",
                                                       "confidential_marker": M}], "total": 199}))
        self.assertIs(r["response_truncated"], False)
        self.assertEqual(self.judged(r), ("supported", "cross_account_read"))

    def test_beyond_the_limit_is_still_cut_and_not_decided(self):
        r = self.run_worker((200, {**OWNER, "padding": "x" * 70000}))
        self.assertIs(r["response_truncated"], True)
        self.assertNotEqual(self.judged(r)[0], "supported")
        r = self.run_worker((200, {"error": "forbidden", "padding": "x" * 70000}))
        self.assertIs(r["response_truncated"], True)
        self.assertEqual(self.judged(r), ("inconclusive", "unrecognised_answer"))
        r = self.run_worker((200, "x" * 65536))
        self.assertIs(r["response_truncated"], False)
        r = self.run_worker((200, "x" * 65537))
        self.assertIs(r["response_truncated"], True)
        self.assertEqual(len(r["response"]), 65536)

    def test_a_long_answer_without_b_record_is_not_closed(self):
        items = [{"id": f"res_a_{i:03d}", "owner": "acct_A", "title": f"my note {i}"} for i in range(2, 200)]
        r = self.run_worker((200, {"items": items, "total": 198}))
        self.assertIs(r["response_truncated"], False)
        self.assertEqual(self.judged(r), ("inconclusive", "unrecognised_answer"))

    def test_the_worker_output_stays_within_the_runtime_capture(self):
        # worst case per kept character: a control character, \\u0001 in the JSON output (6 bytes)
        r = self.run_worker((200, "\x01" * 70000))
        out = json.dumps(r, ensure_ascii=False).encode()
        self.assertLessEqual(len(out), 6 * 65536 + 8192)
        self.assertLess(len(out), MAX_CAPTURE)
        self.assertEqual(json.loads(out)["response"], "\x01" * 65536)

    def test_the_owner_control_keeps_its_own_limit(self):
        handler = type("H", (_Lab,), {"answers": {"acct_B": (200, {**OWNER, "padding": "x" * 5000}),
                                                  "acct_A": (200, OWNER)}})
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = run_lab_check(SimpleNamespace(scheme="http", host="lab.test", ip="127.0.0.1",
                                              port=srv.server_address[1], check="idor"))
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIs(r["control_verified"], False)


if __name__ == "__main__":
    unittest.main()


class TestV5ReviewFalsePositives(unittest.TestCase):
    """The independent review of the v5 judge: the marker must come from B's own record
    (envelope keys only), never from an example, a template, a related or previous object,
    a refusal echoing the id, another id, or anything naming A outside a caller field."""

    def run_match(self, response):
        from aegis.evidence import REPRODUCTION_MARKERS, owner_record_read_by_other_account
        m = REPRODUCTION_MARKERS["idor"]
        owner = {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B",
                 "resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": m}
        res = {"check": "idor", "request_path": "/api/accounts/B/secret",
               "request_headers": {"X-Test-Account": "acct_A"}, "status": 200, "control_status": 200,
               "control_verified": True, "control_response": owner,
               "response": response(m) if callable(response) else response, "response_truncated": False}
        return owner_record_read_by_other_account(res)

    def test_rejected(self):
        cases = {
            "refusal_echoing_id_with_example": lambda m: {"id": "res_b_001", "status": "forbidden",
                                                          "help": {"example_response": {"confidential_marker": m}}},
            "error_with_schema_example": lambda m: {"resource_id": "res_b_001", "error": "forbidden",
                                                    "schema": {"example": {"confidential_marker": m}}},
            "related_object": lambda m: {"id": "res_b_001", "related": {"other": {"confidential_marker": m}}},
            "docs_template": lambda m: {"id": "res_b_001", "docs": {"template": {"secret": m}}},
            "previous_version": lambda m: {"id": "res_b_001", "previous_version": {"confidential_marker": m}},
            "uuid_of_another_record": lambda m: {"id": "res_b_001", "attributes": {"uuid": "res_c_001",
                                                                                   "confidential_marker": m}},
            "note_id_of_another_record": lambda m: {"id": "res_b_001", "attributes": {"noteId": "n_9",
                                                                                      "confidential_marker": m}},
            "account_A_around": lambda m: {"account": "acct_A", "mine": {"id": "res_b_001", "attributes": {"secret": m}}},
            "account_A_inside": lambda m: {"id": "res_b_001", "attributes": {"confidential_marker": m,
                                                                             "account": "acct_A"}},
        }
        for name, body in cases.items():
            with self.subTest(name):
                self.assertFalse(self.run_match(body), name)

    def test_still_accepted(self):
        cases = {
            "json_api": lambda m: {"data": {"type": "accounts", "id": "res_b_001",
                                            "attributes": {"confidential_marker": m, "owner": "acct_B"}}},
            "graphql_field_object": lambda m: {"data": {"account": {"id": "res_b_001", "secret": {"value": m}}}},
            "flat_record_with_caller_A": lambda m: {"resource_id": "res_b_001", "confidential_marker": m,
                                                    "resource_owner": "acct_B", "caller_account": "acct_A"},
        }
        for name, body in cases.items():
            with self.subTest(name):
                self.assertTrue(self.run_match(body), name)
