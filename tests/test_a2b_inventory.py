"""A2B endpoint normalisation and OpenAPI comparison."""
import unittest
from pathlib import Path

from aegis.a2b.endpoint_inventory import build_inventory, compare_openapi, is_third_party, normalise_path
from aegis.a2b.static_analyzer import Hints, scan_source_tree

APP = Path(__file__).resolve().parent / "fixtures" / "a2b" / "sample_app"


class TestNormalisation(unittest.TestCase):
    def test_ids_and_templates_become_one_parameter(self):
        for raw in ("/v1/users/123/orders", "v1/users/{userId}/orders", "/v1/users/:id/orders",
                    "/v1/users/0f8fad5b-d9cb-469f-a165-70867728950e/orders?x=1"):
            self.assertEqual(normalise_path(raw), "/v1/users/{param}/orders", raw)

    def test_third_party_hosts(self):
        self.assertTrue(is_third_party("firebaseinstallations.googleapis.com"))
        self.assertFalse(is_third_party("api.shop-a2b.test"))
        self.assertFalse(is_third_party("notgoogleapis.com"))

    def test_relative_paths_get_no_host_when_the_base_is_ambiguous(self):
        h = Hints(urls=[("https://a.shop-a2b.test/", "x"), ("https://b.shop-a2b.test/", "x")],
                  calls=[("GET", "v1/items/{id}", "x")])
        inv = build_inventory(h)
        self.assertEqual([(e.host, e.path) for e in inv["endpoints"]], [(None, "/v1/items/{param}")])


class TestOpenAPI(unittest.TestCase):
    def test_comparison(self):
        eps = build_inventory(scan_source_tree(APP))["endpoints"]
        spec = {"openapi": "3.0.0", "servers": [{"url": "https://api.shop-a2b.test/v1"}],
                "paths": {"/users/{id}/orders": {"get": {}}, "/orders": {"post": {}},
                          "/orders/{orderId}": {"get": {}}, "/health": {"get": {}}}}
        cmp = compare_openapi(eps, spec)
        matched = {(m["method"], m["path"]) for m in cmp["matched"]}
        self.assertEqual(matched, {("GET", "/v1/users/{param}/orders"), ("POST", "/v1/orders"),
                                   ("GET", "/v1/orders/{param}")})
        undocumented = {u["path"] for u in cmp["undocumented_in_spec"]}
        self.assertIn("/internal/admin/stats", undocumented)
        self.assertEqual(cmp["declared_not_seen_in_app"], ["GET /health"])

    def test_bad_spec(self):
        with self.assertRaises(ValueError):
            compare_openapi([], {"openapi": "3"})


if __name__ == "__main__":
    unittest.main()
