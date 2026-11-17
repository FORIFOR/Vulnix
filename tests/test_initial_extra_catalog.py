"""Initial real-site planning must be reviewed when the L1 catalog changes."""

import unittest
from unittest.mock import patch

from aegis import artex_bridge


class InitialExtraCatalogTests(unittest.TestCase):
    def test_every_extra_l1_catalog_entry_has_an_explicit_initial_rule(self):
        extras = {entry.id for entry in artex_bridge.CATALOG
                  if entry.level == "L1" and entry.id != "l1_http_probe"}
        self.assertEqual(extras, artex_bridge.INITIAL_REAL_SITE_EXTRA_RULES)

    def test_unreviewed_new_l1_entry_fails_closed(self):
        extra = artex_bridge.CatalogEntry(
            "l1_future_read_only", "http_probe", "read_only_probe", "L1",
            "future test check", ("future",))
        with patch.object(artex_bridge, "CATALOG", artex_bridge.CATALOG + (extra,)):
            with self.assertRaisesRegex(ValueError, "unreviewed extra L1 catalog"):
                artex_bridge.initial_real_site_extra_checks(
                    {"server_family": "other"}, status_consent=True,
                    root_observed=True)

    def test_apache_requires_both_consents_and_signed_root(self):
        for family, consent, root, expected in (
                ("apache", True, True, {"l1_apache_mod_status"}),
                ("apache", False, True, set()),
                ("apache", True, False, set()),
                ("other", True, True, set())):
            with self.subTest(family=family, consent=consent, root=root):
                self.assertEqual(artex_bridge.initial_real_site_extra_checks(
                    {"server_family": family}, status_consent=consent,
                    root_observed=root), expected)


if __name__ == "__main__":
    unittest.main()
