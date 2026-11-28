"""Every generated fix (path, SQL, command, XSS; development and held-out styles) is applied to a
scratch copy and run on real Flask: the exploit stops and the normal requests still work."""
import os
import unittest

from tests.test_fix_patch_redirect import REAL_FLASK, _READY


@unittest.skipUnless(_READY and REAL_FLASK, "node, web/node_modules and VULNIX_REAL_FLASK_PYTHON")
class TestGeneratedFixesOnRealFlask(unittest.TestCase):
    def test_each_case_reproduces_before_and_is_fixed_without_side_effects_after(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
        import eval_fix_support as E
        names = sorted(p.name for p in E.CASES.iterdir() if (p / "case.json").exists())
        self.assertGreaterEqual(len(names), 8)
        for name in names:
            with self.subTest(case=name):
                row = E.run_case(name, REAL_FLASK, None, "")
                self.assertEqual(row["baseline"], {"runs": True, "normal_ok": True, "exploited": True})
                self.assertTrue(row["fixed_found"])
                self.assertEqual(row["fixed"]["result"], {"runs": True, "normal_ok": True, "exploited": False})


if __name__ == "__main__":
    unittest.main()
