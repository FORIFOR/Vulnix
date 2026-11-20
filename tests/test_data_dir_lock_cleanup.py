"""A normal process exit closes the data-directory lock handle."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestDataDirLockCleanup(unittest.TestCase):
    def test_no_unclosed_lock_warning_on_normal_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = (
                "from pathlib import Path\n"
                "from aegis.assessment import _claim_data_dir\n"
                f"_claim_data_dir(Path({tmp!r}))\n"
            )
            result = subprocess.run(
                [sys.executable, "-W", "always::ResourceWarning", "-c", script],
                cwd=Path(__file__).resolve().parents[1],
                env={**os.environ, "VULNIX_NO_ENV_LOCAL": "1"},
                capture_output=True, text=True, timeout=20,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("ResourceWarning", result.stderr)


if __name__ == "__main__":
    unittest.main()
