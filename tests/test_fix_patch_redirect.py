"""A generated open-redirect fix: applied to a copy only, run, and re-verified with the same probe."""
import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from aegis.redirect_evidence import open_redirect_verdict
from aegis.workers.redirect_probe import run as probe

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "tests/fixtures/redirect_app"
SHIM = ROOT / "tests/fixtures/flask_shim"


def _port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _fixes(path: Path, name: str) -> list:
    out = subprocess.run(["node", str(ROOT / "scripts/fix_patch_cli.mjs"), str(path), name],
                         capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


class _Served:
    def __init__(self, folder: Path, python: str | None = None):
        """With `python`, the app runs on that interpreter's real Flask (no shim on the path)."""
        self.port = _port()
        paths = [str(folder)] if python else [str(SHIM), str(folder)]
        code = (f"import sys, runpy; sys.path[:0] = {paths!r}; "
                f"sys.argv = ['app.py', '{self.port}']; runpy.run_path({str(folder / 'app.py')!r}, run_name='__main__')")
        self.proc = subprocess.Popen([python or sys.executable, "-I", "-c", code], cwd=folder,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("sample app did not start")

    def check(self):
        return probe(argparse.Namespace(check="open_redirect", ip="127.0.0.1", port=self.port,
                                        host="127.0.0.1", scheme="http"))

    def page(self, path: str) -> tuple[int, str]:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", path)
            r = conn.getresponse()
            return r.status, r.read().decode()
        finally:
            conn.close()

    def close(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)


# The generator is browser TypeScript; it needs node and web/node_modules (typescript). The Web
# CI job installs both and sets VULNIX_REQUIRE_FIX_PATCH_TEST=1, where a skip is a failure.
_READY = bool(shutil.which("node")) and (ROOT / "web/node_modules/typescript").is_dir()
if os.environ.get("VULNIX_REQUIRE_FIX_PATCH_TEST") == "1" and not _READY:
    raise RuntimeError("node and web/node_modules are required for this test")


@unittest.skipUnless(_READY, "node and web/node_modules are required for the browser-side patch generator")
class TestGeneratedRedirectFix(unittest.TestCase):
    def test_the_fix_is_minimal_applied_to_a_copy_and_reverified_with_the_same_probe(self):
        original = (APP / "app.py").read_bytes()
        fixes = _fixes(APP / "app.py", "app.py")
        self.assertEqual(len(fixes), 1)
        fix = fixes[0]
        self.assertTrue(fix["ok"], fix)
        self.assertEqual(fix["finding"]["kind"], "redirect")
        self.assertEqual(fix["finding"]["line"], 12)               # return redirect(return_to)
        removed = [l for l in fix["diff"].splitlines() if l.startswith("-") and not l.startswith("---")]
        self.assertEqual(removed, ["-    return redirect(return_to)"])   # one line changed, helper added
        self.assertLessEqual(fix["changedLines"], 12)
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "work"
            shutil.copytree(APP, copy)
            (copy / "app.py").write_text(fix["patched"])
            self.assertEqual(_fixes(copy / "app.py", "app.py"), [])   # the same scan no longer reports it
            before, after = _Served(APP), _Served(copy)
            try:
                vulnerable, fixed = before.check(), after.check()
            finally:
                before.close()
                after.close()
        self.assertEqual(open_redirect_verdict(vulnerable), "proven")
        self.assertEqual(open_redirect_verdict(fixed), "not_reproduced")
        self.assertTrue(fixed["control_verified"])        # a legitimate same-site return still works
        self.assertEqual(hashlib.sha256((APP / "app.py").read_bytes()).digest(), hashlib.sha256(original).digest())


REAL_FLASK = os.environ.get("VULNIX_REAL_FLASK_PYTHON", "")
if os.environ.get("VULNIX_REQUIRE_FIX_PATCH_TEST") == "1" and not REAL_FLASK:
    raise RuntimeError("VULNIX_REAL_FLASK_PYTHON is required where this test is required")


@unittest.skipUnless(_READY and REAL_FLASK, "set VULNIX_REAL_FLASK_PYTHON to an interpreter with Flask installed")
class TestGeneratedRedirectFixOnRealFlask(unittest.TestCase):
    """The same fix on the real framework (an isolated interpreter; Vulnix does not depend on Flask)."""

    def test_real_flask_original_is_open_patched_is_not_and_normal_pages_still_work(self):
        fix = _fixes(APP / "app.py", "app.py")[0]
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "work"
            shutil.copytree(APP, copy)
            (copy / "app.py").write_text(fix["patched"])
            before, after = _Served(APP, REAL_FLASK), _Served(copy, REAL_FLASK)
            try:
                vulnerable, fixed = before.check(), after.check()
                pages = {path: after.page(path) for path in ("/dashboard", "/auth/callback?return_to=/dashboard",
                                                             "/auth/callback")}
            finally:
                before.close()
                after.close()
        self.assertEqual(open_redirect_verdict(vulnerable), "proven")
        self.assertEqual(open_redirect_verdict(fixed), "not_reproduced")
        self.assertEqual(pages["/dashboard"], (200, "dashboard"))
        self.assertEqual(pages["/auth/callback?return_to=/dashboard"][0], 302)   # same-site return kept
        self.assertEqual(pages["/auth/callback"][0], 302)                         # default "/" still works


if __name__ == "__main__":
    unittest.main()
