"""`.env.local` loader: local secrets reach os.environ at startup, never the console,
never override the real environment, and blank placeholders stay unset."""
from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from aegis import server

SECRET = "sk-test-NEVER-PRINT-9f3c"


class TestEnvLocalLoader(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / ".env.local"

    def tearDown(self):
        self._tmp.cleanup()

    def _load(self, text: str, env: dict | None = None) -> tuple[int, dict, str]:
        self.path.write_text(text, encoding="utf-8")
        with mock.patch.dict(os.environ, env or {}, clear=True):
            buf = io.StringIO()
            with redirect_stdout(buf):
                n = server._load_env_local(self.path)
            return n, dict(os.environ), buf.getvalue()

    def test_values_are_loaded_and_comments_and_blanks_skipped(self):
        n, env, _ = self._load(
            "# comment\n\nVULNIX_ABLITERATION_URL=https://api.example.test/v1/chat/completions\n"
            "VULNIX_ABLITERATION_MODEL=m1\nVULNIX_ABLITERATION_KEY=\n")
        self.assertEqual(n, 2)
        self.assertEqual(env["VULNIX_ABLITERATION_MODEL"], "m1")
        self.assertNotIn("VULNIX_ABLITERATION_KEY", env)

    def test_the_real_environment_wins(self):
        n, env, _ = self._load("VULNIX_ABLITERATION_MODEL=from-file\n",
                               {"VULNIX_ABLITERATION_MODEL": "from-env"})
        self.assertEqual(n, 0)
        self.assertEqual(env["VULNIX_ABLITERATION_MODEL"], "from-env")

    def test_quotes_and_export_prefix_are_stripped(self):
        _, env, _ = self._load('export A_KEY="v1"\nB_KEY=\'v2\'\n')
        self.assertEqual((env["A_KEY"], env["B_KEY"]), ("v1", "v2"))

    def test_malformed_lines_are_skipped_not_fatal(self):
        n, env, _ = self._load('BAD KEY=x\n1X=y\nOK=v # note\nQ="a#b"\nH=\'it\'s\'\nP="half\n')
        self.assertNotIn("BAD KEY", env)
        self.assertNotIn("1X", env)
        self.assertEqual(env["OK"], "v")
        self.assertEqual(env["Q"], "a#b")
        self.assertEqual(env["H"], "it's")
        self.assertEqual(env["P"], '"half')

    def test_a_file_that_is_not_utf8_does_not_stop_the_server(self):
        self.path.write_bytes(b"K=\xff\xfe\n")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(server._load_env_local(self.path), 0)

    def test_a_missing_file_loads_nothing(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(server._load_env_local(Path(self._tmp.name) / "absent"), 0)

    def test_the_loader_never_prints_a_value(self):
        _, env, out = self._load(f"VULNIX_ABLITERATION_KEY={SECRET}\n")
        self.assertEqual(env["VULNIX_ABLITERATION_KEY"], SECRET)
        self.assertNotIn(SECRET, out)


class TestTestsNeverReadTheRealEnvLocal(unittest.TestCase):
    def test_the_opt_out_switch_skips_the_project_file(self):
        with mock.patch.dict(os.environ, {"VULNIX_NO_ENV_LOCAL": "1"}, clear=True), \
                mock.patch.object(Path, "read_text", side_effect=AssertionError("read")):
            self.assertEqual(server._load_env_local(), 0)

    def test_every_test_that_starts_the_server_opts_out(self):
        """A test that runs `main()` (in-process or as `-m aegis.server`) would load a
        developer's real .env.local - and with it a real API key - unless it opts out."""
        tests = Path(__file__).resolve().parent
        offenders = []
        for f in sorted(tests.glob("test_*.py")):
            if f.name == Path(__file__).name:
                continue
            lines = f.read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines):
                if "server.main()" in line or '"-m", "aegis.server"' in line:
                    window = "\n".join(lines[max(0, i - 6):i + 8])
                    if "VULNIX_NO_ENV_LOCAL" not in window:
                        offenders.append(f"{f.name}:{i + 1}")
        self.assertEqual(offenders, [])


class TestEnvLocalStaysOutOfGit(unittest.TestCase):
    def test_env_local_is_git_ignored(self):
        root = Path(server.__file__).resolve().parents[1]
        r = subprocess.run(["git", "check-ignore", "-q", ".env.local"], cwd=root, check=False)
        if r.returncode == 128:
            self.skipTest("not a git checkout")
        self.assertEqual(r.returncode, 0, ".env.local must stay git-ignored")


if __name__ == "__main__":
    unittest.main()
