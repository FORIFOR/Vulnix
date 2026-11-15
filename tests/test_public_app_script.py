"""The public app launcher must not reuse stale tunnel state or hide a port conflict."""

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "public-app.sh"


class PublicAppScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        script_dir = self.base / "scripts"
        script_dir.mkdir()
        self.script = script_dir / "public-app.sh"
        self.script.write_bytes(SCRIPT.read_bytes())
        build_dir = self.base / "web" / ".next"
        build_dir.mkdir(parents=True)
        (build_dir / "BUILD_ID").write_text("existing-build\n")
        self.run_dir = self.base / "run"
        self.run_dir.mkdir()
        self.children = []
        fake_bin = self.base / "bin"
        fake_bin.mkdir()
        self._command(fake_bin, "curl", """#!/bin/sh
case " $* " in
  *"/api/auth/me"*) printf '%s' '{"multi_tenant": true, "real_service_diagnosis": false, "development": false}' ;;
  *"127.0.0.1:39991"*)
    [ "${MOCK_PORT_OCCUPIED:-0}" = 1 ] || [ -f "$VULNIX_APP_RUN_DIR/ready" ] ;;
esac
""")
        self._command(fake_bin, "cloudflared", """#!/bin/sh
printf '%s\\n' 'https://fresh-tunnel.trycloudflare.com'
exec /bin/sleep 60
""")
        self._command(fake_bin, "node", """#!/bin/sh
[ "${MOCK_WEB_FAIL:-0}" = 1 ] && exit 1
touch "$VULNIX_APP_RUN_DIR/ready"
exec /bin/sleep 60
""")
        self._command(fake_bin, "npm", """#!/bin/sh
printf '%s\\n' "$*" > "$VULNIX_APP_RUN_DIR/npm-invocation"
""")
        self._command(fake_bin, "sleep", "#!/bin/sh\nexec /bin/sleep 0.05\n")
        self.env = dict(os.environ, PATH=f"{fake_bin}:/usr/bin:/bin",
                        VULNIX_APP_RUN_DIR=str(self.run_dir), VULNIX_APP_PORT="39991",
                        VULNIX_APP_API="http://lab.test")
        self.addCleanup(self._kill_children)

    def _command(self, folder, name, body):
        path = folder / name
        path.write_text(body)
        path.chmod(0o755)

    def _kill_children(self):
        for name in ("web", "tunnel"):
            pid_file = self.run_dir / f"{name}.pid"
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGTERM)
                except (ValueError, ProcessLookupError):
                    pass
        for child in self.children:
            child.wait(timeout=2)

    def _run(self, action="start"):
        return subprocess.run(["/bin/sh", str(self.script), action], env=self.env,
                              text=True, capture_output=True, timeout=15)

    def test_running_tunnel_uses_its_latest_url(self):
        tunnel = subprocess.Popen(["/bin/sleep", "60"])
        self.children.append(tunnel)
        (self.run_dir / "tunnel.pid").write_text(f"{tunnel.pid}\n")
        (self.run_dir / "tunnel.log").write_text(
            "https://old-tunnel.trycloudflare.com\n"
            "https://fresh-tunnel.trycloudflare.com\n")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "https://fresh-tunnel.trycloudflare.com")
        self.assertEqual((self.run_dir / "url").read_text().strip(),
                         "https://fresh-tunnel.trycloudflare.com")

    def test_running_tunnel_prefers_recorded_url_over_old_log(self):
        tunnel = subprocess.Popen(["/bin/sleep", "60"])
        self.children.append(tunnel)
        (self.run_dir / "tunnel.pid").write_text(f"{tunnel.pid}\n")
        (self.run_dir / "tunnel.log").write_text("https://old-tunnel.trycloudflare.com\n")
        (self.run_dir / "url").write_text("https://current-tunnel.trycloudflare.com\n")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "https://current-tunnel.trycloudflare.com")

    def test_start_rebuilds_existing_web_build(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.run_dir / "npm-invocation").read_text().strip(), "run build")

    def test_untracked_server_on_port_is_refused_before_start(self):
        self.env["MOCK_PORT_OCCUPIED"] = "1"
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("39991", result.stdout)
        self.assertFalse((self.run_dir / "web.pid").exists())
        self.assertFalse((self.run_dir / "tunnel.pid").exists())

    def test_new_tunnel_is_stopped_if_web_fails_to_start(self):
        self.env["MOCK_WEB_FAIL"] = "1"
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Web サーバーが起動しませんでした", result.stdout)
        self.assertFalse((self.run_dir / "url").exists())
        self.assertFalse((self.run_dir / "tunnel.pid").exists())

    def test_status_does_not_show_url_of_stopped_tunnel(self):
        (self.run_dir / "url").write_text("https://old-tunnel.trycloudflare.com\n")
        result = self._run("status")
        self.assertEqual(result.returncode, 0)
        self.assertIn("tunnel: 停止", result.stdout)
        self.assertNotIn("https://old-tunnel.trycloudflare.com", result.stdout)


if __name__ == "__main__":
    unittest.main()
