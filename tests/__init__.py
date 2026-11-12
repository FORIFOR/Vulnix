"""Test-suite wiring shared by every module.

* Revocation markers (written when a revocation cannot be saved in the data
  directory) go to a throw-away directory, never to the developer's home.
* `TEST_CONFINEMENT` stands in for kernel confinement of the L2 worker so that
  the L2 flow can be exercised on any OS - against loopback stand-ins ONLY. It
  refuses every non-loopback destination, and it can be handed to the service
  only through its constructor (there is no environment variable or API for it).
  The real confinement is tested in tests/test_fail_closed.py.
"""
import ipaddress
import os
import tempfile

os.environ.setdefault("VULNIX_REVOCATION_MARKER_DIR", tempfile.mkdtemp(prefix="vulnix-test-markers-"))


class _LoopbackSession:
    evidence = {"mechanism": "test stand-in (loopback only)"}
    leftover = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def wrap(self, argv, env_keys=(), cpu_seconds=60):
        return list(argv)

    def still_enforced(self):
        return True

    def kill(self):
        return None

    def empty(self):
        return True


class LoopbackTestConfinement:
    def __init__(self):
        self.sessions = []

    def status(self):
        return {"ok": True, "reason": "", "mechanism": "test stand-in (loopback only)"}

    def session(self, ip, port, **checks):
        from aegis.confinement import ConfinementError
        if not ipaddress.ip_address(ip).is_loopback:
            raise ConfinementError("the test stand-in confines nothing: loopback targets only")
        self.sessions.append((ip, int(port)))
        return _LoopbackSession()


TEST_CONFINEMENT = LoopbackTestConfinement()
