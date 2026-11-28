"""Test-suite wiring shared by every module.

* Revocation markers (written when a revocation cannot be saved in the data
  directory) go to a throw-away directory, never to the developer's home.
* `TEST_CONFINEMENT` stands in for kernel confinement of the L2 worker so that
  the L2 flow can be exercised on any OS - against loopback stand-ins ONLY. It
  refuses every non-loopback destination, and it can be handed to the service
  only through its constructor (there is no environment variable or API for it).
  The real confinement is tested in tests/test_fail_closed.py.
* `VULNIX_NO_ENV_LOCAL=1`: the project's .env.local is never read during tests.
"""
import functools
import ipaddress
import os
import socketserver
import tempfile

os.environ.setdefault("VULNIX_REVOCATION_MARKER_DIR", tempfile.mkdtemp(prefix="vulnix-test-markers-"))
# Never load the developer's git-ignored .env.local (it may hold a real API key) into a
# test run or into a server a test starts.
os.environ.setdefault("VULNIX_NO_ENV_LOCAL", "1")

# In-process loopback servers: shutdown() waits for the serve_forever() poll, 0.5 s by
# default, and the suite starts and stops hundreds of them. A short poll changes only
# how quickly a stopped test server notices; request handling is unaffected.
_serve_forever = socketserver.BaseServer.serve_forever


@functools.wraps(_serve_forever)
def _serve_forever_fast(self, poll_interval=0.02):
    return _serve_forever(self, poll_interval)


socketserver.BaseServer.serve_forever = _serve_forever_fast


class _LoopbackSession:
    evidence = {"mechanism": "test stand-in (loopback only)"}
    leftover = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def wrap(self, argv, env_keys=(), cpu_seconds=60, **_kw):
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
        self.last_checks = dict(checks)
        return _LoopbackSession()


TEST_CONFINEMENT = LoopbackTestConfinement()


def l2_requested_by_another(requester: str = "op"):
    """Class decorator for tests of OTHER properties of a real-site L2 run (boundary
    proofs, token scrubbing, confinement, persistence...). Separation of duties is on by
    default and always on for a real site: an L2 run needs a request by a different
    operator first. Before a human approver calls `verify_finding`, this files that
    request as `requester` (never the approver). It is applied per class, never to a
    shared base, so the separation tests themselves (tests/test_l2_separation_default.py,
    tests/test_access_control.py) see the rule unaided."""
    from unittest.mock import patch

    def decorate(cls):
        from aegis.assessment import AssessmentService
        real = AssessmentService.verify_finding

        def verify_finding(svc, finding_id, actor, *args, **kwargs):
            if actor and actor != requester and not str(actor).startswith("policy:"):
                ids = list(svc.a.findings) if finding_id == "all" else [finding_id]
                for fid in ids:
                    try:
                        svc.request_l2_run(fid, requester)
                    except Exception:   # not a requestable L2 item: verify_finding answers for itself
                        pass
            return real(svc, finding_id, actor, *args, **kwargs)

        real_fix = AssessmentService.verify_fix

        def verify_fix(svc, actor, *args, **kwargs):
            # a re-verification re-runs an L2 item only on a fresh request by another person
            if actor and actor != requester and not str(actor).startswith("policy:"):
                for fid in list(svc.a.findings):
                    try:
                        svc.request_l2_run(fid, requester)
                    except Exception:
                        pass
            return real_fix(svc, actor, *args, **kwargs)

        original_setup = cls.setUp

        def setUp(self):
            for name, fn in (("verify_finding", verify_finding), ("verify_fix", verify_fix)):
                p = patch.object(AssessmentService, name, fn)
                p.start()
                self.addCleanup(p.stop)
            original_setup(self)

        cls.setUp = setUp
        return cls
    return decorate
