"""Observe operator MFA with a pinned, network-free regression fixture."""

from __future__ import annotations

import argparse
import json
import platform
import secrets
import shutil
import signal
import socket
import sys
import tempfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from .artex_bridge import planner_hidden_paths
from .confinement import ConfinementError, KernelConfinement
from .runtime import RuntimeLimitError, WorkerPool, WorkerResult
from .workers.local_defense import REVIEWED_FILES, read_reviewed, sha256

# A changed test, its implementation, or any import in the reviewed closure needs
# a new review. This is a file-closure pin, not a claim about the rest of the tree.
PROFILE = {
    "id": "vulnix-operator-mfa",
    "review_revision": "8814523032a18eecbb4b8e05e8a2af7f7bce3527",
    "test": "TestStore.test_totp_enroll_then_login_requires_code",
    "conditions": ["A valid password and enrolled second factor permit login",
                   "An enrolled account rejects a missing or invalid second factor"],
    "files": REVIEWED_FILES,
}

MFA_CONDITIONS = {
    "valid_factor": "session",
    "missing_factor": "mfa_required",
    "invalid_factor": "mfa_required",
}


def _canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def build_snapshot(root: Path, snapshot: Path) -> None:
    copies = {name: read_reviewed(root, name) for name in PROFILE["files"]}
    snapshot.mkdir(mode=0o700)
    for name, data in copies.items():
        dest = snapshot / name
        dest.parent.mkdir(exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o444)
    # The worker's dedicated UID can read the snapshot but cannot modify it.
    for directory in (snapshot / "aegis", snapshot / "tests", snapshot):
        directory.chmod(0o555)


def mfa_observations(result: WorkerResult, isolated: bool) -> dict | None:
    if (not isolated or result.returncode != 0 or result.killed or result.timed_out
            or result.pipes_held or result.output_truncated or result.stderr):
        return None
    try:
        observation = json.loads(result.stdout)
    except ValueError:
        return None
    if not isinstance(observation, dict) or observation.get("observation") != "operator_mfa":
        return None
    conditions = observation.get("conditions")
    if (set(observation) != {"observation", "conditions", "regression"} or not isinstance(conditions, dict)
            or conditions.keys() != MFA_CONDITIONS.keys()
            or any(value not in ("session", "mfa_required") for value in conditions.values())
            or observation["regression"] not in ("passed", "failed", "unverified")):
        return None
    return observation


def classify_result(result: WorkerResult, isolated: bool) -> str:
    observation = mfa_observations(result, isolated)
    if observation is None:
        return "unverified"
    if observation["conditions"] != MFA_CONDITIONS:
        return "failed"
    return "passed" if observation["regression"] == "passed" else "unverified"


def reviewed_plan() -> dict:
    harness = Path(__file__).parent / "workers" / "local_defense.py"
    return {**PROFILE, "runner_sha256": sha256(harness.read_bytes()),
            "environment": "linux-namespaces-cgroup-seccomp",
            "timeout_seconds": 15}


def run(root: Path, plan: dict) -> dict:
    if plan != reviewed_plan():
        raise ValueError("execution plan differs from the reviewed plan")
    pool = WorkerPool(max_concurrent=1, cpu_seconds=10)
    confinement = KernelConfinement()
    report = {"run_id": secrets.token_hex(16), "plan": plan,
              "plan_sha256": sha256(_canonical(plan)), "verdict": "unverified"}
    try:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=False, prefix="vulnix-defense-") as tmp:
            # Keep the outer random directory traversable by the isolated UID.
            parent = Path(tmp)
            parent.chmod(0o711)
            snapshot = parent / "snapshot"
            build_snapshot(root, snapshot)
            try:
                with socket.socket() as reserved:
                    # The required loopback relay is pinned to this reserved endpoint.
                    # It is intentionally never put in listen mode.
                    reserved.bind(("127.0.0.1", 0))
                    port = reserved.getsockname()[1]
                    hidden = planner_hidden_paths((), ())
                    session = confinement.session("127.0.0.1", port,
                                                  limits={"memory.max": 256 << 20, "pids.max": 32},
                                                  namespaces={"hide": hidden, "keep": [snapshot]})
                    with session:
                        program = str(Path(__file__).resolve().parent / "workers" / "local_defense.py")
                        outcome = pool.run([sys.executable, "-I", "-B", program, str(snapshot)], plan["timeout_seconds"],
                                           session=session, extra_env={"VULNIX_NO_ENV_LOCAL": "1"})
                        live = session.still_enforced()
                    verified = live and not session.leftover and not session.netns_left
                    report.update(verdict=classify_result(outcome, verified), elapsed_ms=round(outcome.elapsed_s * 1000),
                                  confinement_verified=verified, kernel_release=platform.release() if verified else None,
                                  observation=mfa_observations(outcome, verified),
                                  observation_sha256=sha256(outcome.stdout.encode()) if verified else None)
            finally:
                for directory in (snapshot, snapshot / "aegis", snapshot / "tests"):
                    directory.chmod(0o755)
    except (ConfinementError, RuntimeLimitError, ValueError, OSError):
        report["reason"] = "reviewed source or isolated execution could not be established"
    finally:
        staged = confinement._staged
        if staged is not None:
            shutil.rmtree(staged, ignore_errors=True)
    return {**report, "report_sha256": sha256(_canonical(report))}


def junit_report(report: dict) -> str:
    verdict = report["verdict"]
    suite = Element("testsuite", tests="1", name="vulnix-reviewed-defense")
    properties = SubElement(suite, "properties")
    for key, value in {
        "vulnix.commit": report["plan"]["review_revision"],
        "vulnix.environment": "隔離した模擬環境",
        "vulnix.plan_sha256": report["plan_sha256"],
        "vulnix.report_sha256": report["report_sha256"],
    }.items():
        SubElement(properties, "property", name=key, value=value)
    case = SubElement(suite, "testcase", name=report["plan"]["test"])
    if verdict == "failed":
        SubElement(case, "failure", message="reviewed assertion failed")
    elif verdict != "passed":
        SubElement(case, "skipped", message="valid isolated observation unavailable")
    return tostring(suite, encoding="unicode")


def _interrupt(_signal, _frame) -> None:
    raise KeyboardInterrupt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="folder containing the reviewed source files")
    parser.add_argument("--approve", help="SHA-256 of the displayed plan")
    parser.add_argument("--junit", action="store_true", help="emit a JUnit receipt for manual import")
    args = parser.parse_args()
    plan = reviewed_plan()
    digest = sha256(_canonical(plan))
    if not args.approve:
        try:
            for name in REVIEWED_FILES:
                read_reviewed(args.source, name)
        except (OSError, ValueError):
            parser.error("selected folder does not match the reviewed source closure")
        print(json.dumps({"plan": plan, "plan_sha256": digest}, indent=2))
        return
    if args.approve != digest:
        parser.error("approval does not match this plan")
    previous = signal.signal(signal.SIGTERM, _interrupt)
    try:
        report = run(args.source, plan)
    except KeyboardInterrupt:
        parser.exit(130, "local defense cancelled\n")
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(junit_report(report) if args.junit else json.dumps(report, indent=2))
    if report["verdict"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
