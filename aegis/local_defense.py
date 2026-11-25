"""Run reviewed defence checks with the network-isolated Worker."""

from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import sys
import tempfile
from contextlib import nullcontext
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from .artex_bridge import planner_hidden_paths
from .confinement import ConfinementError, KernelConfinement
from .local_defense_node import (NODE_PROFILE, OBSERVATION_CHECKS, OBSERVER, node_plan,
                                 observation_summary, stage_node_snapshot, vitest_command)
from .local_defense_profile import case_verdicts
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


def run(root: Path, plan: dict, *, portable=None, pool=None, hold_session=None,
        permit=None, prelaunch=None) -> dict:
    is_node = plan.get("id") == NODE_PROFILE["id"]
    expected = portable.plan() if portable else node_plan(root) if is_node else reviewed_plan()
    if plan != expected:
        raise ValueError("execution plan differs from the reviewed plan")
    if pool is None:
        pool = WorkerPool(max_concurrent=1, cpu_seconds=20 if is_node else 10)
    confinement = KernelConfinement()
    report = {"run_id": secrets.token_hex(16), "plan": plan,
              "plan_sha256": sha256(_canonical(plan)), "verdict": "unverified",
              "execution_status": "failed"}
    try:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=False, prefix="vulnix-defense-") as tmp:
            # Keep the outer random directory traversable by the isolated UID.
            parent = Path(tmp)
            parent.chmod(0o711)
            snapshot = parent / "snapshot"
            try:
                if permit:
                    permit()
                if portable:
                    argv = portable.stage(snapshot, plan, permit)
                elif is_node:
                    if sys.platform != "linux" or platform.machine() != "aarch64":
                        raise ValueError("the reviewed Node runtime requires Linux arm64")
                    argv = stage_node_snapshot(root, snapshot, permit=permit, config_sha256=plan["runner_config_sha256"],
                                               observer="observer_sha256" in plan)
                else:
                    build_snapshot(root, snapshot)
                    program = str(Path(__file__).resolve().parent / "workers" / "local_defense.py")
                    argv = [sys.executable, "-I", "-B", program, str(snapshot)]
                with socket.socket() as reserved:
                    # The required loopback relay is pinned to this reserved endpoint.
                    # It is intentionally never put in listen mode.
                    reserved.bind(("127.0.0.1", 0))
                    port = reserved.getsockname()[1]
                    hidden = planner_hidden_paths((), ())
                    session = confinement.session("127.0.0.1", port, limits={
                                                      "memory.max": plan.get("memory_bytes", 256 << 20),
                                                      "pids.max": plan.get("max_processes", 32),
                                                  },
                                                  namespaces={"hide": hidden, "keep": [snapshot]})
                    guard = hold_session(session) if hold_session else nullcontext()
                    node_observation = None
                    with guard, session:
                        def check_launch():
                            if permit:
                                permit()
                            if not is_node and not portable:
                                staged = confinement._staged
                                if (staged is None or sha256((staged / "local_defense.py").read_bytes())
                                        != plan["runner_sha256"]):
                                    raise RuntimeLimitError("reviewed Worker different from plan")
                        env = {
                            "VULNIX_NO_ENV_LOCAL": "1", "HOME": "/nonexistent", "TMPDIR": "/tmp", "NO_COLOR": "1",
                        }
                        outcome = pool.run(argv, plan["timeout_seconds"], session=session, extra_env=env,
                                           permit=check_launch, prelaunch=prelaunch)
                        remaining = plan["timeout_seconds"] - outcome.elapsed_s
                        if is_node and "observer_sha256" in plan and remaining > 0 and not outcome.killed:
                            node_observation = pool.run([*vitest_command(snapshot), "--reporter=dot", "src/lib/" + OBSERVER],
                                                        remaining, session=session, extra_env=env,
                                                        permit=check_launch, prelaunch=prelaunch)
                        live = session.still_enforced()
                    verified = live and not (session.leftover or session.netns_left or session.files_left)
                    if portable:
                        observation, verdict = evaluate_pairs(outcome, verified, portable.manifest())
                        report["verdict"] = verdict
                    elif is_node:
                        observation = observation_summary(outcome, verified)
                        if "observer_sha256" in plan:
                            checks, verdict = evaluate_pairs(node_observation, verified, {"checks": OBSERVATION_CHECKS},
                                                             prefix="VULNIX_OBSERVATIONS ")
                            observation = {**(observation or {}), **checks}
                            report["verdict"] = verdict
                    else:
                        observation = mfa_observations(outcome, verified)
                        report["verdict"] = classify_result(outcome, verified)
                    report.update(execution_status="completed" if observation is not None else "unverified",
                                  elapsed_ms=round((outcome.elapsed_s + (node_observation.elapsed_s if node_observation else 0)) * 1000),
                                  confinement_verified=verified, kernel_release=platform.release() if verified else None,
                                  observation=observation,
                                  observation_sha256=sha256(_canonical(observation)) if observation is not None and verified else None)
            finally:
                for directory, _, _ in os.walk(snapshot):
                    Path(directory).chmod(0o755)
    except (ConfinementError, RuntimeLimitError, ValueError, OSError):
        report.update(execution_status="failed", verdict="unverified", observation=None,
                      observation_sha256=None, confinement_verified=False,
                      reason="reviewed source or isolated execution could not be established")
    finally:
        staged = confinement._staged
        if staged is not None:
            try:
                shutil.rmtree(staged)
            except OSError:
                report.update(execution_status="failed", verdict="unverified", observation=None,
                              observation_sha256=None, confinement_verified=False,
                              reason="could not remove the staged Worker")
    return {**report, "report_sha256": sha256(_canonical(report))}


def _unique_keys(entries):
    result = dict(entries)
    if len(result) != len(entries):
        raise ValueError("duplicate observation keys")
    return result


def evaluate_pairs(outcome, isolated, manifest, *, prefix=None):
    values = None
    if (isolated and outcome and outcome.returncode == 0 and not outcome.killed and not outcome.timed_out
            and not outcome.pipes_held and not outcome.output_truncated and not outcome.stderr):
        try:
            raw = outcome.stdout
            if prefix:
                rows = [line.strip()[len(prefix):] for line in raw.splitlines() if line.strip().startswith(prefix)]
                raw = rows[0] if len(rows) == 1 else ""
            data = json.loads(raw, object_pairs_hook=_unique_keys)
            if isinstance(data, dict) and data.keys() == manifest["checks"].keys():
                values = data
        except ValueError:
            pass
    verdicts = case_verdicts(manifest, values)
    observations = {}
    for category, verdict in verdicts.items():
        pair = values.get(category) if values is not None else None
        observations[category] = {"verdict": verdict}
        if verdict != "unverified":
            observations[category]["observed"] = pair
    overall = "failed" if "failed" in verdicts.values() else "unverified" if (
        "unverified" in verdicts.values()) else "passed"
    return {"checks": observations}, overall


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
    parser.add_argument("--node", action="store_true", help="use the reviewed Node.js bundle layout")
    parser.add_argument("--approve", help="SHA-256 of the displayed plan")
    parser.add_argument("--junit", action="store_true", help="emit a JUnit receipt for manual import")
    args = parser.parse_args()
    plan = node_plan(args.source) if args.node else reviewed_plan()
    digest = sha256(_canonical(plan))
    if not args.approve:
        try:
            if args.node:
                read_reviewed(args.source, "reviewed/snapshot-manifest.json", plan["source_manifest_sha256"])
            else:
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
    if (report["execution_status"] != "completed" if args.node and not plan["automatic_verdict"]
            else report["verdict"] != "passed"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
