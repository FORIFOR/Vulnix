"""Stage the one reviewed Linux arm64 Node.js bundle without fetching anything."""

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from .runtime import WorkerResult
from .workers.local_defense import read_reviewed, sha256

NODE_VERSION = "v22.23.5"
NODE_RELEASE = f"https://nodejs.org/dist/{NODE_VERSION}/"
NODE_EXE = f"node-{NODE_VERSION}-linux-arm64/bin/node"
NODE_PROFILE = {
    "id": "reviewed-node-d34b9f3",
    "review_revision": "d34b9f3fee37b361782ba757902c944b66bf1aeb",
    "test": "Reviewed Node.js application tests",
    "environment": "linux-arm64-namespaces-cgroup-seccomp",
    "timeout_seconds": 45,
    "memory_bytes": 768 << 20,
    "max_processes": 64,
    "runtime": {
        "version": NODE_VERSION,
        "distribution": NODE_RELEASE,
        "archive_sha256": "2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09",
        "binary_sha256": "bb71f797d1b3d156d012c59b152c413cf7d4940156cafcde28f1731201ceaf1c",
    },
    "source_manifest_sha256": "67c2e08d9fdee48fae47e8aeb5bbc171aa37087d9c6d3c54c005316cdb05ffd5",
    "selection_sha256": "574767e1fa396ccd524ce17d9a503d130339bd4f78ac6c2a1e24e9f8e920e2ed",
    "package_sha256": "67fcc4df0c220a4cff2f50cb1846afe93efd869bfe7117fe42f7519775b9e400",
    "lockfile_sha256": "738ed3950eb15bc12928c99f11f001f8fa17358e7149bb1a45c0e168bd0f3b97",
    "dependency_tree_sha256": "79478aeec0a414529d25345685fb5b4d5c4873604ce622660a2c22750d3e0980",
    "automatic_verdict": False,
}
DEPENDENCY_FILES = 18456
DEPENDENCY_BYTES = 450215438
RUN_CONFIG = Path(__file__).with_name("local_defense_vitest.mts")


def _copy_bounded(dfd: int, name: str, dest: Path, limit: int) -> tuple[str, int]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("bundle member exceeds its bounds or is not a regular file")
        size = 0
        with dest.open("xb") as out:
            while chunk := source.read(min(1 << 20, limit - size + 1)):
                size += len(chunk)
                if size > limit:
                    raise ValueError("bundle exceeds its byte limit")
                digest.update(chunk)
                out.write(chunk)
    return digest.hexdigest(), size


def _copy_dependencies(source: Path, dest: Path, permit=None) -> None:
    digests = {}
    total_size = 0
    directory_count = 0
    if source.is_symlink():
        raise ValueError("dependency root is a symlink")
    for directory, subdirs, files, fd in os.fwalk(source, follow_symlinks=False):
        if permit:
            permit()
        relative = Path(directory).relative_to(source)
        if not relative.parts and ".bin" in subdirs:
            subdirs.remove(".bin")
        directory_count += 1
        if (directory_count > DEPENDENCY_FILES
                or any(stat.S_ISLNK(os.stat(part, dir_fd=fd, follow_symlinks=False).st_mode)
                       for part in subdirs)):
            raise ValueError("unexpected dependency directories")
        output = dest / relative
        output.mkdir()
        for filename in files:
            if len(digests) >= DEPENDENCY_FILES:
                raise ValueError("dependency tree exceeds its file limit")
            digest, size = _copy_bounded(fd, filename, output / filename, DEPENDENCY_BYTES - total_size)
            total_size += size
            digests[(relative / filename).as_posix()] = digest
    tree = hashlib.sha256()
    for name, digest in sorted(digests.items(), key=lambda item: Path(item[0]).parts):
        tree.update(name.encode() + b"\0" + digest.encode() + b"\n")
    if (len(digests) != DEPENDENCY_FILES or total_size != DEPENDENCY_BYTES
            or tree.hexdigest() != NODE_PROFILE["dependency_tree_sha256"]):
        raise ValueError("dependency tree digest differs from reviewed bundle")


def stage_node_snapshot(bundle: Path, snapshot: Path, *, permit=None, config_sha256=None) -> list[str]:
    manifest = reviewed_manifest(bundle)
    selection = json.loads(read_reviewed(bundle, "selection.json", NODE_PROFILE["selection_sha256"]))
    snapshot.mkdir()
    for name, digest in manifest.items():
        data = read_reviewed(bundle, "reviewed/" + name, digest)
        dest = snapshot / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    for name, key in (("package.json", "package_sha256"), ("package-lock.json", "lockfile_sha256")):
        (snapshot / name).write_bytes(read_reviewed(bundle, "dependencies/" + name, NODE_PROFILE[key]))
    runtime = bundle / NODE_EXE
    fd = os.open(runtime.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        digest, _ = _copy_bounded(fd, runtime.name, snapshot / "node", 140 << 20)
    finally:
        os.close(fd)
    if digest != NODE_PROFILE["runtime"]["binary_sha256"]:
        raise ValueError("Node runtime digest differs from reviewed bundle")
    _copy_dependencies(bundle / "dependencies/node_modules", snapshot / "node_modules", permit=permit)
    config = RUN_CONFIG.read_bytes()
    if config_sha256 is not None and sha256(config) != config_sha256:
        raise ValueError("Node runner configuration changed after the plan was approved")
    (snapshot / "vitest.config.mts").write_bytes(config)
    for directory, _, files in os.walk(snapshot, topdown=False):
        for name in files:
            path = Path(directory) / name
            path.chmod(0o555 if path == snapshot / "node" else 0o444)
        Path(directory).chmod(0o555)
    return [
        sys.executable, "-I", "-c",
        "import os,sys; os.chdir(sys.argv[1]); os.execv(sys.argv[2],sys.argv[2:])",
        str(snapshot), str(snapshot / "node"), str(snapshot / "node_modules/vitest/vitest.mjs"), "run",
        "--config", "vitest.config.mts", "--configLoader", "native", "--pool=threads",
        "--maxWorkers=1", "--no-cache", "--reporter=json", *selection["tests"], "-t", selection["name_pattern"],
    ]


def node_plan() -> dict:
    return {**NODE_PROFILE, "runner_sha256": sha256(Path(__file__).read_bytes()),
            "runner_config_sha256": sha256(RUN_CONFIG.read_bytes())}


def reviewed_manifest(bundle: Path) -> dict:
    return json.loads(read_reviewed(bundle, "reviewed/snapshot-manifest.json",
                                    NODE_PROFILE["source_manifest_sha256"]))


def observation_summary(result: WorkerResult, isolated: bool) -> dict | None:
    """A reviewed test-run summary, kept separate from defence verdicts."""
    if (not isolated or result.returncode != 0 or result.killed or result.timed_out
            or result.pipes_held or result.output_truncated):
        return None
    try:
        report = json.loads(result.stdout)
    except ValueError:
        return None
    required = {"numPassedTests": 10, "numFailedTests": 0, "numPendingTests": 6, "numTotalTests": 16}
    if (not isinstance(report, dict) or report.get("success") is not True
            or any(type(report.get(key)) is not int or report[key] != count for key, count in required.items())):
        return None
    return {"passed": 10, "excluded": 6}
