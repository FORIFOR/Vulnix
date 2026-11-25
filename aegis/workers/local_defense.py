"""Isolated worker entry point for the fixed operator MFA test."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import unittest
from pathlib import Path


REVIEWED_FILES = {
    "aegis/__init__.py": "e24858a2a64396b86cab192042252eaaabc69f47576c9c68b6d9a885becb39b1",
    "aegis/operators.py": "78b9e01cc57b299c69f23624e2dd3fd9f9566ee4278a475934f9ae78f7a24c48",
    "aegis/grant_lease.py": "e72333edebac75d22478ceeef71020d5ab78dc1e229a062056fa8da04362dff9",
    "tests/test_operators.py": "7372925183b7d2349904c80e0a3dbe4f79201433f8554d634ced41efe85690ab",
}
MAX_SOURCE_BYTES = 512 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_reviewed(root: Path, name: str) -> bytes:
    """Open the fixed path from a pinned root descriptor without following links."""
    directory = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parts = name.split("/")
    fd = os.open(root, directory)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(leaf, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
                raise ValueError("reviewed source is not a bounded regular file")
            data = handle.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES or sha256(data) != REVIEWED_FILES[name]:
            raise ValueError("reviewed source digest differs")
        return data
    except OSError as error:
        raise ValueError("reviewed source cannot be opened safely") from error
    finally:
        os.close(fd)



def restrict(event, _args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn", "os.fork", "os.posix_spawn", "os.system")):
        raise PermissionError("offline defense fixture")


def main():
    snapshot = Path(sys.argv[1])
    for directory in (snapshot, snapshot / "aegis", snapshot / "tests"):
        expected = ({name.split("/")[0] for name in REVIEWED_FILES} if directory == snapshot else
                    {name.split("/")[1] for name in REVIEWED_FILES if name.startswith(directory.name + "/")})
        if directory.is_symlink() or os.access(directory, os.W_OK) or set(os.listdir(directory)) != expected:
            raise ValueError("unexpected content in reviewed snapshot")
    for name in REVIEWED_FILES:
        if os.access(snapshot / name, os.W_OK):
            raise ValueError("reviewed source is writable by the worker")
        read_reviewed(snapshot, name)
    sys.addaudithook(restrict)
    sys.path.insert(0, str(snapshot))
    test = importlib.util.spec_from_file_location("reviewed_operator_test", snapshot / "tests/test_operators.py")
    if test is None or test.loader is None:
        return
    module = importlib.util.module_from_spec(test)
    test.loader.exec_module(module)
    case = module.TestStore("test_totp_enroll_then_login_requires_code")
    result = unittest.TextTestRunner(stream=io.StringIO()).run(case)
    outcome = "unverified"
    if result.testsRun == 1 and not (result.skipped or result.errors or result.expectedFailures or result.unexpectedSuccesses):
        outcome = "failed" if result.failures else "passed"
    print(json.dumps({"observation": "completed", "outcome": outcome}))


if __name__ == "__main__":
    main()
