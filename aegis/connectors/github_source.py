"""Local pinned checkout gate. GitHub App connectivity is not enabled."""
import re
import subprocess
from pathlib import Path


def open_pinned_local_checkout(root: Path, commit_sha: str) -> Path:
    root = root.resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise ValueError("full commit SHA required")
    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                              text=True, check=True, timeout=10).stdout.strip()
    if git("rev-parse", "--show-toplevel") != str(root):
        raise ValueError("root must be checkout top level")
    if git("rev-parse", "HEAD") != commit_sha:
        raise ValueError("checkout SHA mismatch")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("checkout must be clean")
    if git("submodule", "status"):
        raise ValueError("submodules not supported")
    return root


def read_pinned_file(root: Path, commit_sha: str, relative_path: str) -> str:
    """Read the commit blob, not a mutable working tree file."""
    path = Path(relative_path)
    if path.is_absolute() or ".." in path.parts or not relative_path or not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise ValueError("invalid pinned source reference")
    raw = subprocess.run(["git", "-C", str(root), "show", f"{commit_sha}:{relative_path}"],
                         capture_output=True, check=True, timeout=10).stdout
    if len(raw) > 1_000_000:
        raise ValueError("source file too large")
    return raw.decode("utf-8")
