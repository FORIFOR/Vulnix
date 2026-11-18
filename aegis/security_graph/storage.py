"""Per-tenant storage must be supplied by TenantRegistry's service caller."""
import json
import os
from dataclasses import asdict
from pathlib import Path
from .models import SecurityGraph
from .sqlite_store import GraphStore


def write_graph(graph: SecurityGraph, destination: Path) -> None:
    """Persist metadata only; caller supplies a tenant-scoped destination."""
    if destination.name != "security-graph.json" or destination.is_symlink():
        raise ValueError("invalid graph destination")
    raw = json.dumps(asdict(graph), ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(raw) > 1_000_000:
        raise ValueError("graph too large")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = destination.with_suffix(destination.suffix + ".tmp")
    if tmp.is_symlink():
        raise ValueError("symlink temporary file rejected")
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    os.replace(tmp, destination)


def write_report(report: dict, destination: Path) -> None:
    """Write a metadata-only report into a caller-supplied tenant directory."""
    if destination.name != "research-report.json" or destination.is_symlink():
        raise ValueError("invalid report destination")
    raw = json.dumps(report, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(raw) > 256_000:
        raise ValueError("report too large")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = destination.with_suffix(".json.tmp")
    if tmp.is_symlink():
        raise ValueError("symlink temporary file rejected")
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    os.replace(tmp, destination)


def read_report(destination: Path) -> dict:
    if destination.name != "research-report.json" or destination.is_symlink():
        raise ValueError("invalid report destination")
    if not destination.exists():
        return {"status": "not_available"}
    if destination.stat().st_size > 256_000:
        raise ValueError("report too large")
    fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(256_001)
    if len(raw) > 256_000:
        raise ValueError("report too large")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("invalid report")
    return data
