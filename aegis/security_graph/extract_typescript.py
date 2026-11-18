"""TypeScript AST bridge to the pinned local TypeScript compiler package."""
import json
import shutil
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "web" / "tools" / "extract-typescript.mjs"
TYPESCRIPT = SCRIPT.parent.parent / "node_modules" / "typescript"


def extract_route(source: str, source_path: str) -> list[dict] | None:
    """Return None when the parser is unavailable or rejects input.

    The source is passed on stdin to a trusted AST parser, never executed.
    """
    node = shutil.which("node")
    if not node or not TYPESCRIPT.is_dir() or len(source.encode("utf-8")) > 1_000_000:
        return None
    try:
        proc = subprocess.run([node, str(SCRIPT), source_path], input=source,
                              text=True, capture_output=True, timeout=5, check=False,
                              env={"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "NODE_NO_WARNINGS": "1"})
        if proc.returncode or len(proc.stdout) > 128_000:
            return None
        parsed = json.loads(proc.stdout)
        if not isinstance(parsed, dict) or parsed.get("parse_ok") is not True or not isinstance(parsed.get("routes"), list):
            return None
        routes = parsed["routes"]
        if len(routes) > 20:
            return None
        for route in routes:
            if not isinstance(route, dict) or set(route) != {"method", "line", "handler", "auth", "data", "guard_status"}:
                return None
            if (route["method"] not in {"GET", "POST", "PUT", "PATCH", "DELETE"} or
                type(route["line"]) is not int or route["line"] < 1 or
                route["guard_status"] not in {"unknown", "guard_observed"}):
                return None
            for key in ("auth", "data"):
                if not isinstance(route[key], list) or len(route[key]) > 50:
                    return None
                for item in route[key]:
                    if (not isinstance(item, dict) or set(item) != {"name", "line"} or
                        type(item["name"]) is not str or len(item["name"]) > 160 or
                        type(item["line"]) is not int or item["line"] < 1):
                        return None
        return routes
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
        return None
