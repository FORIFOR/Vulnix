"""Source-only inventory of the Vulnix request flow (no imports or network calls).

Run from the repository root: python3 scripts/flow_inventory.py > docs/PROCESS_INVENTORY.json
This deliberately reads only tracked source paths, never local configuration or data.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = sorted((ROOT / "aegis").glob("*.py")) + sorted((ROOT / "aegis/workers").glob("*.py"))
FRONTEND = sorted((ROOT / "web/src").rglob("*.ts")) + sorted((ROOT / "web/src").rglob("*.tsx"))
ARTEX_GO = sorted((ROOT / "integrations/artex/overlay").rglob("*.go"))
ROUTE_METHODS = {"do_GET": "GET", "_get_org": "GET", "_tenancy_get": "GET",
                 "do_POST": "POST", "_dispatch": "POST", "_tenancy_post": "POST"}
NETWORK_CALLS = {"urlopen", "getaddrinfo", "create_connection", "Popen", "run", "fetch"}


def node_text(node: ast.AST) -> str:
    return ast.unparse(node).replace("\n", " ")


def route_literals(node: ast.AST) -> list[str]:
    values = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if child.value.startswith("/api/") or child.value.startswith("/assets/"):
                values.append(child.value)
        elif isinstance(child, ast.JoinedStr):
            rendered = node_text(child)
            if "/api/" in rendered:
                values.append(rendered)
    return sorted(set(values))


def inventory_python(path: Path) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    rel = str(path.relative_to(ROOT))
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    functions, routes, network, jobs = [], [], [], []

    def visit(body: list[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + node.name
                functions.append({"file": rel, "line": node.lineno, "name": name})
                if node.name in ROUTE_METHODS and rel == "aegis/server.py":
                    for branch in ast.walk(node):
                        if not isinstance(branch, ast.If):
                            continue
                        test = node_text(branch.test)
                        if not re.search(r"\bp\b|\bpath\b", test):
                            continue
                        routes.append({"method": ROUTE_METHODS[node.name], "file": rel,
                                       "line": branch.lineno, "handler": name,
                                       "condition": test, "literals": route_literals(branch.test)})
                for child in ast.walk(node):
                    if not isinstance(child, ast.Call):
                        continue
                    call = node_text(child.func)
                    last = call.rsplit(".", 1)[-1]
                    if last in NETWORK_CALLS and last != "run":
                        network.append({"file": rel, "line": child.lineno, "function": name, "call": call})
                    elif last == "run" and ("subprocess" in call or rel.endswith("runtime.py")):
                        network.append({"file": rel, "line": child.lineno, "function": name, "call": call})
                    if last in {"Thread", "Timer", "start"} and (last != "start" or "thread" in call.lower()):
                        jobs.append({"file": rel, "line": child.lineno, "function": name, "call": call})
                visit(node.body, name + ".")

    visit(tree.body)
    return functions, routes, network, jobs


def main() -> None:
    functions, routes, network, jobs = [], [], [], []
    for path in BACKEND:
        a, b, c, d = inventory_python(path)
        functions.extend(a); routes.extend(b); network.extend(c); jobs.extend(d)
    def unique(items: list[dict], fields: tuple[str, ...]) -> list[dict]:
        seen = set()
        result = []
        for item in items:
            key = tuple(item[field] for field in fields)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result
    network = unique(network, ("file", "line", "call"))
    jobs = unique(jobs, ("file", "line", "call"))
    web_api, web_functions = [], []
    for path in FRONTEND:
        rel = str(path.relative_to(ROOT))
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "/api/" in line or "new EventSource" in line:
                web_api.append({"file": rel, "line": line_no, "source": line.strip()[:220]})
            if match := re.search(r"\b(?:export\s+)?(?:async\s+)?function\s+(\w+)|\bconst\s+(\w+)\s*=\s*(?:async\s*)?\(", line):
                web_functions.append({"file": rel, "line": line_no, "name": match.group(1) or match.group(2)})
    artex_functions = []
    for path in ARTEX_GO:
        rel = str(path.relative_to(ROOT))
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if match := re.match(r"^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(", line):
                artex_functions.append({"file": rel, "line": line_no, "name": match.group(1)})
    print(json.dumps({"schema": 1, "source": "AST and text; conditional routes may be dynamic",
                      "backend_functions": functions, "route_conditions": routes,
                      "network_process_calls": network, "background_jobs": jobs,
                      "web_api_references": web_api, "web_functions": web_functions,
                      "artex_go_functions": artex_functions}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
