"""Conservative local Python AST indexing; unsupported code remains unknown."""
import ast
import hashlib
import re
import subprocess
from pathlib import Path

from aegis.connectors.github_source import read_pinned_file
from .extract_ai_tools import extract_mcp_tools
from .extract_typescript import extract_route
from .models import Evidence, GraphEdge, GraphNode, SecurityGraph

_SHA = re.compile(r"[0-9a-f]{40}")
_SKIP = {".git", ".next", "node_modules", "data", "venv", ".venv", "__pycache__", "tests", "fixtures"}
_METHODS = {"get", "post", "put", "patch", "delete"}
_ORG_FIELDS = {"org_id", "orgId"}
_RESOURCE_NAMES = {"order", "resource"}
_IDENTITY_NAMES = {"identity", "session", "user"}


def _name(expr):
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return f"{_name(expr.value)}.{expr.attr}"
    return ""


def _call_names(tree):
    calls = []

    class DirectCalls(ast.NodeVisitor):
        def visit_Call(self, node):
            calls.append((_name(node.func), node.lineno))
            if isinstance(node.func, ast.Lambda):
                # This lambda executes now; a lambda merely assigned to a
                # variable does not. Keep the direct call without treating
                # every nested callable as part of the handler.
                self.visit(node.func.body)
            self.generic_visit(node)

        def visit_FunctionDef(self, node):
            pass  # A nested callable has not been invoked by the handler.

        visit_AsyncFunctionDef = visit_FunctionDef
        visit_Lambda = visit_FunctionDef
        visit_ClassDef = visit_FunctionDef

    DirectCalls().visit(tree)
    return calls


def _org_owner(expr: ast.expr) -> str:
    if isinstance(expr, ast.Attribute) and expr.attr in _ORG_FIELDS and isinstance(expr.value, ast.Name):
        base = expr.value.id
    elif (isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Name) and
          isinstance(expr.slice, ast.Constant) and expr.slice.value in _ORG_FIELDS):
        base = expr.value.id
    else:
        return ""
    if base in _RESOURCE_NAMES:
        return "resource"
    if base in _IDENTITY_NAMES:
        return "identity"
    return ""


def _guarded(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Recognize only explicit resource/identity comparison followed by rejection.

    Other middleware and dynamic checks are unknown. This is not proof of safety.
    """
    for node in fn.body:
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
                len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.NotEq)):
            owners = {_org_owner(node.test.left), _org_owner(node.test.comparators[0])}
            # A nested branch may reject only some mismatches. Recognize a guard
            # only when the mismatch branch itself raises unconditionally.
            reject = bool(node.body) and isinstance(node.body[0], ast.Raise)
            if owners == {"resource", "identity"} and reject:
                return True
        if any(isinstance(item, ast.Return) for item in ast.walk(node)):
            return False  # a prior exit may bypass a later guard
    return False


def build_graph(root: Path, commit_sha: str) -> SecurityGraph:
    """Index an explicitly supplied local checkout at a caller-pinned commit.

    The caller is responsible for authorizing the source and checking that the
    checkout actually matches commit_sha. This function never fetches a repo.
    """
    root = root.resolve(strict=True)
    if not root.is_dir() or not _SHA.fullmatch(commit_sha):
        raise ValueError("local checkout and full commit SHA required")
    nodes: list[GraphNode] = []
    node_index: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    evidence: dict[str, Evidence] = {}

    def add_evidence(path: str, line: int, lines: list[str]) -> str:
        raw = lines[line - 1] if 0 < line <= len(lines) else ""
        eid = hashlib.sha256(f"{commit_sha}:{path}:{line}:{raw}".encode()).hexdigest()[:20]
        evidence[eid] = Evidence(eid, path, line, commit_sha, hashlib.sha256(raw.encode()).hexdigest())
        return eid

    def add_node(kind, name, path, line, lines, status="observed"):
        eid = add_evidence(path, line, lines)
        nid = f"{kind}:{path}:{line}:{name}"
        if nid in node_index:
            return node_index[nid]
        node = GraphNode(nid, kind, name, path, line, commit_sha, (eid,), status)
        nodes.append(node)
        node_index[nid] = node
        return node

    if (root / ".git").exists():
        listed = subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "-z"],
                                capture_output=True, check=True, timeout=10).stdout
        files = [root / name.decode("utf-8", "surrogateescape") for name in listed.split(b"\0") if name]
        pinned = True
    else:
        # Only for the explicit non-Git test fixtures. Production callers use
        # open_pinned_local_checkout and therefore index tracked files only.
        files = list(root.rglob("*"))
        pinned = False
    for file in sorted(files):
        if not file.is_relative_to(root):
            continue
        parts = file.relative_to(root).parts
        if (any(part in _SKIP or part.startswith("data") or part.startswith(".env") for part in parts[:-1])
                or parts[-1].startswith(".env") or parts[-1].endswith(".key")
                or parts[-1] in {"operators.json", "initial_accounts.json", "initial_accounts.py"}):
            continue
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 1_000_000:
            continue
        path = file.relative_to(root).as_posix()
        if file.name in {"route.ts", "route.tsx"} and "app" in file.parts:
            try:
                source = read_pinned_file(root, commit_sha, path) if pinned else file.read_text(encoding="utf-8")
            except (UnicodeError, OSError):
                add_node("route", path, path, 1, [], "unknown")
                continue
            lines = source.splitlines()
            routes = extract_route(source, path)
            if not routes:
                add_node("route", path, path, 1, lines, "unknown")
                continue
            parts = file.relative_to(root).parts
            app_index = parts.index("app")
            url_parts = parts[app_index + 1:-1]
            url_parts = ["{" + item[1:-1] + "}" if item.startswith("[") and item.endswith("]") else item
                         for item in url_parts]
            route_path = "/" + "/".join(url_parts)
            for item in routes:
                line = item["line"]
                route = add_node("route", f"{item['method']} {route_path}", path, line, lines)
                handler = add_node("handler", item["handler"], path, line, lines, item["guard_status"])
                edges.append(GraphEdge(route.id, handler.id, "EXPOSES", 1.0,
                                       route.evidence_ids, path, line, commit_sha))
                for call in item["auth"]:
                    identity = add_node("identity", call["name"], path, call["line"], lines, "unknown")
                    edges.append(GraphEdge(handler.id, identity.id, "CALLS", 0.9,
                                           tuple(dict.fromkeys((*handler.evidence_ids, *identity.evidence_ids))),
                                           path, call["line"], commit_sha))
                for call in item["data"]:
                    resource = add_node("resource", call["name"], path, call["line"], lines, "unknown")
                    edges.append(GraphEdge(handler.id, resource.id, "READS", 0.8,
                                           tuple(dict.fromkeys((*handler.evidence_ids, *resource.evidence_ids))),
                                           path, call["line"], commit_sha))
            continue
        if file.suffix != ".py":
            continue
        try:
            source = read_pinned_file(root, commit_sha, path) if pinned else file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=path)
        except (UnicodeError, SyntaxError):
            add_node("repository", path, path, 1, [], "unknown")
            continue
        except OSError:
            continue
        lines = source.splitlines()
        imports: dict[str, tuple[str, int]] = {}
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    imports[alias.asname or alias.name] = (statement.module, statement.lineno)
            elif isinstance(statement, ast.Import):
                for alias in statement.names:
                    imports[alias.asname or alias.name.split(".")[0]] = (alias.name, statement.lineno)
        tool_registrations = extract_mcp_tools(tree)
        for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            route_decorators = [d for d in fn.decorator_list if isinstance(d, ast.Call) and
                                _name(d.func).split(".")[-1] in _METHODS]
            tool_registration = tool_registrations.get(fn)
            if not route_decorators and tool_registration is None:
                continue
            handler = add_node("handler", fn.name, path, fn.lineno, lines,
                               "guard_observed" if route_decorators and _guarded(fn) else "unknown")
            if tool_registration is not None:
                tool = add_node("ai_tool", tool_registration.name, path,
                                tool_registration.decorator_line, lines, tool_registration.status)
                edges.append(GraphEdge(tool.id, handler.id, "EXPOSES", 1.0,
                                       tuple(dict.fromkeys((*tool.evidence_ids, *handler.evidence_ids))),
                                       path, tool_registration.decorator_line, commit_sha))
                for declaration in tool_registration.role_declarations:
                    role = add_node("role", declaration.name_digest, path,
                                    declaration.decorator_line, lines, "declaration_unverified")
                    edges.append(GraphEdge(handler.id, role.id, "REQUIRES_ROLE", 0.4,
                                           tuple(dict.fromkeys((*handler.evidence_ids, *role.evidence_ids))),
                                           path, declaration.decorator_line, commit_sha, "inferred"))
            used_names = {node.id for node in ast.walk(fn) if isinstance(node, ast.Name)}
            for alias in sorted(used_names & imports.keys()):
                module, line = imports[alias]
                dependency = add_node("dependency", module, path, line, lines, "observed_import")
                edges.append(GraphEdge(handler.id, dependency.id, "USES_DEPENDENCY", 0.9,
                                       tuple(dict.fromkeys((handler.evidence_ids[0], dependency.evidence_ids[0]))),
                                       path, line, commit_sha))
            for dec in route_decorators:
                route_path = dec.args[0].value if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str) else "dynamic"
                route = add_node("route", f"{_name(dec.func)} {route_path}", path, dec.lineno, lines,
                                 "unknown" if route_path == "dynamic" else "observed")
                edges.append(GraphEdge(route.id, handler.id, "EXPOSES", 1.0,
                                       tuple(dict.fromkeys((route.evidence_ids[0], handler.evidence_ids[0]))),
                                       path, dec.lineno, commit_sha))
            for name, line in (call for statement in fn.body for call in _call_names(statement)):
                if name.endswith(".get") or name.endswith(".read") or name.endswith(".fetch"):
                    resource = add_node("resource", name, path, line, lines, "unknown")
                    edges.append(GraphEdge(handler.id, resource.id, "READS", 0.8,
                                           tuple(dict.fromkeys((handler.evidence_ids[0], resource.evidence_ids[0]))),
                                           path, line, commit_sha))
            for arg in (*fn.args.defaults, *fn.args.kw_defaults):
                if isinstance(arg, ast.Call) and _name(arg.func) == "Depends":
                    identity_name = _name(arg.args[0]) if arg.args else "dynamic"
                    identity = add_node("identity", identity_name, path, arg.lineno, lines, "unknown")
                    edges.append(GraphEdge(handler.id, identity.id, "CALLS", 0.9,
                                           tuple(dict.fromkeys((handler.evidence_ids[0], identity.evidence_ids[0]))),
                                           path, arg.lineno, commit_sha))
    return SecurityGraph(commit_sha, tuple(nodes), tuple(edges), evidence)
