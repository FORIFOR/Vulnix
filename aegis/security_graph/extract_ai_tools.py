"""Identify explicit FastMCP tool registration without importing source code."""
import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolRegistration:
    name: str
    decorator_line: int
    status: str


def _factory_call(expr: ast.expr, imported_names: set[str], imported_modules: set[str]) -> bool:
    if not isinstance(expr, ast.Call):
        return False
    if isinstance(expr.func, ast.Name):
        return expr.func.id in imported_names
    return (isinstance(expr.func, ast.Attribute) and expr.func.attr == "FastMCP" and
            isinstance(expr.func.value, ast.Name) and expr.func.value.id in imported_modules)


def _registration(fn: ast.FunctionDef | ast.AsyncFunctionDef,
                  instances: set[str]) -> ToolRegistration | None:
    for decorator in fn.decorator_list:
        if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and
                decorator.func.attr == "tool" and isinstance(decorator.func.value, ast.Name) and
                decorator.func.value.id in instances):
            continue
        name = fn.name
        status = "observed_registration"
        for keyword in decorator.keywords:
            if keyword.arg == "name":
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    # A decorator string is source data and may contain secrets.
                    # Keep the Python symbol; retain only the alias line digest.
                    status = "registration_observed_name_redacted"
                else:
                    status = "unknown"
        if decorator.args or any(keyword.arg is None for keyword in decorator.keywords):
            status = "unknown"
        return ToolRegistration(name, decorator.lineno, status)
    return None


def extract_mcp_tools(tree: ast.Module) -> dict[ast.FunctionDef | ast.AsyncFunctionDef, ToolRegistration]:
    """Return registrations only while a module-level FastMCP binding is intact.

    Dynamic factory calls and decorators outside this small AST subset remain
    unclassified. A registration is not evidence of an effective permission gate.
    """
    imported_names: set[str] = set()
    imported_modules: set[str] = set()
    instances: set[str] = set()
    result: dict[ast.FunctionDef | ast.AsyncFunctionDef, ToolRegistration] = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom) and statement.module in {"fastmcp", "mcp.server.fastmcp"}:
            imported_names.update(alias.asname or alias.name for alias in statement.names
                                  if alias.name == "FastMCP")
        elif isinstance(statement, ast.Import):
            imported_modules.update(alias.asname or alias.name for alias in statement.names
                                    if alias.name == "fastmcp")
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            names = {target.id for target in targets if isinstance(target, ast.Name)}
            factory = value is not None and _factory_call(value, imported_names, imported_modules)
            imported_names.difference_update(names)
            imported_modules.difference_update(names)
            instances.difference_update(names)
            if factory:
                instances.update(names)
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            registration = _registration(statement, instances)
            if registration is not None:
                result[statement] = registration
            imported_names.discard(statement.name)
            imported_modules.discard(statement.name)
            instances.discard(statement.name)
        elif isinstance(statement, ast.ClassDef):
            imported_names.discard(statement.name)
            imported_modules.discard(statement.name)
            instances.discard(statement.name)
        elif isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name):
            imported_names.discard(statement.target.id)
            imported_modules.discard(statement.target.id)
            instances.discard(statement.target.id)
        elif isinstance(statement, ast.Delete):
            names = {target.id for target in statement.targets if isinstance(target, ast.Name)}
            imported_names.difference_update(names)
            imported_modules.difference_update(names)
            instances.difference_update(names)
        elif isinstance(statement, (ast.If, ast.Try, ast.TryStar, ast.For, ast.AsyncFor,
                                    ast.While, ast.With, ast.AsyncWith, ast.Match)):
            # Conditional rebinding and aliases escaping a context are not
            # tracked. A later declaration can establish a new known binding.
            imported_names.clear()
            imported_modules.clear()
            instances.clear()
    return result
