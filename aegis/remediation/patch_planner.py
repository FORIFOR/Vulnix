"""A narrow, reviewable repair template for the synthetic example."""
import ast
import difflib
from dataclasses import dataclass
from pathlib import Path

from aegis.connectors.github_source import read_pinned_file
from aegis.research.hypotheses import Hypothesis
from aegis.security_graph.models import SecurityGraph
from aegis.validation.verdicts import Verdict


@dataclass(frozen=True)
class PatchPlan:
    source_path: str
    original: str
    modified: str
    diff: str
    commit_sha: str


def plan_patch(checkout: Path, graph: SecurityGraph, hypothesis: Hypothesis, verdict: Verdict) -> PatchPlan:
    if verdict.status != "confirmed_in_synthetic_lab" or verdict.hypothesis_id != hypothesis.hypothesis_id:
        raise ValueError("confirmed synthetic finding required")
    handlers = [node for node in graph.nodes if node.id in hypothesis.affected_nodes and node.kind == "handler"]
    if len(handlers) != 1 or handlers[0].name != "get_order" or handlers[0].source_path != "api.py":
        raise ValueError("repair template only supports synthetic api.py")
    source = read_pinned_file(checkout, graph.commit_sha, "api.py")
    if (checkout / "api.py").read_text(encoding="utf-8") != source:
        raise ValueError("checkout changed after pinning")
    tree = ast.parse(source)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "get_order"]
    if len(functions) != 1:
        raise ValueError("ambiguous handler")
    fn = functions[0]
    if len(fn.body) != 2 or not isinstance(fn.body[0], ast.Assign) or not isinstance(fn.body[1], ast.Return):
        raise ValueError("unexpected handler shape")
    if (len(fn.body[0].targets) != 1 or not isinstance(fn.body[0].targets[0], ast.Name) or
        fn.body[0].targets[0].id != "order" or not isinstance(fn.body[1].value, ast.Name) or
        fn.body[1].value.id != "order"):
        raise ValueError("unexpected data flow")
    lines = source.splitlines(keepends=True)
    insert = "    if order.org_id != identity['org_id']:\n        raise HTTPException(status_code=403)\n"
    lines.insert(fn.body[1].lineno - 1, insert)
    modified = "".join(lines)
    ast.parse(modified)
    diff = "".join(difflib.unified_diff(source.splitlines(keepends=True), modified.splitlines(keepends=True),
                                        fromfile="a/api.py", tofile="b/api.py"))
    return PatchPlan("api.py", source, modified, diff, graph.commit_sha)
