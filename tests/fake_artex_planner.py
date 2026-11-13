"""A STAND-IN for the ARTEX overlay, for tests on machines without the Go build.

It is a Python script, so Vulnix labels its runs "unverified" - never ARTEX itself.
It speaks the overlay's stdin/stdout contract. Behaviour is chosen by the request:
  request["fake_mode"]: "ok" (default) | "bad_tools" | "bad_call" | "sleep" | "fail"
  request["fake_intents"]: intents to report (default: the mock LLM's intents)
  request["dump_env_to"]: write the environment it received to this path
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.artex_mock_llm import INTENTS  # noqa: E402

ALLOWED = ["graph_overview", "list_findings", "list_facts", "node_detail", "list_goals", "add_intent",
           "prove_goal", "goal_met"]

req = json.loads(sys.stdin.read() or "{}")
mode = req.get("fake_mode", "ok")
if req.get("dump_env_to"):
    with open(req["dump_env_to"], "w") as fh:
        json.dump(dict(os.environ), fh)
if mode == "sleep":
    time.sleep(60)
if mode == "fail":
    print(json.dumps({"engine": "artex", "error": "planner failed"}))
    sys.exit(3)
allowed = ALLOWED + (["Bash"] if mode == "bad_tools" else [])
calls = [{"name": "add_intent", "allowed": True}]
if mode == "bad_call":
    calls.append({"name": "WebFetch", "allowed": True})
intents = req.get("fake_intents") or INTENTS
print(json.dumps({
    "engine": "artex", "artex_module": "github.com/Autumn-27/artex", "artex_commit": "fake-not-artex",
    "go_version": "none", "allowed_tools": allowed, "tool_calls": calls,
    "denied_tool_calls": ["Bash", "WebFetch", "add_task_scope"],
    "intents": [{"id": i + 1, **it} for i, it in enumerate(intents)], "goal_met": False,
}, ensure_ascii=False))
