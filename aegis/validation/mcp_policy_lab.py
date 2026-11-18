"""A fixed, synthetic MCP policy control; never runs indexed repository code."""

from .sandbox import SandboxUnavailable, _run_synthetic_program


SOURCE = '''from fastmcp import FastMCP
from functools import wraps

server = FastMCP("synthetic-lab")
CONTEXT = {"role": "viewer"}

class Store:
    def get(self, customer_id):
        return {"org_id": "org-b", "customer_id": customer_id}

store = Store()

def requires_role(role):
    def decorate(fn):
        @wraps(fn)
        def guarded(*args, **kwargs):
            if CONTEXT["role"] != role:
                raise PermissionError("synthetic role denied")
            return fn(*args, **kwargs)
        return guarded
    return decorate

@server.tool()
def open_customer(customer_id):
    return store.get(customer_id)

@server.tool()
@requires_role("admin")
def guarded_customer(customer_id):
    return store.get(customer_id)

@requires_role("admin")
@server.tool()
def misordered_customer(customer_id):
    return store.get(customer_id)
'''


HARNESS = '''import json
import runpy
import sys
import types

class FakeFastMCP:
    def __init__(self, name):
        self.tools = {}

    def tool(self):
        def register(fn):
            self.tools[fn.__name__] = fn
            return fn
        return register

stub = types.ModuleType("fastmcp")
stub.FastMCP = FakeFastMCP
sys.modules["fastmcp"] = stub
namespace = runpy.run_path(sys.argv[1])
tools = namespace["server"].tools
context = namespace["CONTEXT"]

def reaches_data(tool):
    return tools[tool]("synthetic-customer")["org_id"] == "org-b"

context["role"] = "viewer"
open_result = reaches_data("open_customer")
try:
    reaches_data("guarded_customer")
except PermissionError:
    guarded_denied = True
else:
    guarded_denied = False
misordered_result = reaches_data("misordered_customer")
context["role"] = "admin"
admin_result = reaches_data("guarded_customer")
print(json.dumps({
    "open_viewer_reached_data": open_result,
    "guarded_viewer_denied": guarded_denied,
    "misordered_viewer_reached_data": misordered_result,
    "guarded_admin_reached_data": admin_result,
}, sort_keys=True))
'''

_RESULT_KEYS = frozenset({"open_viewer_reached_data", "guarded_viewer_denied",
                          "misordered_viewer_reached_data", "guarded_admin_reached_data"})


def run_mcp_policy_lab(*, pool=None, prelaunch=None) -> dict[str, bool]:
    """Run only packaged constants through the existing confinement boundary.

    The result demonstrates a control behavior; it does not verify any
    customer's MCP tool or turn a graph candidate into a finding.
    """
    result = _run_synthetic_program(SOURCE, HARNESS, _RESULT_KEYS,
                                    pool=pool, prelaunch=prelaunch)
    if any(type(value) is not bool for value in result.values()):
        raise SandboxUnavailable("invalid synthetic MCP result")
    return result
