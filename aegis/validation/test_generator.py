"""Fixed harness, not AI-generated executable code."""

HARNESS = '''import json, runpy, sys
module = runpy.run_path(sys.argv[1])
def check(order_id):
    try:
        result = module["get_order"](order_id, {"org_id": "org-a"})
        return {"returned_org": getattr(result, "org_id", None), "denied": False}
    except module["HTTPException"] as exc:
        return {"returned_org": None, "denied": exc.status_code == 403}
print(json.dumps({"own": check("a"), "other": check("b")}))
'''
