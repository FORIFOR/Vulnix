"""Next.js route extraction through the TypeScript compiler AST."""
import tempfile
import unittest
from pathlib import Path

from aegis.security_graph.builder import build_graph
from aegis.security_graph.queries import authorization_paths


VULNERABLE = '''import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

export async function GET(request: Request) {
  const session = await auth();
  const order = await db.order.findUnique({ where: { id: "123" } });
  return NextResponse.json(order);
}
'''
PROTECTED = VULNERABLE.replace("  return NextResponse.json(order);",
    "  if (order.orgId !== session.orgId) { return new Response(null, { status: 403 }); }\n"
    "  return NextResponse.json(order);")


class TypeScriptGraphTest(unittest.TestCase):
    def graph(self, source):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        path = root / "app" / "api" / "orders" / "[id]" / "route.ts"
        path.parent.mkdir(parents=True)
        path.write_text(source)
        return build_graph(root, "a" * 40)

    def test_next_route_auth_and_data_access(self):
        graph = self.graph(VULNERABLE)
        self.assertEqual(len(authorization_paths(graph)), 1)
        path = authorization_paths(graph)[0]
        self.assertEqual(path.status, "unknown")
        self.assertTrue(any(n.kind == "route" and "GET" in n.name for n in graph.nodes))
        self.assertTrue(any(e.relation == "CALLS" for e in graph.edges))
        self.assertTrue(any(e.relation == "READS" for e in graph.edges))
        self.assertTrue(all(e.evidence_ids for e in graph.edges))

    def test_explicit_org_guard_is_only_observed(self):
        path = authorization_paths(self.graph(PROTECTED))[0]
        self.assertEqual(path.status, "guard_observed")

    def test_inverted_org_guard_is_unknown(self):
        graph = self.graph(PROTECTED.replace("order.orgId !== session.orgId",
                                             "order.orgId === session.orgId"))
        self.assertEqual(authorization_paths(graph)[0].status, "unknown")

    def test_nested_unused_guard_is_unknown(self):
        nested = VULNERABLE.replace("  return NextResponse.json(order);",
            "  function unused() { if (order.orgId !== session.orgId) { throw new Error('403'); } }\n"
            "  return NextResponse.json(order);")
        self.assertEqual(authorization_paths(self.graph(nested))[0].status, "unknown")

    def test_conditional_rejection_inside_mismatch_is_unknown(self):
        conditional = VULNERABLE.replace("  return NextResponse.json(order);",
            "  if (order.orgId !== session.orgId) {\n"
            "    if (session.isAdmin) { return new Response(null, { status: 403 }); }\n"
            "  }\n"
            "  return NextResponse.json(order);")
        self.assertEqual(authorization_paths(self.graph(conditional))[0].status, "unknown")

    def test_comment_containing_throw_is_not_a_guard(self):
        comment = VULNERABLE.replace("  return NextResponse.json(order);",
            "  if (order.orgId !== session.orgId) {\n"
            "    // throw new Error('403')\n"
            "    return NextResponse.json(order);\n"
            "  }\n"
            "  return NextResponse.json(order);")
        self.assertEqual(authorization_paths(self.graph(comment))[0].status, "unknown")

    def test_forbidden_status_with_resource_body_is_unknown(self):
        exposed_body = PROTECTED.replace("new Response(null, { status: 403 })",
                                          "new Response(order, { status: 403 })")
        self.assertEqual(authorization_paths(self.graph(exposed_body))[0].status, "unknown")

    def test_guard_after_return_is_unknown(self):
        unreachable = VULNERABLE.replace("  return NextResponse.json(order);",
            "  return NextResponse.json(order);\n"
            "  if (order.orgId !== session.orgId) { return new Response(null, { status: 403 }); }")
        self.assertEqual(authorization_paths(self.graph(unreachable))[0].status, "unknown")

    def test_dynamic_route_stays_unknown(self):
        graph = self.graph("export const GET = makeHandler();\n")
        self.assertTrue(any(n.kind == "route" and n.status == "unknown" for n in graph.nodes))
        self.assertFalse(authorization_paths(graph))

    def test_exported_arrow_handler_is_parsed(self):
        arrow = VULNERABLE.replace("export async function GET(request: Request) {",
                                   "export const GET = async (request: Request) => {")
        graph = self.graph(arrow)
        self.assertEqual(len(authorization_paths(graph)), 1)
        self.assertEqual(authorization_paths(graph)[0].status, "unknown")
        self.assertTrue(any(e.relation == "READS" for e in graph.edges))

    def test_exported_arrow_handler_with_direct_guard(self):
        arrow = PROTECTED.replace("export async function GET(request: Request) {",
                                  "export const GET = async (request: Request) => {")
        self.assertEqual(authorization_paths(self.graph(arrow))[0].status, "guard_observed")


if __name__ == "__main__":
    unittest.main()
