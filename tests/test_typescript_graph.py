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

    def test_dynamic_route_stays_unknown(self):
        graph = self.graph("export const GET = makeHandler();\n")
        self.assertTrue(any(n.kind == "route" and n.status == "unknown" for n in graph.nodes))
        self.assertFalse(authorization_paths(graph))


if __name__ == "__main__":
    unittest.main()
