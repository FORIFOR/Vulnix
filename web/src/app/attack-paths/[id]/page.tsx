"use client";

import { useParams } from "next/navigation";
import { GraphWorkspace } from "@/components/graph/GraphWorkspace";

export default function AttackPathDetailPage() {
  const params = useParams<{ id: string }>();
  return <GraphWorkspace title="攻撃経路の詳細" initialPathId={params.id} />;
}
