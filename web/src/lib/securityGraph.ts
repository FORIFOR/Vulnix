export type GraphSnapshot = {
  id: string;
  repository_id: string;
  commit_sha: string;
  parser_version: string;
  status: string;
  created_at: string;
};
export type GraphNode = {
  id: string;
  kind: string;
  name: string;
  source_path: string;
  source_line: number;
  commit_sha: string;
  evidence_ids: string[];
  status: string;
};
export type GraphEdge = {
  source: string;
  target: string;
  relation: string;
  confidence: number;
  evidence_ids: string[];
  source_path: string;
  source_line: number;
  commit_sha: string;
  evidence_status: string;
};
export type GraphPath = {
  id: string;
  nodes: string[];
  edges: GraphEdge[];
  evidence_ids: string[];
  status: string;
};
export type GraphEvidence = {
  id: string;
  source_path: string;
  source_line: number;
  commit_sha: string;
  source_digest: string;
};
export type GraphHypothesis = {
  hypothesis_id: string;
  category: string;
  summary: string;
  evidence_ids: string[];
  assumptions: string[];
  counter_evidence: string[];
  uncertainties: string[];
  confidence: number;
  verdict: string;
};
export type McpScopeCandidate = {
  id: string;
  tool_id: string;
  handler_id: string;
  resource_ids: string[];
  declared_role_ids: string[];
  evidence_ids: string[];
  status: string;
  validation_status: string;
};

export function mcpScopeLabel(status: string): string {
  const labels: Record<string, string> = {
    scope_unknown: "MCPツールの権限範囲は未確認",
    role_declaration_unverified: "コード上にロール宣言あり（実効性は未検証）",
  };
  return labels[status] ?? "MCPツールの権限状態は未確認";
}

export function pathStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    observed_structure: "コード上の構造（脆弱性は未確定）",
    inferred: "推定された接続（未確認）",
    hypothesized: "AIの仮説（未検証）",
    verified: "隔離検証で成立",
    refuted: "検証で否定",
    guard_observed: "認可ガードを観測（有効性は未確認）",
  };
  return labels[status] ?? "状態未確認";
}

export function pathIsVerified(status: string): boolean {
  return status === "verified";
}

export function syntheticValidationLabel(status: string): string {
  const labels: Record<string, string> = {
    synthetic_fixed: "合成ラボで越境を再現し、ローカル修正後に解消を確認",
    confirmed_in_synthetic_lab: "合成ラボで越境を再現（修正は未確認）",
    not_reproduced: "合成ラボで越境は再現せず",
    inconclusive: "合成ラボの結果は判定不能",
  };
  return labels[status] ?? "合成ラボの結果は未確認";
}
