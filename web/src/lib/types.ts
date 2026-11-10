export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "detected" | "unverified" | "proven" | "not_reproduced" | "aborted";
export type AssessmentState = "idle" | "running" | "paused" | "stopped" | "failed" | "completed";
export type PhaseStatus = "pending" | "running" | "done" | "aborted" | "skipped";
export type RiskLevel = "L1" | "L2" | "L3";

export interface Phase { key: string; label: string; status: PhaseStatus; detail: string }

export interface Evidence {
  evidence_id: string;
  kind: string;
  saved_at: number | null;
  audit_hash: string | null;
  content: string;
}

export type EvidenceStatus = "candidate" | "detected" | "proven" | "not_reproduced" | "incomplete" | "fixture";

export interface Finding {
  evidence_status: EvidenceStatus;
  id: string;
  title: string;
  severity: Severity;
  verdict: Verdict;
  category: string;
  cve: string[];
  risk_level: RiskLevel;
  help_term?: string;
  summary: string;
  what_was_established?: string;
  why_detected?: string;
  caveat?: string;
  verdict_note?: string;
  evidence: Evidence[];
  remediation: { steps: string[]; how_to_verify: string };
  executor: { agent: string; model: string; tool: string };
  demo_fixture: boolean;
  _in_verification?: boolean;
}

export interface Approval {
  id: string;
  action: string;
  risk_level: RiskLevel;
  title: string;
  description: string;
  status: "pending" | "approved" | "rejected";
  decided_by: string | null;
  decided_at: number | null;
}

export interface Risk { score: number; label: string; provisional: boolean; basis: string }

export interface StopReport {
  actor: string;
  confirmed: boolean;
  killed_pids: number[];
  survivors: number[];
  steps: { name: string; elapsed_ms: number }[];
  at: number;
}

export interface Activity {
  title: string;
  tool: string;
  risk_level: RiskLevel;
  agent: string;
  model: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  actor: string;
  text: string;
  term?: string | null;
  finding_id?: string | null;
  ts: number;
}

export interface AssessmentHistory {
  demo_fixture?: boolean;
  previous_assessment_id: string;
  previous_assessed_at: number;
  previous_score: number;
  previous_label: string;
  delta_score: number | null;
  resolved_findings: string[];
  new_findings_count: number;
  runs: {
    id: string;
    at: number;
    score: number | null;
    label: string;
    status: string;
    summary: string;
  }[];
}

export interface DefenseComparison {
  verified_at: number;
  actor: string;
  lab_mode: string;
  before_score: number;
  after_score: number;
  items: {
    id: string;
    title: string;
    severity: Severity;
    before_verdict: Verdict;
    after_verdict: Verdict;
    latest_evidence_id?: string;
  }[];
}

export interface ControlVerificationReport {
  verified_at: number;
  host_platform: string;
  all_passed: boolean;
  total_elapsed_ms: number;
  checks: {
    id: string;
    name: string;
    passed: boolean;
    elapsed_ms: number;
    detail: string;
  }[];
}

export interface CveStatus {
  cve_count: number;
  kev_count: number;
  last_synced_at: number;
  sync_source: string;
  cves: {
    id: string;
    product: string;
    severity: Severity;
    cwe: string;
    in_kev: boolean;
  }[];
}

export interface Snapshot {
  id: string;
  demo: boolean;
  lab_mode?: string;
  lab_endpoint: string;
  evidence_summary: Record<EvidenceStatus, number>;
  planner: {
    mode: "builtin" | "external_configured";
    external_model_configured: boolean;
    connection_verified: boolean;
    note: string;
    backends: string[];
  };
  asset: { id: string; name: string; kind: string; environment: string };
  authorization: {
    status: "authorized" | "missing";
    ref: string;
    ownership_verified: boolean;
    not_before: number;
    not_after: number;
    scope: { hosts: string[]; cidrs: string[]; ports: number[] };
    allowed_actions: string[];
  };
  state: AssessmentState;
  phases: Phase[];
  activity: Activity | null;
  approvals: Approval[];
  findings: Finding[];
  risk: Risk;
  stop_report: StopReport | null;
  chat_messages?: ChatMessage[];
  history?: AssessmentHistory;
  defense_comparison?: DefenseComparison | null;
  cve_status?: CveStatus;
  artex_tasks?: {
    id: string;
    phase: string;
    title: string;
    risk_level: RiskLevel;
    status: string;
    tool: string;
  }[];
  last_seq: number;
}

export interface Asset {
  id: string;
  name: string;
  kind: string;
  environment: string;
  status: string;
  assessment_id: string | null;
  risk: Risk | null;
  previous_risk_score?: number | null;
  last_assessed_at?: number | null;
  authorization_ref?: string;
  ownership_verified?: boolean;
  note?: string;
}

export interface AuditEntry {
  ts: number;
  event: string;
  fields: Record<string, unknown>;
  hash: string;
  prev?: string;
}

export interface AegisEvent {
  event_id: string;
  seq: number;
  assessment_id: string;
  type: string;
  timestamp: string;
  [k: string]: unknown;
}
