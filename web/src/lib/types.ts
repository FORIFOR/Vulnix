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

export interface Finding {
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

export interface Snapshot {
  id: string;
  demo: boolean;
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
