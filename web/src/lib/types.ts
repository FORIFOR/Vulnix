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
  reproduce_check?: string;
  l2_ready?: boolean;
  /** True for profile-defined L2 checks: needs an approver, per item. */
  requires_l2_approval?: boolean;
  l2_preconditions?: string[];
  l2_spec_status?: "confirmed" | "placeholder" | "unaccepted";
  /** Verdict of the most recent L2 run; differs from `verdict` when an earlier proof is kept. */
  last_run_verdict?: Verdict;
  /** Separation of duties is on: an L2 run needs a request by one operator and approval by another. */
  l2_needs_request?: boolean;
  l2_request?: { requested_by: string; requested_at: number } | null;
  risk_score?: number;
  risk_rationale?: string;
  impact?: string;
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
  source?: "builtin" | "external_model";
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

/** L2 test-account status for one asset. Fields, labels and checks come from the
 *  asset's service profile on the server; raw token values are never included. */
export interface SecretsStatus {
  host: string;
  has_l2_credentials: boolean;
  l2_ready?: boolean;
  encryption: string;
  /** null when no L2 rule profile applies to this asset (L1 only). */
  profile: { id: string; label: string; spec_status: "confirmed" | "partial" | "placeholder" | "unaccepted"; spec_note: string } | null;
  /** usable=false: only needed by rules that are not confirmed against the API, so it cannot be stored. */
  tokens: { key: string; label: string; set: boolean; usable: boolean; fingerprint: string | null }[];
  paths: { key: string; label: string; default: string; value?: string | null }[];
  /** Per-check readiness: which test-account tokens are still missing. */
  checks: Record<string, {
    label: string; category: string; ready: boolean; missing: string[]; preconditions: string[];
    /** "placeholder": the rule is not matched against the target API and cannot be executed. */
    /** "unaccepted": a site profile whose content an admin has not accepted (or that changed since). */
    spec_status: "confirmed" | "placeholder" | "unaccepted"; spec_note: string;
  }>;
}

export interface Snapshot {
  id: string;
  demo: boolean;
  target_url?: string;
  is_external_service?: boolean;
  l2_separation_required?: boolean;
  /** Set while state cannot be written to disk; real-service work is refused meanwhile. */
  persistence_error?: string | null;
  /** Set when saved ownership/scope was not restored at startup. */
  authority_notice?: string | null;
  /** Generation token of the authority ledger; changes with every committed change of authority. */
  authority_generation?: string;
  /** Workers a revocation or deletion could not confirm dead (still alive now). */
  unstopped_workers?: { host: string; pids: number[]; at?: number } | null;
  /** Why the assessment is "failed". */
  failure?: { reason: string; kind: "run" | "persistence"; at?: number; error?: string } | null;
  /** Kernel confinement of the L2 worker on this host; real-service L2 needs ok === true. */
  l2_isolation?: { ok: boolean; reason: string; mechanism?: string } | null;
  lab_mode?: string;
  lab_endpoint: string;
  secrets_status?: SecretsStatus;
  prohibited_actions?: string[];
  evidence_summary: Record<EvidenceStatus, number>;
  planner: {
    mode: "builtin" | "external_configured";
    external_model_configured: boolean;
    connection_verified: boolean;
    model_name?: string | null;
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
  /** null for a real service: the demo history is fictional and never attached to it. */
  history?: AssessmentHistory | null;
  defense_comparison?: DefenseComparison | null;
  cve_status?: CveStatus;
  artex_plan?: ArtexPlanView | null;
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

export interface OwnershipChallenge {
  token: string;
  dns_txt_name: string;
  dns_txt_value: string;
  well_known_url: string;
  well_known_content: string;
}

export interface Asset {
  id: string;
  name: string;
  display_name?: string;
  target_url?: string;
  scheme?: string;
  port?: number;
  kind: string;
  environment: string;
  status: string;
  assessment_id: string | null;
  risk: Risk | null;
  previous_risk_score?: number | null;
  last_assessed_at?: number | null;
  authorization_ref?: string;
  ownership_verified?: boolean;
  scope_confirmed?: boolean;
  challenge?: OwnershipChallenge;
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

/** A plan from the real ARTEX planner, rebuilt by Vulnix (never ARTEX's own targets/args). */
export interface ArtexPlanView {
  configured: boolean;
  plan: null | {
    run_id: string;
    requested_by: string;
    at: number;
    engine: { kind: string; label: string; sha256?: string; artex_commit?: string; go_version?: string };
    allowed_tools: string[];
    tool_calls: { name: string; allowed: boolean }[];
    denied_tool_calls: string[];
    goal_met: boolean;
    elapsed_ms: number;
    intents: number;
    items: {
      id: string; intent_id: number; intent_summary: string; catalog_id: string; label: string;
      level: "L1" | "L2"; target_id: string; tool: string; status: string;
    }[];
    advisories: { intent_id: number; summary: string; reason: string }[];
  };
}
