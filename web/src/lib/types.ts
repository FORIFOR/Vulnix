import type { AuditAnchorStatus } from "./auditAnchor";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "candidate" | "detected" | "unverified" | "proven" | "not_reproduced" | "aborted";
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
  cookie_checks?: { name: string; purpose: "session" | "non_session" | "unknown"; verdict: "detected" | "candidate" | "none"; gaps: string[] }[];
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
  /** set when the external model's answer was withheld by the output check */
  withheld_reason?: string;
  guard_note?: string;
  /** code-written status for an answer about a finding not proven by L2 */
  verdict_note?: string;
  /** code-written warning when the answer reads as an overclaim or a breach claim */
  caution_note?: string;
  cautions?: string[];
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
  /** null until a feed was actually fetched or ingested (bundled data only) */
  last_synced_at: number | null;
  sync_source: string;
  freshness?: "fresh" | "stale" | "unfetched";
  stale?: boolean;
  nvd_sha256?: string | null;
  kev_sha256?: string | null;
  last_sync_error?: string | null;
  last_error_at?: number | null;
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
  /** Local audit anchor (docs/AUDIT_ANCHOR.md): protected only when enabled and the last check passed. */
  audit_anchor?: AuditAnchorStatus | null;
  id: string;
  demo: boolean;
  target_url?: string;
  is_external_service?: boolean;
  optional_status_scope?: boolean;
  /** public beta: a real site gets only the read-only diagnosis (no L2, no re-checks) */
  real_site_read_only?: boolean;
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
    /** the explanation (chat) model; configured independently of external proposals */
    explanation_model_configured?: boolean;
    connection_verified: boolean;
    /** configured ≠ connected: "verified" only after a real answer, "failed" after a failed call */
    connection_state?: "unconfigured" | "configured" | "verified" | "failed";
    connection_checked_at?: number | null;
    connection_error?: string | null;
    status_seq?: number;
    boot_id?: string;
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
  /** completed runs of this organization's workspace, newest first */
  run_history?: RunHistoryEntry[];
  defense_comparison?: DefenseComparison | null;
  cve_status?: CveStatus;
  artex_plan?: ArtexPlanView | null;
  /** Display-only provenance. It survives restart; executable plan items do not. */
  plan_source?: { engine: "artex-binary" | "unverified"; pinned: boolean; model: string | null } | null;
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
  meta_tag_url?: string;
  meta_tag_name?: string;
  meta_tag_content?: string;
  meta_tag_html?: string;
  code?: string;
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
    engine: { kind: string; label: string; pinned?: boolean; sha256?: string; artex_commit?: string; go_version?: string };
    llm_model?: string;
    isolation?: {
      confined: boolean; label: string; mechanism?: string; kernel_dropped_packets?: number;
      pinned?: string; pinned_extra?: string[]; egress_canary?: string | null;
    };
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

export interface RunHistoryEntry {
  at: number;
  asset: string;
  score: number | null;
  label: string | null;
  counts: { detected?: number; proven?: number; not_reproduced?: number; incomplete?: number };
  findings: number;
}

// ---- diagnosis loop (GET /api/assessments/{id}/diagnosis, SSE diagnosis.updated) ----
// docs/DIAGNOSIS_READ_API.md. Every text is a fixed id; the screen turns it into words.
export type DiagnosisStatus = "not_started" | "ok" | "unverified";
export type HypothesisState = "open" | "supported" | "contradicted" | "inconclusive" | "needs_spec";
export type DiagnosisAttrs = Record<string, string | number | boolean>;

export interface DiagnosisHypothesis {
  id: string;
  claim: string;
  target_ref: string;
  state: HypothesisState;
  purpose: "diagnose" | "confirm_fix";
  generation: number;
  supersedes: string | null;
  basis: string[];
  supporting: string[];
  contradicting: string[];
  inconclusive: string[];
}

export interface DiagnosisStep {
  plan_id: string | null;
  step_id: string | null;
  catalog_id: string;
  level: string | null;
  hypothesis_id: string;
  target_ref: string | null;
  reason: string | null;
  evidence_refs: string[];
  approved_by: string | null;
  generation: number;
  observation: { evidence_id: string; attrs: DiagnosisAttrs };
  judgement: { from: string | null; to: HypothesisState; rule: string };
  result_audit_hash: string;
  judged_audit_hash: string;
  at: string | null;
}

export interface DiagnosisEvidence {
  evidence_id: string;
  kind: string;
  source: string;
  target_ref: string;
  generation: number;
  attrs: DiagnosisAttrs;
  step_id: string | null;
  catalog_id: string | null;
  audit_hash: string | null;
  recorded_by: string | null;
  journal_hash: string | null;
  at: string | null;
}

export interface DiagnosisFixSide {
  generation: number;
  to: HypothesisState;
  rule: string;
  judged_audit_hash: string;
  result_audit_hash?: string;
  /** what that step's own audited result said about reproduction */
  reproduction?: string | null;
}

export interface DiagnosisFix {
  hypothesis_id: string;
  supersedes: string;
  catalog_id: string | null;
  before: DiagnosisFixSide | null;
  after: DiagnosisFixSide | null;
  result: "fixed" | "not_fixed" | "pending";
  /** the finding these steps are about, and its status now */
  finding?: { finding_id: string; status: string } | null;
}

/** PR-C: the loop job (who asked, what it waits for). Never a result. */
export interface DiagnosisOperation {
  id: string;
  kind: string;
  state: string;
  requested_by: string;
  diag_id: string | null;
  generation: number | null;
  waiting_item_id: string | null;
  needs_spec: string[];
  result: { plan_state?: string; reason?: string; detail?: string } | null;
  started_at: number | null;
}

/** PR-C: who reads (GET only) and what they may do. The server checks every operation again. */
export interface DiagnosisViewer {
  actor: string | null;
  permissions: string[];
}

export interface DiagnosisPlan {
  plan_id: string;
  state: string;
  reason: string | null;
  steps_used: number;
  steps_max: number | null;
}

export interface DiagnosisNext {
  kind: string;
  item_id?: string;
  hypothesis_id?: string;
  target_ref?: string;
  state?: string;
  reason?: string | null;
}

export interface DiagnosisView {
  schema_version: number;
  lab_only: boolean;
  assessment_id: string;
  status: DiagnosisStatus;
  reason?: string;
  restored: boolean;
  persisted: boolean;
  diag_id?: string;
  generation: number | null;
  plan: DiagnosisPlan | null;
  hypotheses: DiagnosisHypothesis[];
  steps: DiagnosisStep[];
  evidence: DiagnosisEvidence[];
  fix_comparison: DiagnosisFix[];
  next: DiagnosisNext;
  operation?: DiagnosisOperation | null;
  viewer?: DiagnosisViewer;
}
