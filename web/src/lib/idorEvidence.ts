import type { Evidence, Finding } from "./types";

export interface IdorEvidence {
  evidenceId: string | null;
  caller: string | null;
  owner: string | null;
  status: number | null;
  outcome: "read" | "blocked" | "unknown" | "pending" | "unavailable";
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

/** Evidence is appended by the backend. Never borrow fields from an earlier run. */
export function latestIdorEvidence(evidence: Evidence[]): IdorEvidence {
  const latest = evidence.at(-1);
  const result: IdorEvidence = {
    evidenceId: latest?.evidence_id ?? null,
    caller: null, owner: null, status: null, outcome: "unknown",
  };
  if (!latest) return result;
  let data: Record<string, unknown> | null;
  try { data = record(JSON.parse(latest.content)); } catch { return result; }
  if (!data || data.check !== "idor") return result;
  const response = record(data.response);
  const control = record(data.control_response);
  const requestHeaders = record(data.request_headers);
  result.caller = text(response?.caller_account);
  result.owner = text(response?.resource_owner);
  result.status = typeof data.status === "number" && Number.isInteger(data.status)
    && data.status >= 100 && data.status <= 599 ? data.status : null;
  const controlReady = data.request_path === "/api/accounts/B/secret"
    && requestHeaders !== null && Object.keys(requestHeaders).length === 1
    && requestHeaders["X-Test-Account"] === "acct_A"
    && data.control_status === 200 && data.control_verified === true
    && control?.Check === "idor_cross_account_access"
    && control?.caller_account === "acct_B" && control?.resource_owner === "acct_B"
    && control?.resource_id === "res_b_001"
    && control?.confidential_marker === "VULNIX_LAB_IDOR_PROVEN";
  if (controlReady && result.status === 200 && data.established === true && data.verdict === "proven"
    && response?.Check === "idor_cross_account_access" && response?.established === true
    && response?.caller_account === "acct_A" && response?.resource_owner === "acct_B"
    && response?.resource_id === "res_b_001"
    && response?.confidential_marker === "VULNIX_LAB_IDOR_PROVEN") {
    result.outcome = "read";
  } else if (controlReady && result.status === 403 && data.established === false
    && data.verdict === "not_reproduced") {
    result.caller = result.caller ?? "acct_A";
    result.owner = result.owner ?? "acct_B";
    result.outcome = "blocked";
  }
  return result;
}

/** A failed or unfinished attempt can leave old evidence attached to the finding. */
export function currentIdorEvidence(
  finding: Pick<Finding, "evidence" | "verdict" | "evidence_status" | "last_run_verdict" | "_in_verification">,
  busy = false,
): IdorEvidence {
  const pending = busy || finding._in_verification;
  if (pending || finding.verdict === "unverified" || finding.verdict === "aborted") {
    return {
      evidenceId: null, caller: null, owner: null, status: null,
      outcome: pending ? "pending" : "unavailable",
    };
  }
  if (finding.last_run_verdict === "unverified" || finding.last_run_verdict === "aborted") {
    return { evidenceId: null, caller: null, owner: null, status: null, outcome: "unavailable" };
  }
  const latest = latestIdorEvidence(finding.evidence);
  if (latest.outcome === "read" && (finding.verdict !== "proven" || finding.evidence_status !== "proven"
    || (finding.last_run_verdict && finding.last_run_verdict !== "proven"))) {
    return { ...latest, outcome: "unknown" };
  }
  if (latest.outcome === "blocked" && finding.last_run_verdict !== "not_reproduced"
    && finding.verdict !== "not_reproduced") {
    return { ...latest, outcome: "unknown" };
  }
  return latest;
}
