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
  result.caller = text(response?.caller_account);
  result.owner = text(response?.resource_owner);
  result.status = typeof data.status === "number" && Number.isInteger(data.status)
    && data.status >= 100 && data.status <= 599 ? data.status : null;
  const crossAccount = result.caller && result.owner && result.caller !== result.owner;
  if (crossAccount && result.status === 200 && data.established === true && text(response?.resource_id)) {
    result.outcome = "read";
  } else if (crossAccount && result.status === 403 && data.established === false) {
    result.outcome = "blocked";
  }
  return result;
}

/** A failed or unfinished attempt can leave old evidence attached to the finding. */
export function currentIdorEvidence(
  finding: Pick<Finding, "evidence" | "verdict" | "_in_verification">,
  busy = false,
): IdorEvidence {
  const pending = busy || finding._in_verification;
  if (pending || finding.verdict === "unverified" || finding.verdict === "aborted") {
    return {
      evidenceId: null, caller: null, owner: null, status: null,
      outcome: pending ? "pending" : "unavailable",
    };
  }
  return latestIdorEvidence(finding.evidence);
}
