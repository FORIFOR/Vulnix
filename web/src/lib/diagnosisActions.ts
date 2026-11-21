// PR-C: sending a diagnosis operation (docs/DIAGNOSIS_ACTIONS.md).
//
// Every request carries an Idempotency-Key. The key is kept only for a retry of the very
// same request that got no answer (a network failure or a timeout): the server then
// returns what it already did instead of doing it twice. Any answer from the server ends
// that request; the next click is a new request with a new key.

export const KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

export type PendingKey = { sig: string; key: string } | null;

export function newIdempotencyKey(): string {
  return `dk-${crypto.randomUUID()}`;
}

export function requestSignature(op: string, body: Record<string, unknown>): string {
  return `${op}:${JSON.stringify(body, Object.keys(body).sort())}`;
}

/** The key for this request: the pending one if it is the same request, else a new one. */
export function keyFor(pending: PendingKey, sig: string, make: () => string = newIdempotencyKey): { sig: string; key: string } {
  return pending && pending.sig === sig ? pending : { sig, key: make() };
}

export type OpAnswer = { status: number; body: Record<string, unknown> };

/** POST the operation. Returns null when no answer came back (keep the key and retry). */
export async function postDiagnosisOp(assessmentId: string, op: string, body: Record<string, unknown>,
                                      key: string): Promise<OpAnswer | null> {
  let res: Response;
  try {
    res = await fetch(`/api/assessments/${encodeURIComponent(assessmentId)}/diagnosis/${op}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Aegis-Request": "1", "Idempotency-Key": key },
      body: JSON.stringify(body),
    });
  } catch {
    return null;
  }
  const data = await res.json().catch(() => ({}));
  return { status: res.status, body: typeof data === "object" && data !== null ? data as Record<string, unknown> : {} };
}
