// Live updates arrive as server-sent events. Some paths deliver them late or all at once
// (Cloudflare Quick Tunnels buffer event streams), so the page also re-reads the snapshot
// whenever the stream has been quiet for a while and the page is visible.

export const QUIET_MS = 6000;
export const POLL_EVERY_MS = 4000;
export const MAX_SNAPSHOT_AGE_MS = 30000;

export function needsPoll(lastEventAt: number, now: number, visible: boolean, quietMs: number = QUIET_MS): boolean {
  return visible && now - lastEventAt >= quietMs;
}

// A live heartbeat proves that the SSE transport is moving, but it cannot
// prove that every state mutation was published to the event bus. Bound how
// long the visible screen can rely on events alone.
export function needsAuthoritativeRefresh(
  lastSnapshotAt: number, now: number, visible: boolean, maxAgeMs: number = MAX_SNAPSHOT_AGE_MS,
): boolean {
  return visible && now - lastSnapshotAt >= maxAgeMs;
}

export function shouldApplySnapshot(
  snapshotSeq: number, seenSeq: number, requestSerial: number = 0, appliedSerial: number = 0,
): boolean {
  return Number.isSafeInteger(snapshotSeq) &&
    (snapshotSeq > seenSeq || (snapshotSeq === seenSeq && requestSerial >= appliedSerial));
}

// An older failed request may complete after a newer successful read. Its
// access error must not clear that newer state or permanently stop updates.
export function shouldApplyRequestFailure(
  requestSerial: number, latestIssuedSerial: number, appliedSerial: number,
): boolean {
  return requestSerial === latestIssuedSerial && requestSerial >= appliedSerial;
}

// A heartbeat is useful only if it covers every event the browser has seen.
// If the server reports a newer sequence, an event was missed: re-read both
// snapshot and audit. Malformed or stale heartbeats never suppress the backup.
export function heartbeatDecision(serverSeq: unknown, seenSeq: number): "healthy" | "refresh" | "ignore" {
  if (typeof serverSeq !== "number" || !Number.isSafeInteger(serverSeq) || serverSeq < 0 || serverSeq < seenSeq) {
    return "ignore";
  }
  return serverSeq > seenSeq ? "refresh" : "healthy";
}

// The event sequence lives in the server process: after a restart it starts again from
// zero, so every newer snapshot would look older than what the browser has seen and the
// screen would freeze. The model status carries an id made at each start (`boot_id`);
// a different one means the browser must forget its sequence and reconnect the stream.
export function serverRestarted(seenBootId: string | null, bootId: unknown): boolean {
  return typeof bootId === "string" && bootId !== "" && seenBootId !== null && bootId !== seenBootId;
}

/** What to do with a streamed event, given the newest sequence already applied:
 *  "drop" a duplicate or a stale replay (a reconnect replays from the first `after`),
 *  "refetch" when one or more events were missed, else "apply". */
export function eventDecision(seq: unknown, seenSeq: number): "drop" | "refetch" | "apply" {
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq <= seenSeq) return "drop";
  return seq > seenSeq + 1 ? "refetch" : "apply";
}

/** Ownership-traffic status needs re-reading only while another person's decision
 *  is pending or a time-limited grant can lapse. A standing self-service budget
 *  changes only through the user's own attempts, which trigger a re-read. */
export function needsOwnershipRefresh(value: { status: string; can_verify: boolean; self_service?: boolean }): boolean {
  return value.status === "pending" || (value.can_verify && value.self_service !== true);
}
