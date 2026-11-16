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

// A heartbeat is useful only if it covers every event the browser has seen.
// If the server reports a newer sequence, an event was missed: re-read both
// snapshot and audit. Malformed or stale heartbeats never suppress the backup.
export function heartbeatDecision(serverSeq: unknown, seenSeq: number): "healthy" | "refresh" | "ignore" {
  if (typeof serverSeq !== "number" || !Number.isSafeInteger(serverSeq) || serverSeq < 0 || serverSeq < seenSeq) {
    return "ignore";
  }
  return serverSeq > seenSeq ? "refresh" : "healthy";
}
