// Live updates arrive as server-sent events. Some paths deliver them late or all at once
// (Cloudflare Quick Tunnels buffer event streams), so the page also re-reads the snapshot
// whenever the stream has been quiet for a while and the page is visible.

export const QUIET_MS = 6000;
export const POLL_EVERY_MS = 4000;

export function needsPoll(lastEventAt: number, now: number, visible: boolean, quietMs: number = QUIET_MS): boolean {
  return visible && now - lastEventAt >= quietMs;
}
