// Per-client limits at the public entrance. Requests that arrive through Cloudflare carry
// CF-Connecting-IP (set by Cloudflare's edge; the UI listens on 127.0.0.1, so only the
// tunnel reaches it). The control plane behind the proxy cannot see clients at all, so
// this is the only place a per-person limit can be applied.

export interface Rule { name: string; match: (method: string, path: string) => boolean; limit: number; windowMs: number }

export const RULES: Rule[] = [
  { name: "register", match: (m, p) => m === "POST" && p === "auth/register", limit: 3, windowMs: 60_000 },
  { name: "login", match: (m, p) => m === "POST" && p === "auth/login", limit: 10, windowMs: 60_000 },
  { name: "write", match: (m) => m === "POST", limit: 60, windowMs: 60_000 },
  { name: "any", match: () => true, limit: 240, windowMs: 60_000 },
];

export class IpLimiter {
  private hits = new Map<string, number[]>();
  constructor(private rules: Rule[] = RULES, private maxKeys = 50_000) {}

  /** null when allowed (and recorded), else the name of the rule that refused. */
  check(ip: string, method: string, path: string, now: number = Date.now()): string | null {
    const applicable = this.rules.filter((r) => r.match(method, path));
    for (const r of applicable) {
      const k = `${r.name}|${ip}`;
      const recent = (this.hits.get(k) ?? []).filter((t) => now - t < r.windowMs);
      this.hits.set(k, recent);
      if (recent.length >= r.limit) return r.name;
    }
    for (const r of applicable) this.hits.get(`${r.name}|${ip}`)!.push(now);
    if (this.hits.size > this.maxKeys) this.hits.clear();      // bounded memory under a flood
    return null;
  }
}

/** The client address Cloudflare reports, if it looks like one. */
export function clientIp(header: string | null): string | null {
  const v = (header ?? "").trim();
  return /^[0-9a-fA-F:.]{2,45}$/.test(v) ? v : null;
}
