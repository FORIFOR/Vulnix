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
/** Limits for the whole entrance, whatever the address (rotating addresses do not help). */
export const GLOBAL_RULES: Rule[] = [
  { name: "register-all", match: (m, p) => m === "POST" && p === "auth/register", limit: 20, windowMs: 60_000 },
];

/** The key a client is limited by: an IPv4 address, or the /64 network of an IPv6 address
 *  (one IPv6 subscriber usually holds a whole /64 and could rotate through it). */
export function limitKey(ip: string): string {
  if (!ip.includes(":")) return ip;
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) return mapped[1];                        // IPv4-mapped: the IPv4 address itself
  const [head, tail = ""] = ip.toLowerCase().split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = ip.includes("::") ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t] : h;
  return groups.slice(0, 4).map((g) => (g || "0").replace(/^0+(?=.)/, "")).join(":") + "::/64";
}

export class IpLimiter {
  private hits = new Map<string, number[]>();
  constructor(private rules: Rule[] = RULES, private maxKeys = 50_000, private globalRules: Rule[] = GLOBAL_RULES) {}

  /** null when allowed (and recorded), else the name of the rule that refused. */
  check(ip: string, method: string, path: string, now: number = Date.now()): string | null {
    const who = limitKey(ip);
    const keyed = [
      ...this.rules.filter((r) => r.match(method, path)).map((r) => ({ r, k: `${r.name}|${who}` })),
      ...this.globalRules.filter((r) => r.match(method, path)).map((r) => ({ r, k: `${r.name}|*` })),
    ];
    for (const { r, k } of keyed) {
      const recent = (this.hits.get(k) ?? []).filter((t) => now - t < r.windowMs);
      this.hits.set(k, recent);
      if (recent.length >= r.limit) return r.name;
    }
    for (const { k } of keyed) this.hits.get(k)!.push(now);
    if (this.hits.size > this.maxKeys) this.evict();
    return null;
  }

  /** Bounded memory under a flood: drop the keys with the fewest recent hits first, so the
   *  counters of clients who are actually near a limit survive a flood of one-off addresses. */
  private evict(): void {
    const target = Math.floor(this.maxKeys * 0.9);
    const order = [...this.hits.entries()]
      .filter(([k]) => !k.endsWith("|*"))
      .sort((a, b) => a[1].length - b[1].length || (a[1].at(-1) ?? 0) - (b[1].at(-1) ?? 0));
    for (const [k] of order) {
      if (this.hits.size <= target) break;
      this.hits.delete(k);
    }
  }
}

/** The client address Cloudflare reports, if it looks like one. */
export function clientIp(header: string | null): string | null {
  const v = (header ?? "").trim();
  return /^[0-9a-fA-F:.]{2,45}$/.test(v) ? v : null;
}
