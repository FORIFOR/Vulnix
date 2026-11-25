// Streaming proxy to the Python control plane (127.0.0.1 only).
// Enforces same-origin + X-Aegis-Request on state-changing requests (CSRF guard),
// and forwards the session cookie both ways so the control plane can
// authenticate the operator. The CSRF guard and the session cookie are
// independent; neither replaces the other.
import type { NextRequest } from "next/server";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { catalogSource } from "@/lib/catalogUpdate";
import { clientIp, IpLimiter } from "@/lib/ipLimit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const UPSTREAM = process.env.AEGIS_API ?? "http://127.0.0.1:8787";

// The UI is a local tool. It answers only when addressed by a loopback name, so a
// page that reaches it through another hostname (DNS rebinding) or a LAN client
// gets nothing - not even the pre-login surface. Extra names can be allowed
// explicitly with AEGIS_UI_ALLOWED_HOSTS (comma separated host[:port]).
const LOCAL_NAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);
const EXTRA_HOSTS = new Set(
  (process.env.AEGIS_UI_ALLOWED_HOSTS ?? "").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean),
);

function hostAllowed(host: string | null): boolean {
  if (!host) return false;
  const h = host.trim().toLowerCase();
  if (EXTRA_HOSTS.has(h)) return true;
  // exactly  name  or  name:port  - nothing before, nothing after
  const m = /^(localhost|127\.0\.0\.1|\[::1\])(?::(\d{1,5}))?$/.exec(h);
  return m !== null && LOCAL_NAMES.has(m[1]);
}

// per-client limits for requests that came through Cloudflare (public beta)
const limiter = new IpLimiter();

function limited(req: NextRequest, method: string, path: string[]): Response | null {
  const ip = clientIp(req.headers.get("cf-connecting-ip"));
  if (!ip) return null;                       // local use: no per-client limit
  const rule = limiter.check(ip, method, path.join("/"));
  if (!rule) return null;
  return Response.json({ error: "リクエストが多すぎます。少し時間をおいてからお試しください" },
                       { status: 429, headers: { "Retry-After": "60" } });
}

function misdirected() {
  return Response.json({ error: "misdirected request" }, { status: 421 });
}

function upstreamUrl(req: NextRequest, path: string[]) {
  const safe = path.map(encodeURIComponent).join("/");
  return `${UPSTREAM}/api/${safe}${req.nextUrl.search}`;
}

// PR-C: a diagnosis operation names its request (docs/DIAGNOSIS_ACTIONS.md). Passed on
// only in the expected form; the control plane checks it again.
function idempotency(req: NextRequest, headers: Record<string, string>) {
  const key = req.headers.get("idempotency-key");
  if (key && /^[A-Za-z0-9_-]{16,128}$/.test(key)) headers["Idempotency-Key"] = key;
  return headers;
}

function withCookie(req: NextRequest, headers: Record<string, string>) {
  const cookie = req.headers.get("cookie");
  if (cookie) headers["Cookie"] = cookie;
  return headers;
}

function relay(res: Response, extra: Record<string, string>) {
  const out = new Headers(extra);
  const setCookie = res.headers.get("set-cookie");
  if (setCookie) out.append("set-cookie", setCookie);
  return out;
}

export async function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  if (!hostAllowed(req.headers.get("host"))) return misdirected();
  const { path } = await ctx.params;
  const refused = limited(req, "GET", path);
  if (refused) return refused;
  const headers: Record<string, string> = {};
  const lastId = req.headers.get("last-event-id");
  if (lastId) headers["Last-Event-ID"] = lastId;
  let res: Response;
  try {
    res = await fetch(upstreamUrl(req, path), {
      headers: withCookie(req, headers),
      cache: "no-store",
      signal: req.signal,
    });
  } catch {
    return Response.json({ error: "制御プレーンに接続できません" }, { status: 502 });
  }
  return new Response(res.body, {
    status: res.status,
    headers: relay(res, {
      "Content-Type": res.headers.get("content-type") ?? "application/json",
      "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no",
    }),
  });
}

let catalogTransfer = false;
const previousCatalogAttempts = new Map<string, number>();

async function refreshCatalog(req: NextRequest) {
  const source = catalogSource(req.headers.get("x-vulnix-catalog"));
  if (!source) return Response.json({ error: "未対応のカタログです。" }, { status: 400 });
  const session = await fetch(`${UPSTREAM}/api/auth/me`, {
    headers: withCookie(req, {}), cache: "no-store", signal: AbortSignal.timeout(5000),
  });
  const identity = session.ok ? await session.json() : null;
  if (!identity?.session) return Response.json({ error: "ログインしてください。" }, { status: 401 });
  if (catalogTransfer || Date.now() - (previousCatalogAttempts.get(source) ?? 0) < 60_000)
    return Response.json({ error: "別の更新が実行中か、直前に更新したカタログです。" }, { status: 429 });
  previousCatalogAttempts.set(source, Date.now());
  catalogTransfer = true;
  const child = spawn("python3", ["-I", "-u", resolve(process.cwd(), "../aegis/public_catalog.py"), source], {
    stdio: ["ignore", "pipe", "ignore"], timeout: 8 * 60_000,
  });
  const stop = () => { child.kill(); };
  req.signal.addEventListener("abort", stop, { once: true });
  if (req.signal.aborted) stop();
  const stream = child.stdout[Symbol.asyncIterator]();
  const success = new Promise<boolean>((done) => {
    child.once("error", () => done(false));
    child.once("close", (code) => {
      req.signal.removeEventListener("abort", stop);
      catalogTransfer = false;
      done(code === 0);
    });
  });
  return new Response(new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const result = await stream.next();
        if (!result.done) controller.enqueue(new Uint8Array(result.value));
        else if (await success) controller.close();
        else controller.error(new Error("catalog archive incomplete"));
      } catch (error) {
        stop();
        controller.error(error);
      }
    },
    cancel() { stop(); },
  }), { headers: { "Content-Type": "application/x-ndjson", "Cache-Control": "no-store, no-transform", "X-Accel-Buffering": "no" } });
}

export async function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const origin = req.headers.get("origin");
  const host = req.headers.get("host");
  if (!hostAllowed(host)) return misdirected();
  let originHost: string | null = null;
  try {
    originHost = origin ? new URL(origin).host : null;
  } catch {
    originHost = null;
  }
  // same-origin AND that origin is one of the allowed local names
  if (req.headers.get("x-aegis-request") !== "1" || !originHost || originHost !== host || !hostAllowed(originHost)) {
    return Response.json({ error: "csrf check failed" }, { status: 403 });
  }
  const { path } = await ctx.params;
  const refused = limited(req, "POST", path);
  if (refused) return refused;
  if (path.length === 2 && path[0] === "catalog" && path[1] === "refresh") {
    const unexpected = () => Response.json({ error: "引数は指定できません。" }, { status: 400 });
    if (req.nextUrl.search || (req.headers.get("content-length") ?? "0") !== "0" || req.headers.has("transfer-encoding"))
      return unexpected();
    // Next may expose an empty POST as a stream. Reject actual bytes without buffering a request body.
    if (req.body) {
      const reader = req.body.getReader();
      try {
        if (!(await reader.read()).done) return unexpected();
      } finally { await reader.cancel().catch(() => {}); }
    }
    try { return await refreshCatalog(req); }
    catch { return Response.json({ error: "カタログ更新を開始できませんでした。" }, { status: 502 }); }
  }
  try {
    const res = await fetch(upstreamUrl(req, path), {
      method: "POST",
      headers: withCookie(req, idempotency(req, { "Content-Type": "application/json", "X-Aegis-Request": "1" })),
      body: await req.text(),
      cache: "no-store",
    });
    return new Response(res.body, {
      status: res.status,
      headers: relay(res, { "Content-Type": "application/json; charset=utf-8" }),
    });
  } catch {
    return Response.json({ error: "制御プレーンに接続できません" }, { status: 502 });
  }
}
