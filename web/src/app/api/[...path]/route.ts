// Streaming proxy to the Python control plane (127.0.0.1 only).
// Enforces same-origin + X-Aegis-Request on state-changing requests (CSRF guard),
// and forwards the session cookie both ways so the control plane can
// authenticate the operator. The CSRF guard and the session cookie are
// independent; neither replaces the other.
import type { NextRequest } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const UPSTREAM = process.env.AEGIS_API ?? "http://127.0.0.1:8787";

function upstreamUrl(req: NextRequest, path: string[]) {
  const safe = path.map(encodeURIComponent).join("/");
  return `${UPSTREAM}/api/${safe}${req.nextUrl.search}`;
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
  const { path } = await ctx.params;
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

export async function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const origin = req.headers.get("origin");
  const host = req.headers.get("host");
  if (req.headers.get("x-aegis-request") !== "1" || !origin || new URL(origin).host !== host) {
    return Response.json({ error: "csrf check failed" }, { status: 403 });
  }
  const { path } = await ctx.params;
  try {
    const res = await fetch(upstreamUrl(req, path), {
      method: "POST",
      headers: withCookie(req, { "Content-Type": "application/json", "X-Aegis-Request": "1" }),
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
