// Public mode guard (Next.js 16 "proxy", formerly middleware).
// Only when VULNIX_PUBLIC_MODE=1 - the instance exposed through a public tunnel.
// The local operator instance (no variable) is unaffected.
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { publicDecision } from "@/lib/publicMode";

export function proxy(request: NextRequest) {
  if (process.env.VULNIX_PUBLIC_MODE !== "1") return NextResponse.next();
  // the raw request path, before Next.js normalises it
  const raw = new URL(request.url).pathname;
  const decision = publicDecision(raw);
  if (decision === "allow") {
    const res = NextResponse.next();
    res.headers.set("X-Robots-Tag", "noindex");
    return res;
  }
  if (decision === "deny") {
    return new NextResponse("Not Found", { status: 404, headers: { "Cache-Control": "no-store" } });
  }
  return NextResponse.redirect(new URL("/", request.url), 307);
}

export const config = {
  // every path, static files included: the decision itself allows what may be served
  matcher: "/:path*",
};
