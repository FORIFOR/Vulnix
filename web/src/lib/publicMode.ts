// Public mode (VULNIX_PUBLIC_MODE=1): the instance behind a public tunnel serves the
// landing page and its static files only. Every API path is refused and every other
// page is sent to the landing page, so nothing that reaches the control plane (login,
// assets, findings, evidence, logs, settings) is reachable from the internet. The
// decision is made on the raw path, before any normalisation, and anything unusual
// (encoded characters, dot segments, double slashes) is refused.

export type PublicDecision = "allow" | "deny" | "redirect";

const STATIC_PREFIXES = ["/_next/static/", "/_next/image"];
const ROOT_FILES = new Set(["/favicon.ico", "/robots.txt"]);
const MEDIA_FILE = /^\/media\/[A-Za-z0-9][A-Za-z0-9_-]{0,80}\.(png|jpg|webp|mp4|webm)$/;

export function publicDecision(rawPath: string): PublicDecision {
  const p = rawPath || "/";
  const lower = p.toLowerCase();
  // the API, however it is spelled: encoded, doubled or dotted forms are refused too
  if (/^\/+(api|%61pi)(\/|%2f|$)/i.test(p) || lower.includes("/api/") || lower.includes("%2f") || /%2e|\/\.\.?(\/|$)|\/\//i.test(p)) {
    return /api/i.test(p) || /%61pi/i.test(p) ? "deny" : "redirect";
  }
  if (p === "/") return "allow";
  if (ROOT_FILES.has(p)) return "allow";
  if (STATIC_PREFIXES.some((pre) => p.startsWith(pre))) return "allow";
  if (MEDIA_FILE.test(p)) return "allow";
  return "redirect";
}

/** Pages rendered without the login redirect and without the app chrome. */
export function isPublicPage(path: string): boolean {
  return path === "/" || path === "/welcome" || path === "/login";
}
