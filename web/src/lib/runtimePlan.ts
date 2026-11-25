import type { RuntimeCheck } from "./runtimeDefense";

type CheckId = RuntimeCheck[0];
type Candidate = { path: string; line: number; permits: boolean; denies: boolean };
export type PlannedCheck = { id: CheckId; locations: string[]; candidates: Candidate[] };

const rules: [CheckId, RegExp, RegExp][] = [
  ["authentication", /\b(?:next-auth|passport|authjs|django|fastapi|flask|express|next)\b|(?:^|\/)auth\.[a-z]+$/i, /\b(?:session|login|authenticate|unauthenticated)\b/i],
  ["authorization", /(?:^|\/)(?:middleware|auth|rbac|permissions?)\.[a-z]+$/i, /\b(?:role|permission|forbidden|authorize)\b/i],
  ["isolation", /(?:^|\/)(?:tenancy|db|database|tenantRegistry)\.[a-z]+$/i, /\b(?:tenant|organization|membership|crossTenant)\b/i],
  ["webhook", /(?:twilio|resend|svix|webhook)/i, /\b(?:webhook|verifyResendWebhook|signature)\b/i],
  ["input", /\b(?:next|express|react|django|fastapi|flask|dompurify)\b/i, /\b(?:sanitize|escape|parser|render)\b/i],
  ["saml", /(?:node-saml|passport-saml|saml2|pysaml|samlify)/i, /\b(?:saml|assertionSignature)\b/i],
  ["xml", /\b(?:libxmljs|defusedxml|lxml|fast-xml-parser|xml2js)\b/i, /\b(?:xml|entityResolver|externalEntity|doctype)\b/i],
  ["mfa", /(?:^|[/-])(?:totp|mfa|webauthn)(?:[.\/-]|$)|pyotp|otplib/i, /\b(?:totp|mfa|secondFactor|webauthn)\b/i],
  ["iam", /(?:terraform|\.tf(?:\.json)?$|cloudformation|type:\s*AWS::IAM::)/i, /\b(?:iam|principal|policy)\b/i],
  ["egress", /(?:networkpolicy|egress|netfilter)/i, /\b(?:egress|networkPolicy|outbound)\b/i],
  ["container", /(?:^|\/)Dockerfile(?:\.|$)|kind:\s*(?:Pod|Deployment)\b/i, /\b(?:runAsNonRoot|nonRoot|capabilities|containerUid)\b/i],
  ["agent", /(?:@anthropic-ai\/sdk|(?:^|\/)\.claude\/|(?:^|\/)call-tools\.|(?:^|\/)approval\.)/i, /\b(?:tool|operation|approval|allowlist)\b/i],
  ["integrity", /(?:^|\/)\.github\/workflows\/|(?:^|\/)Dockerfile(?:\.|$)/i, /\b(?:artifact|provenance|readOnlyRootFilesystem)\b/i],
  ["infrastructure", /\b(?:openvpn|wireguard|openldap|postfix|dovecot)\b/i, /\b(?:vpn|ldap|smtp)\b/i],
];

const testPath = /(?:^|\/)(?:test_[^/]+\.py|[^/]+\.(?:test|spec)\.[cm]?[jt]sx?)$/i;
const suites = /^[ \t]*(?:(?:it|test)\s*\(|(?:async\s+)?def\s+test_)/gm;
const conditions = /(?:\bexpect\(.*|\bassert(?:\s|[A-Z]).*)/;
const positive = /\b(?:200|201|204|allow|allowed|accepted|resolves|succeeded)\b|\.toBe\(\s*true\s*\)/i;
const negative = /\b(?:400|401|403|404|422|deny|denied|refused|rejected|rejects|forbidden|assertRaises|toThrow)\b|\.toBe\(\s*false\s*\)/i;

export function inspectRuntimeFile(
  plan: Map<CheckId, PlannedCheck>, path: string, body: string, manifestDependencies: string[],
) {
  const test = testPath.test(path);
  const configuration = /\.(?:ya?ml|tf(?:\.json)?)$/i.test(path);
  // Source snippets and test names remain in the worker. Only locations and inspection hints are returned.
  const source = test ? body.replace(/\/\*[\s\S]*?\*\//g, (match) => match.replace(/[^\n]/g, " "))
    .replace(/^\s*(?:\/\/|#)[^\n]*/gm, (match) => match.replace(/[^\n]/g, " ")) : "";
  const starts = Array.from(source.matchAll(suites)).slice(0, 80);
  for (const [id, technology, subject] of rules) {
    const locations = !test && (technology.test(path) || manifestDependencies.some((dependency) => technology.test(dependency)) ||
      (configuration && technology.test(body)));
    const candidates = starts.flatMap((match, index) => {
      const from = match.index + match[0].length;
      const end = Math.min(starts[index + 1]?.index ?? source.length, from + 8192);
      // Drop the declaration line if assertions are on later lines. A test's name never supplies a condition.
      const headerEnd = source.indexOf("\n", from);
      const raw = source.slice(headerEnd >= from && headerEnd < end && !conditions.test(source.slice(from, headerEnd))
        ? headerEnd + 1 : from, end);
      const code = raw.replace(/^\s*["'`][^\n]*?["'`]\s*,/, "");
      if (!subject.test(code)) return [];
      const assertions = code.split("\n").filter((line) => conditions.test(line));
      const permits = assertions.some((line) => positive.test(line));
      const denies = assertions.some((line) => negative.test(line));
      if (!permits && !denies) return [];
      return [{ path, line: source.slice(0, match.index).split("\n").length, permits, denies }];
    });
    if (!locations && !candidates.length) continue;
    const item = plan.get(id) ?? { id, locations: [], candidates: [] };
    if (locations && item.locations.length < 4) item.locations.push(path);
    item.candidates.push(...candidates.slice(0, Math.max(0, 6 - item.candidates.length)));
    plan.set(id, item);
  }
}
