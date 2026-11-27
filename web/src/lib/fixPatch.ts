/**
 * Minimal fix candidates for Python flow findings, as a unified diff the user reviews.
 *
 * Nothing here writes to the user's project: the patched text and the diff are returned
 * for display, download or testing on a copy. Only shapes with one well-understood,
 * behaviour-preserving fix are patched; everything else returns a reason for a manual fix.
 *
 * redirect: the destination expression in the sink call is wrapped in a helper that keeps a
 * same-site relative path ("/x", never "//x" or "/\x") and otherwise uses "/". Legitimate
 * relative redirects keep working; absolute and protocol-relative destinations stop.
 */
import { logicalLines, pythonFlow, type PythonFlowFinding } from "./pythonFlow";

export type FixPatch =
  | { ok: true; file: string; finding: PythonFlowFinding; patched: string; diff: string; changedLines: number }
  | { ok: false; file: string; finding: PythonFlowFinding; reason: string };

export const REDIRECT_HELPER = "_vulnix_safe_redirect";
const HELPER = [
  "",
  "",
  `def ${REDIRECT_HELPER}(target, default="/"):`,
  '    """Fix suggested by Vulnix: redirect only to a same-site relative path."""',
  "    from urllib.parse import urlsplit",
  '    value = str(target or "")',
  '    if value.startswith("/") and not value.startswith(("//", "/\\\\")) and "\\\\" not in value \\',
  "            and not urlsplit(value).netloc:",
  "        return value",
  "    return default",
];

/** The text between the parentheses that open at `open` (same line only). */
function firstArgSpan(line: string, open: number): [number, number] | null {
  let level = 0;
  let quote = "";
  for (let k = open; k < line.length; k++) {
    const c = line[k];
    if (quote) { if (c === "\\") k++; else if (c === quote) quote = ""; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === "(" || c === "[" || c === "{") level++;
    else if (c === ")" || c === "]" || c === "}") { level--; if (level === 0) return [open + 1, k]; }
    else if (c === "," && level === 1) return [open + 1, k];
  }
  return null;
}

type Edit = { at: number; remove: number; add: string[] };   // at: index in the original lines

/** A unified diff from explicit edits (sorted, non-overlapping), with 2 lines of context. */
function unifiedDiff(file: string, before: string[], edits: Edit[]): string {
  const out = [`--- a/${file}`, `+++ b/${file}`];
  let shift = 0;
  for (const e of [...edits].sort((a, b) => a.at - b.at)) {
    const from = Math.max(0, e.at - 2);
    const to = Math.min(before.length, e.at + e.remove + 2);
    const oldLen = to - from;
    const newLen = oldLen - e.remove + e.add.length;
    out.push(`@@ -${from + 1},${oldLen} +${from + 1 + shift},${newLen} @@`);
    for (let k = from; k < e.at; k++) out.push(" " + before[k]);
    for (let k = e.at; k < e.at + e.remove; k++) out.push("-" + before[k]);
    for (const line of e.add) out.push("+" + line);
    for (let k = e.at + e.remove; k < to; k++) out.push(" " + before[k]);
    shift += e.add.length - e.remove;
  }
  return out.join("\n") + "\n";
}

/** Fix candidates for the redirect findings in one Python file. */
export function redirectFixes(file: string, source: string): FixPatch[] {
  const findings = pythonFlow(source).filter((f) => f.kind === "redirect");
  if (!findings.length) return [];
  const lines = source.split("\n");
  const physical = new Set(logicalLines(source).map((l) => l.line));
  const edits: Edit[] = [];
  const results: FixPatch[] = [];
  for (const finding of findings) {
    const index = finding.line - 1;
    const line = lines[index] ?? "";
    const name = finding.sink.split(".").pop() ?? "";
    const call = line.search(new RegExp(`(?<![\\w.])(?:\\w+\\.)?${name}\\s*\\(`));
    const open = call < 0 ? -1 : line.indexOf("(", call);
    const span = open < 0 ? null : firstArgSpan(line, open);
    const arg = span ? line.slice(span[0], span[1]).trim() : "";
    if (!physical.has(finding.line) || !span || !arg || line.includes(REDIRECT_HELPER) || edits.some((e) => e.at === index)) {
      results.push({ ok: false, file, finding, reason: "移動先の式を1行の中で特定できないため、手動で修正してください" });
      continue;
    }
    const lead = line.slice(0, span[0]).length + (line.slice(span[0], span[1]).length - line.slice(span[0], span[1]).trimStart().length);
    edits.push({ at: index, remove: 1, add: [line.slice(0, lead) + `${REDIRECT_HELPER}(${arg})` + line.slice(lead + arg.length)] });
    results.push({ ok: true, file, finding, patched: "", diff: "", changedLines: 0 });
  }
  if (!edits.length) return results;
  if (!source.includes(`def ${REDIRECT_HELPER}(`)) {
    // after the last top-level import before the first definition
    let at = -1;
    for (let k = 0; k < lines.length; k++) {
      if (/^(?:from\s+\S+\s+import\s|import\s)/.test(lines[k])) {
        at = k;
        if (/\(\s*$/.test(lines[k])) while (at + 1 < lines.length && !/\)/.test(lines[at])) at++;
      } else if (/^(?:def |class |@|async def )/.test(lines[k])) break;
    }
    edits.push({ at: at + 1, remove: 0, add: HELPER });
  }
  const patchedLines: string[] = [];
  const byAt = [...edits].sort((a, b) => a.at - b.at);
  let k = 0;
  for (const e of byAt) {
    while (k < e.at) patchedLines.push(lines[k++]);
    patchedLines.push(...e.add);
    k += e.remove;
  }
  while (k < lines.length) patchedLines.push(lines[k++]);
  const patched = patchedLines.join("\n");
  const diff = unifiedDiff(file, lines, byAt);
  const changed = byAt.reduce((n, e) => n + Math.max(e.remove, e.add.length), 0);
  return results.map((r) => r.ok ? { ...r, patched, diff, changedLines: changed } : r);
}
