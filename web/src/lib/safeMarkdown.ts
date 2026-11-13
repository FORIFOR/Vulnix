/**
 * A small, safe Markdown subset for AI answers.
 *
 * The model's answer is untrusted text. It is parsed into a plain data tree that the
 * React renderer turns into elements, so every string ends up as escaped text:
 * - no HTML is ever produced or injected (no dangerouslySetInnerHTML anywhere);
 * - raw HTML tags in the text are dropped from display (code spans/blocks keep their
 *   content as literal, escaped text — a payload shown as an example is never run);
 * - links and images are never rendered as links or images: only their visible text
 *   remains, so no URL (javascript:, data:, or any other) becomes clickable or loads.
 *
 * Supported: paragraphs (with line breaks), headings, bullet and numbered lists
 * (indented continuation lines), fenced code blocks, **bold**, *italic*, `code`.
 */

export type Inline =
  | { t: "text"; v: string }
  | { t: "br" }
  | { t: "b"; c: Inline[] }
  | { t: "i"; c: Inline[] }
  | { t: "code"; v: string };

export type Block =
  | { t: "p"; c: Inline[] }
  | { t: "h"; c: Inline[] }
  | { t: "ul"; items: Inline[][] }
  | { t: "ol"; start: number; items: Inline[][] }
  | { t: "code"; v: string };

export const MAX_MARKDOWN_CHARS = 20000;

const BULLET = /^\s{0,3}[-*+]\s+(.*)$/;
const NUMBERED = /^\s{0,3}(\d{1,9})[.)]\s+(.*)$/;
const HEADING = /^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$/;
const FENCE = /^\s{0,3}(```|~~~)/;
const RULE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/;

// Names of HTML elements. Only these are treated as tags, so text such as
// `List<String>` or `a < b > c` is kept.
const TAG_NAMES =
  "a|abbr|audio|b|base|body|br|button|center|code|details|dialog|div|em|embed|font|form|frame|frameset|" +
  "h[1-6]|head|html|i|iframe|img|input|label|li|link|marquee|math|meta|object|ol|option|p|pre|s|script|" +
  "select|source|span|strong|style|summary|svg|table|tbody|td|template|textarea|th|thead|tr|u|ul|video";
const TAG = new RegExp(`</?(?:${TAG_NAMES})(?=[\\s/>])[^<>]{0,500}>`, "gi");
const BLOCK_ELEMENTS = ["script", "style", "iframe", "object", "template", "svg", "math"];

/** Remove every `open ... close` span (case-insensitive). One left-to-right scan
 *  with indexOf: linear, so hostile input cannot make it slow. An opener with no
 *  closer is left for the per-line tag pass. */
function removeSpans(s: string, open: string, close: string, needsBoundary: boolean): string {
  const lower = s.replace(/[A-Z]+/g, (c) => c.toLowerCase());   // ASCII only: indexes stay aligned
  let out = "";
  let pos = 0;
  for (;;) {
    let at = lower.indexOf(open, pos);
    while (needsBoundary && at !== -1 && !/[\s/>]/.test(lower[at + open.length] ?? "")) at = lower.indexOf(open, at + 1);
    if (at === -1) break;
    const end = lower.indexOf(close, at + open.length);
    if (end === -1) break;
    const gt = lower.indexOf(">", end + close.length - 1);
    if (gt === -1) break;
    out += s.slice(pos, at);
    pos = gt + 1;
  }
  return out + s.slice(pos);
}

/** Whole-text pass (outside code fences): elements whose content is never text
 *  (script, style, ...) and comments go, across lines. */
function stripHtmlBlocks(s: string): string {
  let out = removeSpans(s, "<!--", "-->", false);
  for (const name of BLOCK_ELEMENTS) out = removeSpans(out, `<${name}`, `</${name}`, true);
  return out;
}

/** Per line: remaining tags are dropped from display. */
function stripTags(s: string): string {
  return s.replace(TAG, "");
}

/** Links and images keep only their visible text; the target is discarded.
 *  Bounded patterns: linear in the input, whatever the model sends. */
function dropLinkTargets(s: string): string {
  const target = String.raw`\((?:[^()\n]|\([^()\n]{0,100}\)){0,500}\)`;
  return s
    .replace(new RegExp(String.raw`!\[([^\[\]\n]{0,300})\]` + target, "g"), "$1")
    .replace(new RegExp(String.raw`\[([^\[\]\n]{1,300})\]` + target, "g"), "$1")
    .replace(/<((?:https?|ftp|mailto|javascript|data|vbscript|file):[^<>\s]{0,2000})>/gi, "$1")
    .replace(/\]\([^\s)]{0,4000}\)?/g, "]");   // a target past those bounds is still not shown
}

function emphasis(s: string): Inline[] {
  const out: Inline[] = [];
  const re = /\*\*([^\n]{1,300}?)\*\*|__([^\n]{1,300}?)__|\*(?![\s*])([^\n]{1,300}?)(?<![\s*])\*/g;
  let last = 0;
  for (let m = re.exec(s); m; m = re.exec(s)) {
    if (m.index > last) out.push({ t: "text", v: s.slice(last, m.index) });
    if (m[1] !== undefined || m[2] !== undefined) out.push({ t: "b", c: emphasis(m[1] ?? m[2]) });
    else out.push({ t: "i", c: emphasis(m[3]) });
    last = m.index + m[0].length;
  }
  if (last < s.length) out.push({ t: "text", v: s.slice(last) });
  return out;
}

/** One line of inline Markdown. Code spans are taken first and kept literal. */
export function parseInline(line: string): Inline[] {
  const out: Inline[] = [];
  const parts = line.split(/(`[^`\n]+`)/g);
  for (const part of parts) {
    if (!part) continue;
    if (part.length > 2 && part.startsWith("`") && part.endsWith("`")) {
      out.push({ t: "code", v: part.slice(1, -1) });
    } else {
      const text = stripTags(dropLinkTargets(part));
      if (text) out.push(...emphasis(text));
    }
  }
  return out;
}

function inlineLines(lines: string[]): Inline[] {
  const out: Inline[] = [];
  lines.forEach((l, i) => {
    if (i > 0) out.push({ t: "br" });
    out.push(...parseInline(l));
  });
  return out;
}

/** Remove HTML blocks from the text between code fences only, finding fences by
 *  exactly the rule the block parser uses, so code always keeps its content. */
function stripHtmlOutsideFences(lines: string[]): string[] {
  const out: string[] = [];
  let run: string[] = [];
  const flush = () => {
    if (run.length) out.push(...stripHtmlBlocks(run.join("\n")).split("\n"));
    run = [];
  };
  for (let i = 0; i < lines.length; i++) {
    const fence = FENCE.exec(lines[i]);
    if (!fence) {
      run.push(lines[i]);
      continue;
    }
    flush();
    out.push(lines[i]);
    for (i++; i < lines.length; i++) {
      out.push(lines[i]);
      if (lines[i].trimStart().startsWith(fence[1])) break;
    }
  }
  flush();
  return out;
}

export function parseMarkdown(src: string): Block[] {
  const text = String(src ?? "").slice(0, MAX_MARKDOWN_CHARS).replace(/\r\n?/g, "\n");
  const lines = stripHtmlOutsideFences(text.split("\n"));
  const blocks: Block[] = [];
  let para: string[] = [];
  let list: { kind: "ul" | "ol"; start: number; items: string[][] } | null = null;

  const flushPara = () => {
    if (para.length) blocks.push({ t: "p", c: inlineLines(para) });
    para = [];
  };
  const flushList = () => {
    if (!list) return;
    const items = list.items.map(inlineLines);
    blocks.push(list.kind === "ul" ? { t: "ul", items } : { t: "ol", start: list.start, items });
    list = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fence = FENCE.exec(line);
    if (fence) {
      flushPara();
      flushList();
      const body: string[] = [];
      for (i++; i < lines.length && !lines[i].trimStart().startsWith(fence[1]); i++) body.push(lines[i]);
      blocks.push({ t: "code", v: body.join("\n") });
      continue;
    }
    if (!line.trim()) {
      flushPara();
      flushList();
      continue;
    }
    if (RULE.test(line)) {
      flushPara();
      flushList();
      continue;
    }
    const h = HEADING.exec(line);
    if (h) {
      flushPara();
      flushList();
      blocks.push({ t: "h", c: parseInline(h[1]) });
      continue;
    }
    const b = BULLET.exec(line);
    const n = b ? null : NUMBERED.exec(line);
    if (b || n) {
      flushPara();
      const kind = b ? "ul" : "ol";
      if (!list || list.kind !== kind) {
        flushList();
        list = { kind, start: n ? Number(n[1]) : 1, items: [] };
      }
      list.items.push([b ? b[1] : n![2]]);
      continue;
    }
    if (list && /^\s+\S/.test(line)) {            // indented continuation of the last item
      list.items[list.items.length - 1].push(line.trim());
      continue;
    }
    flushList();
    para.push(line.replace(/^\s{0,3}>\s?/, ""));
  }
  flushPara();
  flushList();
  return blocks;
}
