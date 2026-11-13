import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/safeMarkdown.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { parseMarkdown, parseInline } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

const flat = (nodes) => nodes.map((n) => (n.t === "text" || n.t === "code" ? n.v : n.t === "br" ? "\n" : flat(n.c))).join("");
const allText = (blocks) => blocks.map((b) => (b.t === "code" ? b.v : b.t === "ul" || b.t === "ol" ? b.items.map(flat).join("|") : flat(b.c))).join("\n");

test("the real answer shape renders as a numbered list with bold and code, no stray markers", () => {
  const md = "以下の通りです。\n\n1. **検出理由**\n   検索パラメータ `q` において未エスケープのクエリ連結\n2. **対策**\n   プレースホルダを使う";
  const blocks = parseMarkdown(md);
  assert.deepEqual(blocks.map((b) => b.t), ["p", "ol"]);
  const ol = blocks[1];
  assert.equal(ol.items.length, 2);
  assert.equal(ol.items[0][0].t, "b");
  assert.ok(ol.items[0].some((n) => n.t === "code" && n.v === "q"));
  assert.ok(!allText(blocks).includes("**"));
  assert.ok(!allText(blocks).includes("`"));
});

test("raw HTML is never produced and tags are dropped from display", () => {
  const blocks = parseMarkdown('注意<script>alert(1)</script><img src=x onerror=alert(1)><b>強調</b><!-- hidden -->');
  const text = allText(blocks);
  assert.ok(!/<|>/.test(text), text);
  assert.ok(!text.includes("hidden"));
  assert.ok(text.includes("注意") && text.includes("強調"));
});

test("links and images keep only their text; no URL survives as a target", () => {
  const blocks = parseMarkdown("[ここを押す](javascript:alert(1)) と ![図](https://evil.example/x.png) と <javascript:alert(1)>");
  const json = JSON.stringify(blocks);
  assert.ok(!/href|src/.test(json));
  assert.ok(!json.includes("evil.example"));
  assert.ok(allText(blocks).includes("ここを押す"));
  assert.ok(allText(blocks).includes("図"));
  for (const b of blocks) for (const n of b.c ?? []) assert.ok(["text", "br", "b", "i", "code"].includes(n.t));
});

test("code keeps a payload as literal text (shown, never parsed or run)", () => {
  const inline = parseInline("例: `<script>alert(1)</script>`");
  assert.equal(inline.at(-1).t, "code");
  assert.equal(inline.at(-1).v, "<script>alert(1)</script>");
  const blocks = parseMarkdown("```sql\nSELECT * FROM t WHERE q = '' OR 1=1 --\n```");
  assert.deepEqual(blocks, [{ t: "code", v: "SELECT * FROM t WHERE q = '' OR 1=1 --" }]);
});

test("headings, bullets and line breaks", () => {
  const blocks = parseMarkdown("### 原因\n- 一つ目\n- 二つ目\n\n一行目\n二行目");
  assert.deepEqual(blocks.map((b) => b.t), ["h", "ul", "p"]);
  assert.equal(blocks[1].items.length, 2);
  assert.ok(blocks[2].c.some((n) => n.t === "br"));
});

test("snake_case and lone asterisks are left alone", () => {
  assert.equal(flat(parseInline("user_id と a * b")), "user_id と a * b");
});

test("oversized input is bounded", () => {
  const blocks = parseMarkdown("あ".repeat(50000));
  assert.ok(allText(blocks).length <= 20000);
});

test("script and style contents are not shown, and a link target with parentheses leaves nothing behind", () => {
  const text = allText(parseMarkdown("前<script>alert('xss')</script><style>p{}</style>後 [詳細はこちら](javascript:alert(1)) 終"));
  assert.equal(text, "前後 詳細はこちら 終");
});

test("multi-line script blocks, autolinks and generic-looking text", () => {
  const blocks = parseMarkdown("前\n<SCRIPT type=x>\nalert(1)\n</script >\n後 <https://example.test/a> と List<String> と a < b > c");
  const text = allText(blocks);
  assert.ok(!text.includes("alert"));
  assert.ok(text.includes("https://example.test/a"));
  assert.ok(text.includes("List<String>"));
  assert.ok(text.includes("a < b > c"));
});

test("a script example inside a code fence is kept literally", () => {
  const blocks = parseMarkdown("```html\n<script>alert(1)</script>\n```");
  assert.deepEqual(blocks, [{ t: "code", v: "<script>alert(1)</script>" }]);
});

test("Unicode case folding cannot misalign the block scan", () => {
  const text = allText(parseMarkdown("İİİ<script>x</script>残る"));
  assert.equal(text, "İİİ残る");
});

test("hostile inputs at the size cap parse quickly (no quadratic blow-up)", () => {
  const cases = ["![".repeat(9990), "[".repeat(19990) + "](", "[a".repeat(9999), "*a ".repeat(6666),
    "<script>".repeat(2500), "<!--".repeat(5000), "**".repeat(10000), "`".repeat(20000), "<a ".repeat(6666)];
  for (const c of cases) {
    const t0 = performance.now();
    parseMarkdown(c);
    const ms = performance.now() - t0;
    assert.ok(ms < 60, `${JSON.stringify(c.slice(0, 6))}… took ${ms.toFixed(1)} ms`);
  }
});

test("a fence indented under a list item keeps its payload example literally", () => {
  const blocks = parseMarkdown("1. 例:\n   ```html\n   <script>alert(1)</script>\n   ```");
  const code = blocks.find((b) => b.t === "code");
  assert.ok(code && code.v.includes("<script>alert(1)</script>"), JSON.stringify(blocks));
});

test("mismatched fence markers: content stays code, and script text outside never shows", () => {
  const a = parseMarkdown("```\n~~~\n<script>x</script>\n```");
  assert.ok(a.find((b) => b.t === "code").v.includes("<script>x</script>"));
  const b = parseMarkdown("```\na\n   ```\n<script>alert(1)</script>\n```");
  const outside = b.filter((x) => x.t !== "code");
  assert.ok(!JSON.stringify(outside).includes("alert"), JSON.stringify(b));
});

test("an over-long link target is still not shown", () => {
  const text = allText(parseMarkdown(`[押す](http://evil.example/${"a".repeat(800)})`));
  assert.ok(!text.includes("evil.example"), text.slice(0, 80));
});
