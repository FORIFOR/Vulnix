import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";

const require = createRequire(import.meta.url);
const source = readFileSync(new URL("../src/components/findings/CookieCheckList.tsx", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
});
const renderedModule = { exports: {} };
new Function("require", "module", "exports", outputText)(require, renderedModule, renderedModule.exports);
const { CookieCheckList } = renderedModule.exports;

test("mixed Cookie verdicts display separately without values", () => {
  const html = renderToStaticMarkup(React.createElement(CookieCheckList, { checks: [
    { name: "auth", purpose: "session", verdict: "detected", gaps: ["HttpOnly"] },
    { name: "lang", purpose: "non_session", verdict: "none", gaps: [] },
    { name: "unknown", purpose: "unknown", verdict: "candidate", gaps: ["Secure"] },
  ] }));
  assert.match(html, /auth.*認証用（所有者仕様）.*属性不足・不一致を確認/);
  assert.match(html, /lang.*一般用途（所有者仕様）.*認証セッションの判定対象外/);
  assert.match(html, /unknown.*用途未確認.*確認候補/);
  assert.doesNotMatch(html, /secret-token|private-value/);
});
