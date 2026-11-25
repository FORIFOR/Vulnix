import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const { outputText } = ts.transpileModule(readFileSync(new URL("../src/lib/catalogUpdate.ts", import.meta.url), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
});
const { fetchCatalogs } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("manual update requests fixed public sources and isolates one provider failure", async () => {
  const urls = [];
  const result = await fetchCatalogs(async (raw, init) => {
    const url = new URL(raw);
    urls.push(url);
    assert.equal(init.body, undefined);
    assert.equal(init.redirect, "error");
    if (url.hostname === "services.nvd.nist.gov") {
      assert.equal(url.searchParams.get("resultsPerPage"), "100");
      return Response.json({ format: "NVD_CVE", vulnerabilities: [], totalResults: 0 });
    }
    assert.equal(url.hostname, "osv-vulnerabilities.storage.googleapis.com");
    if (url.pathname.startsWith("/Go/")) return new Response("unavailable", { status: 500 });
    if (url.pathname.endsWith(".csv")) {
      assert.deepEqual(init.headers, { Range: "bytes=0-65535" });
      return new Response("2026-01-01T00:00:00Z,GHSA-test\n2026-01-01T00:00:00Z,https://elsewhere.invalid/\n");
    }
    assert.match(url.pathname, /^\/(?:npm|PyPI)\/GHSA-test\.json$/);
    return Response.json({ id: "GHSA-test", affected: [] });
  }, new Date("2026-01-02T12:00:00.000Z"));
  assert.equal(urls.length, 6);
  assert.deepEqual(result.map(({ source, failed, records }) => [source, !!failed, records?.length]), [
    ["NVD", false, 0], ["npm", false, 1], ["PyPI", false, 1], ["Go", true, undefined],
  ]);
});
