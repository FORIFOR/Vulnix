import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = readFileSync(new URL("../src/lib/labels.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
});
const { completedHeadline, threatFeedSummary } = await import(
  `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`
);

test("completed summary keeps candidates and unconfirmed rechecks out of problem count", () => {
  const findings = [
    { evidence_status: "candidate", demo_fixture: false },
    { evidence_status: "not_reproduced", demo_fixture: false },
    { evidence_status: "detected", demo_fixture: false },
    { evidence_status: "proven", demo_fixture: false },
    { evidence_status: "proven", demo_fixture: true },
  ];
  const summary = completedHeadline(findings);
  assert.match(summary, /証拠のある問題を2件/);
  assert.match(summary, /未確認の候補1件/);
  assert.match(summary, /再現できなかった所見1件/);
  assert.doesNotMatch(completedHeadline(findings.slice(0, 2)), /[12]件の問題/);
});

test("threat feed count is unknown until status arrives, but measured zero remains zero", () => {
  assert.equal(threatFeedSummary(undefined), "脅威情報の件数を取得できていません。");
  assert.match(threatFeedSummary({ cve_count: 0, kev_count: 0, last_synced_at: 0 }),
    /NVD 登録 0 件 \/ CISA KEV 悪用確認 0 件/);
  assert.match(
    threatFeedSummary({ cve_count: 2, kev_count: 2, last_synced_at: 1000, freshness: "stale", stale: true, last_sync_error: "URLError: offline" }),
    /更新期限超過（要同期）・直近の同期に失敗（以前のデータを保持）/,
  );
  assert.match(
    threatFeedSummary({ cve_count: 0, kev_count: 0, last_synced_at: 0, freshness: "unfetched" }),
    /フィード未取得/,
  );
});
