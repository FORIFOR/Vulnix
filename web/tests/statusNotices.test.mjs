import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/statusNotices.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { statusNotices, failureHeadline, stoppedHeadline } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("a healthy snapshot has no notices", () => {
  assert.deepEqual(statusNotices({ state: "completed", is_external_service: true, l2_isolation: { ok: true, reason: "" } }), []);
});

test("a save failure is shown even while the state still says completed", () => {
  const n = statusNotices({ state: "completed", persistence_error: "OSError" });
  assert.equal(n.length, 1);
  assert.equal(n[0].tone, "error");
  assert.match(n[0].detail, /OSError/);
});

test("a failed run shows its recorded cause, and says so when it is a save failure", () => {
  const n = statusNotices({ state: "failed", failure: { kind: "persistence", reason: "結果をディスクに保存できなかった" } });
  assert.match(n[0].title, /保存できなかった/);
  assert.equal(n[0].detail, "結果をディスクに保存できなかった");
  assert.match(failureHeadline({ state: "failed", failure: { kind: "run", reason: "Gateway が拒否しました" } }), /Gateway が拒否しました/);
  assert.match(failureHeadline({ state: "failed" }), /ログで理由/);
});

test("a stale failure record is not shown once the state is no longer failed", () => {
  assert.deepEqual(statusNotices({ state: "running", failure: { kind: "run", reason: "x" } }), []);
});

test("missing kernel isolation is shown for a real service only", () => {
  const iso = { ok: false, reason: "Linux 以外のホスト（darwin）" };
  assert.equal(statusNotices({ state: "idle", is_external_service: true, l2_isolation: iso }).length, 1);
  assert.deepEqual(statusNotices({ state: "idle", is_external_service: false, l2_isolation: iso }), []);
});

test("authority that was not restored is announced", () => {
  assert.equal(statusNotices({ state: "idle", authority_notice: "引き継いでいません" })[0].tone, "warn");
});

test("a stop is only called a stop when it was confirmed", () => {
  assert.match(stoppedHeadline({ state: "stopped", stop_report: { confirmed: true, survivors: [] } }), /緊急停止しました/);
  const h = stoppedHeadline({ state: "stopped", stop_report: { confirmed: false, survivors: [4242] } });
  assert.match(h, /確認できていません/);
  assert.doesNotMatch(h, /強制終了しました/);
});

test("a withdrawal whose worker is still alive is shown as not completed", () => {
  const n = statusNotices({ state: "idle", unstopped_workers: { host: "svc.example.test", pids: [4242] } });
  assert.equal(n[0].tone, "error");
  assert.match(n[0].detail, /4242/);
  assert.match(n[0].detail, /完了として扱いません/);
  assert.deepEqual(statusNotices({ state: "idle", unstopped_workers: null }), []);
});
