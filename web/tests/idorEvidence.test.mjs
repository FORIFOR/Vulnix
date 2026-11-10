import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
const source = readFileSync(new URL("../src/lib/idorEvidence.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const { latestIdorEvidence, currentIdorEvidence } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
const success = { check: "idor", request_path: "/api/accounts/B/secret", request_headers: { "X-Test-Account": "acct_A" }, status: 200, established: true, response: { caller_account: "acct_A", resource_owner: "acct_B", resource_id: "res_b_001" }, connected_ip: "127.0.0.1" };
const evidence = (data, id = "ev_latest") => ({ evidence_id: id, kind: "worker", saved_at: 1, audit_hash: "hash", content: JSON.stringify(data) });
test("200 with complete cross-account evidence confirms a read", () => {
  assert.deepEqual(latestIdorEvidence([evidence(success)]), { evidenceId: "ev_latest", caller: "acct_A", owner: "acct_B", status: 200, outcome: "read" });
});
test("newer 403 overrides older 200 and does not require a returned resource", () => {
  const denied = { ...success, status: 403, established: false, response: { caller_account: "acct_A", resource_owner: "acct_B" } };
  assert.deepEqual(latestIdorEvidence([evidence(success, "ev_old"), evidence(denied)]), { evidenceId: "ev_latest", caller: "acct_A", owner: "acct_B", status: 403, outcome: "blocked" });
});
test("malformed latest evidence never falls back to older success", () => {
  const result = latestIdorEvidence([evidence(success), { ...evidence(null, "ev_broken"), content: "invalid JSON" }]);
  assert.deepEqual(result, { evidenceId: "ev_broken", caller: null, owner: null, status: null, outcome: "unknown" });
});
test("empty evidence is explicitly unknown", () => {
  assert.deepEqual(latestIdorEvidence([]), { evidenceId: null, caller: null, owner: null, status: null, outcome: "unknown" });
});
for (const status of [201, 301, 401, 404, 500]) {
  test(`HTTP ${status} does not establish access or a successful fix`, () => {
    assert.equal(latestIdorEvidence([evidence({ ...success, status })]).outcome, "unknown");
  });
}
for (const data of [null, [], {}, { ...success, response: {} }, { ...success, response: { caller_account: "acct_A", resource_owner: "acct_A", resource_id: "res_a" } }, { ...success, response: { caller_account: "acct_A", resource_owner: "acct_B" } }, { ...success, established: "true" }, { ...success, check: "other" }, { ...success, status: "200" }]) {
  test(`incomplete or incompatible schema stays unknown: ${JSON.stringify(data)}`, () => {
    assert.equal(latestIdorEvidence([evidence(success, "ev_old"), evidence(data)]).outcome, "unknown");
  });
}

for (const verdict of ["unverified", "aborted"]) {
  test(`${verdict} after older 200 does not present stale evidence as current`, () => {
    assert.deepEqual(currentIdorEvidence({ verdict, evidence: [evidence(success)] }), {
      evidenceId: null, caller: null, owner: null, status: null, outcome: "unavailable",
    });
  });
}
for (const [inVerification, busy] of [[true, false], [false, true]]) {
  test(`pending verification hides previous success (snapshot=${inVerification}, busy=${busy})`, () => {
    assert.deepEqual(currentIdorEvidence({ verdict: "proven", _in_verification: inVerification, evidence: [evidence(success)] }, busy), {
      evidenceId: null, caller: null, owner: null, status: null, outcome: "pending",
    });
  });
}
test("completed verification may present its attached evidence", () => {
  assert.equal(currentIdorEvidence({ verdict: "proven", evidence: [evidence(success)] }).outcome, "read");
});
