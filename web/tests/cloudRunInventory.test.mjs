import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = readFileSync(new URL("../src/lib/cloudRunInventory.ts", import.meta.url), "utf8")
  .replace('from "yaml"', `from "${import.meta.resolve("yaml")}"`);
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
});
const { importCloudRunService } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
const project = { id: "synthetic-project", number: "123", label: "Lab" };
const fixture = `apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: sample
  namespace: '123'
spec:
  template:
    spec:
      containers:
        - image: example.invalid/team/service:fixture
          env:
            - name: FIXTURE
              value: fixture-not-retained
status:
  url: https://sample-synthetic.a.run.app
  latestReadyRevisionName: sample-00001
`;

test("Cloud Run UI imports only deployment selection fields and enforces the selected project", () => {
  assert.deepEqual(importCloudRunService(fixture, project), {
    name: "sample", url: "https://sample-synthetic.a.run.app",
    revision: "sample-00001", images: ["example.invalid/team/service:fixture"],
  });
  assert.throws(() => importCloudRunService(fixture.replace("namespace: '123'", "namespace: '234'"), project));
  assert.throws(() => importCloudRunService(fixture.replace("https://sample-synthetic.a.run.app", "https://sample.run.app.bad.invalid"), project));
  assert.throws(() => importCloudRunService(fixture + "resource: !custom abc", project));
});
