import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const [first, second, output] = process.argv.slice(2);
const checkingLock = first === "check-lock";
const upstream = readFileSync(checkingLock ? second : first);
const lockHash = createHash("sha256").update(upstream).digest("hex");
const expectedLockHash = "a250cafac0fc58361229688488b9af4a751dd182ab61d1cf273c62e5e5eecd1a";
const workspaceRequire = createRequire(path.resolve("package.json"));
if (lockHash !== expectedLockHash || workspaceRequire("next/package.json").version !== "16.4.5") {
  throw new Error("Review the release profile and upstream lock for this Next.js version");
}
if (checkingLock) process.exit(0);

const { default: config } = await import(pathToFileURL(path.resolve("next.config.ts")));
if (config.output !== "standalone" || config.compress !== false || config.images?.unoptimized !== true) {
  throw new Error("The expected release build options are missing");
}
for (const glob of config.outputFileTracingExcludes["**"]) {
  const subdirectory = glob.slice(0, -"/**/*".length);
  if (existsSync(path.join(second, subdirectory))) throw new Error(`Trace still contains ${subdirectory}`);
}

const yaml = workspaceRequire("yaml");
const lock = yaml.parse(upstream.toString("utf8"));
const dependencyVersions = (name) => {
  const importer = lock.importers[name];
  return { ...importer.dependencies, ...importer.devDependencies, ...importer.optionalDependencies };
};
const nextVersions = dependencyVersions("packages/next");
const rootVersions = dependencyVersions(".");
const modules = path.join(second, "node_modules");
const ciInfoRevision = "f43f6a1cefff47fb361c88cf4b943fdbcaafe540";

function manifests(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) return manifests(file);
    return entry.isFile() && entry.name === "package.json" ? [file] : [];
  });
}

const components = [];
for (const file of manifests(modules).sort()) {
  const pkg = JSON.parse(readFileSync(file, "utf8"));
  if (!pkg.name) continue;
  const ref = path.relative(modules, path.dirname(file));
  let version = pkg.version;
  let evidence = "packaged manifest";
  let externalReferences;
  if (!version && ref.startsWith("next/dist/compiled/")) {
    evidence = "Next.js release lock and NCC recipe";
    version = (nextVersions[pkg.name] ?? rootVersions[pkg.name])?.version?.split("(")[0];
    if (pkg.name === "ci-info" && version?.endsWith(`/${ciInfoRevision}`)) {
      version = "2.0.0";
      evidence = `fork manifest at ${ciInfoRevision}`;
      externalReferences = [{ type: "vcs", url: `https://github.com/watson/ci-info/tree/${ciInfoRevision}` }];
    }
  }
  if (!version || !/^\d/.test(version)) throw new Error(`Unidentified package at ${ref}`);
  const [group, name] = pkg.name.startsWith("@") ? pkg.name.split("/") : [undefined, pkg.name];
  const purl = `pkg:npm/${group ? `${encodeURIComponent(group)}/` : ""}${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
  components.push({
    type: "library", "bom-ref": ref, group, name, version, purl, externalReferences,
    properties: [{ name: "vulnix:identityEvidence", value: evidence }],
  });
}

const version = process.env.VULNIX_RELEASE_SHA;
if (readFileSync(path.join(second, ".next/BUILD_ID"), "utf8").trim() !== version) {
  throw new Error("Standalone build ID does not match the source commit");
}
const bom = {
  bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: `urn:uuid:${randomUUID()}`, version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    component: { type: "application", name: "vulnix-web", version },
  },
  components,
};
writeFileSync(output, `${JSON.stringify(bom, null, 2)}\n`);
