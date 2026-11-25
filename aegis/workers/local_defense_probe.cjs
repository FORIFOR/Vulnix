"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { syncBuiltinESMExports } = require("node:module");

function refused() {
  throw new Error("offline defence adapter");
}

for (const [module, names] of [
  ["node:child_process", ["exec", "execFile", "execFileSync", "execSync", "fork", "spawn", "spawnSync"]],
  ["node:net", ["connect", "createConnection", "createServer"]],
  ["node:dgram", ["createSocket"]],
]) {
  const builtIn = require(module);
  for (const name of names) builtIn[name] = refused;
}
syncBuiltinESMExports();
globalThis.fetch = refused;

async function main() {
  const snapshot = process.argv[2];
  const write = process.stdout.write.bind(process.stdout);
  const { observe } = require(path.join(snapshot, "source/check.cjs"));
  const cases = JSON.parse(fs.readFileSync(path.join(snapshot, "cases.json"), "utf8"));
  const result = {};
  for (const [name, pair] of Object.entries(cases)) {
    const observations = {};
    for (const [mode, values] of Object.entries(pair)) {
      try {
        const value = await observe(name, values);
        observations[mode] = typeof value === "boolean" ? value : null;
      } catch {
        observations[mode] = null;
      }
    }
    result[name] = observations;
  }
  write(JSON.stringify(result));
}

main().catch(() => { process.exitCode = 1; });
