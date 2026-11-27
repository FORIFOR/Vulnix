import { compare as semverCompare, valid as semverValid } from "semver";
import { compare as pepCompare, valid as pepValid } from "@renovatebot/pep440";
import { record } from "./quickDefense";

export type Location = { path: string; line?: number };
export type Package = Location & { ecosystem: "npm" | "PyPI" | "Go"; name: string; version: string };

export function compareVersions(ecosystem: Package["ecosystem"], left: string, right: string) {
  if (left.length > 128 || right.length > 128) return null;
  if (ecosystem === "PyPI") {
    if (!pepValid(left) || !pepValid(right) || left.includes("+") || right.includes("+")) return null;
    return pepCompare(left, right);
  }
  // Go /vN and +incompatible describe module identities. Compare versions
  // only within the exact module path and preserve pseudo-version ordering.
  if (!semverValid(left) || !semverValid(right)) return null;
  return semverCompare(left, right);
}

export function affects(version: string, ecosystem: Package["ecosystem"], affected: Record<string, unknown>): boolean {
  if (Array.isArray(affected.versions) && affected.versions.some((v) =>
    typeof v === "string" && compareVersions(ecosystem, version, v) === 0)) return true;
  if (!Array.isArray(affected.ranges)) return false;
  return affected.ranges.some((input) => {
    const range = record(input);
    if (!(ecosystem === "PyPI" ? range.type === "ECOSYSTEM" :
          range.type === "SEMVER" || (ecosystem === "Go" && range.type === "ECOSYSTEM")) || !Array.isArray(range.events)) return false;
    let active = false;
    let open = false;
    let lastBoundary: string | undefined;
    for (const input of range.events) {
      const entries = Object.entries(record(input));
      if (entries.length !== 1) return false;
      const [kind, boundary] = entries[0];
      if (typeof boundary !== "string") return false;
      const start = kind === "introduced";
      if (start === open || (!start && !["fixed", "last_affected", "limit"].includes(kind))) return false;
      if (boundary === "0" && (!start || lastBoundary !== undefined)) return false;
      const unbounded = start && boundary === "0";
      const infinity = kind === "limit" && boundary === "*";
      const order = unbounded ? 1 : infinity ? -1 : compareVersions(ecosystem, version, boundary);
      if (order === null) return false;
      if (lastBoundary && lastBoundary !== "0") {
        const step = infinity ? -1 : compareVersions(ecosystem, lastBoundary, boundary);
        if (step === null || step >= 0) return false;
      }
      if (infinity && input !== range.events.at(-1)) return false;
      if (start && order >= 0) active = true;
      if (!start && (order > 0 || (order === 0 && kind !== "last_affected"))) active = false;
      open = start;
      lastBoundary = boundary;
    }
    return active;
  });
}

export function propertyLine(body: string, key: string): number | undefined {
  const quoted = JSON.stringify(key);
  let cursor = 0;
  while ((cursor = body.indexOf(quoted, cursor)) !== -1) {
    const end = cursor + quoted.length;
    if (/^\s*:/.test(body.slice(end, end + 80))) return body.slice(0, cursor).split("\n").length;
    cursor = end;
  }
  return undefined;
}

export function sbomComponents(value: unknown): { rows: Array<Record<string, unknown>>; key: string; total: number } {
  const sbom = record(value);
  if (sbom.bomFormat === "CycloneDX" && Array.isArray(sbom.components)) {
    return { rows: sbom.components.slice(0, 12000).map(record), key: "components", total: sbom.components.length };
  }
  if (sbom.spdxVersion === "SPDX-2.3" && Array.isArray(sbom.packages)) {
    const rows = sbom.packages.slice(0, 12000).map((value) => {
      const pkg = record(value);
      const refs = Array.isArray(pkg.externalRefs) ? pkg.externalRefs.slice(0, 32).map(record) : [];
      const identifiers = (type: string) => new Set(refs.filter((ref) => ref.referenceType === type)
        .map((ref) => ref.referenceLocator));
      const purls = identifiers("purl");
      const cpes = identifiers("cpe23Type");
      return { purl: purls.size === 1 ? [...purls][0] : undefined,
        cpe: cpes.size === 1 ? [...cpes][0] : undefined, version: pkg.versionInfo };
    });
    return { rows, key: "packages", total: sbom.packages.length };
  }
  return { rows: [], key: "components", total: 0 };
}

export function collectPackages(name: string, path: string, body: string, parsed: unknown): Package[] {
  const { rows, key, total } = sbomComponents(parsed);
  if (total) {
    const line = propertyLine(body, key);
    return rows.flatMap<Package>((entry) => {
      const purl = typeof entry.purl === "string" && entry.purl.length <= 600
        ? /^pkg:(npm|pypi|golang)\/([^@?#]+)@([^@/?#]+)$/.exec(entry.purl) : null;
      if (!purl) return [];
      try {
        let name = decodeURIComponent(purl[2]);
        const version = decodeURIComponent(purl[3]);
        const ecosystem = purl[1] === "npm" ? "npm" : purl[1] === "pypi" ? "PyPI" : "Go";
        if (entry.version !== undefined && entry.version !== version) return [];
        if (ecosystem === "PyPI") {
          if (!/^[A-Za-z0-9_.-]+$/.test(name)) return [];
          name = name.toLowerCase().replace(/[-_.]+/g, "-");
        } else if (ecosystem === "npm" ? !/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name)
          : !/^[\w.~-]+\/[\w./~-]+$/.test(name)) return [];
        return compareVersions(ecosystem, version, version) === 0 ? [{ ecosystem, name, version, path, line }] : [];
      } catch {
        return [];
      }
    });
  }

  if (name === "package-lock.json" || name === "npm-shrinkwrap.json") {
    const lock = record(parsed);
    if (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) return [];
    const positions = new Map<string, number>();
    for (const [i, line] of body.split("\n").entries()) {
      for (const match of line.matchAll(/"([^"\\]*node_modules\/[^"\\]+)"\s*:/g)) {
        if (!positions.has(match[1])) positions.set(match[1], i + 1);
      }
    }
    return Object.entries(record(lock.packages)).slice(0, 10000).flatMap(([key, value]) => {
      const entry = record(value);
      const match = key.match(/(?:^|\/)node_modules\/((?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)$/);
      if (!match || entry.link === true || (entry.name && entry.name !== match[1]) ||
          typeof entry.version !== "string" || entry.version.length > 128 || !semverValid(entry.version) ||
          typeof entry.integrity !== "string" || typeof entry.resolved !== "string" ||
          !/^https:\/\//i.test(entry.resolved)) return [];
      return [{ ecosystem: "npm", name: match[1], version: entry.version, path, line: positions.get(key) }];
    });
  }
  if (!/^requirements.*\.txt$/i.test(name) && name !== "go.mod") return [];
  const lines = body.split(/\r?\n/);
  // Includes and overrides prevent a standalone file from identifying a unique selection.
  if (name === "go.mod" && lines.some((line) => /^\s*(?:replace|exclude)\b/.test(line))) return [];
  return lines.flatMap<Package>((line, index) => {
    if (name !== "go.mod") {
      const match = line.match(/^\s*([a-z0-9_.-]+)(?:\[[a-z0-9_.-]+(?:\s*,\s*[a-z0-9_.-]+)*\])?\s*==\s*([^\s;#*\\]+)\s*(?:#.*)?$/i);
      return match && match[2].length <= 128 && pepValid(match[2]) ? [{
        ecosystem: "PyPI", name: match[1].toLowerCase().replace(/[-_.]+/g, "-"),
        version: match[2], path, line: index + 1,
      }] : [];
    }
    const match = line.match(/^\s*(?:require\s+)?([\w.~-]+\/[\w./~-]+)\s+(v[\w.+-]+)\s*(?:\/\/.*)?$/);
    return match && match[2].length <= 128 && semverValid(match[2]) ? [{
      ecosystem: "Go", name: match[1], version: match[2], path, line: index + 1,
    }] : [];
  });
}
