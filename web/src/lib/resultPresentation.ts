import type { ResultLocation, Severity } from "./quickDefense";

const severityOrder: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
export const advisorySeverityLabels: Record<Severity, string> = {
  CRITICAL: "Critical（緊急）", HIGH: "High（高）", MEDIUM: "Medium（中）", LOW: "Low（低）",
};
const rank = (severity?: Severity) => severity ? severityOrder[severity] : 4;

export function sortByAdvisorySeverity<T extends { severity?: Severity }>(rows: readonly T[]): T[] {
  return [...rows].sort((a, b) => rank(a.severity) - rank(b.severity));
}

type Finding = {
  category: string; status: string; title: string; severity?: Severity;
  location?: ResultLocation; locations?: ResultLocation[];
};

type Advisory = {
  id: string; severity?: Severity; fixed: string[];
  locations: { path: string; line?: number }[];
};

type Dependency = {
  name: string; version: string; ecosystem?: string; severity?: Severity; advisories: Map<string, Advisory>;
  reachable?: "imported" | "not_imported_directly";
};

export function groupDependencyFindings(rows: readonly Finding[]) {
  const grouped = new Map<string, Dependency>();
  const seen = new Map<Advisory, Set<string>>();
  for (const row of sortByAdvisorySeverity(rows)) {
    if (row.category !== "CVE" || row.status !== "action" || !/^CVE-\d{4}-\d{4,}$/.test(row.title)) continue;
    for (const { dependency, ecosystem, version, path, line, fixed, reachable } of row.locations ?? (row.location ? [row.location] : [])) {
      if (!dependency || !version) continue;
      const key = JSON.stringify([ecosystem, dependency, version]);
      const group: Dependency = grouped.get(key) ?? {
        name: dependency, version, ecosystem, severity: row.severity, advisories: new Map(),
      };
      if (reachable && group.reachable !== "imported") group.reachable = reachable;
      grouped.set(key, group);
      const advisory = group.advisories.get(row.title) ?? {
        id: row.title, severity: row.severity, fixed: [], locations: [],
      };
      group.advisories.set(row.title, advisory);
      advisory.fixed = [...new Set([...advisory.fixed, ...(fixed ?? [])])];
      const location = JSON.stringify([path, line]);
      const visited = seen.get(advisory) ?? new Set<string>();
      if (!visited.has(location)) {
        advisory.locations.push({ path, line });
        visited.add(location);
        seen.set(advisory, visited);
      }
    }
  }
  return [...grouped.values()].map((group) => ({ ...group, advisories: [...group.advisories.values()] }));
}
