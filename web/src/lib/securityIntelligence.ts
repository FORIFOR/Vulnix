import type { EvidenceStatus, Finding, RunHistoryEntry, Severity } from "./types";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const EVIDENCE = ["candidate", "detected", "proven", "not_reproduced", "incomplete", "fixture"] as const;
export const EVIDENCE_LABEL: Record<EvidenceStatus, string> = {
  candidate: "未計測", detected: "検出・未実証", proven: "実証済み", not_reproduced: "再現せず",
  incomplete: "未完了・要確認", fixture: "デモ資料",
};
const CATEGORIES = [
  "アクセス制御", "APIアクセス制御", "インジェクション", "設定不備", "情報露出", "情報公開設定",
  "暗号・TLS設定", "セッション・Cookie設定", "CORS・オリジン境界", "既知の脆弱性（CVE）", "その他",
];

function zeros<T extends string>(keys: readonly T[]) {
  return Object.fromEntries(keys.map((key) => [key, 0])) as Record<T, number>;
}

function knownCategory(category: string) {
  return CATEGORIES.includes(category) ? category : "その他";
}

export function aggregate(findings: Finding[], external: boolean, chainValid: boolean | null, hashes: Iterable<string>) {
  const verified = new Set(hashes);
  const severity = zeros(SEVERITIES);
  const evidence = zeros(EVIDENCE);
  const matrix = Object.fromEntries(SEVERITIES.map((key) => [key, zeros(EVIDENCE)])) as Record<Severity, Record<EvidenceStatus, number>>;
  const categories: Record<string, number> = {};
  const rows: Finding[] = [];
  for (const finding of findings) {
    const fixture = finding.demo_fixture || finding.evidence_status === "fixture";
    if (external && fixture) continue;
    const s = SEVERITIES.includes(finding.severity) ? finding.severity : "info";
    let state = fixture ? "fixture" : EVIDENCE.includes(finding.evidence_status) ? finding.evidence_status : "incomplete";
    const proof = [...(finding.evidence ?? [])].reverse().find((entry) => entry.tool === "reproduction_probe" || entry.kind === "reproduction_probe");
    const showsProof = state === "proven" || state === "not_reproduced" || finding.verdict === "proven"
      || finding.last_run_verdict === "proven" || finding.last_run_verdict === "not_reproduced";
    if (!fixture && showsProof &&
      (chainValid !== true || !proof?.audit_hash || proof.saved_at == null || !verified.has(proof.audit_hash))) {
      state = "incomplete";
      rows.push({ ...finding, evidence_status: state, verdict: "unverified", last_run_verdict: undefined,
        verdict_note: "対応する検証記録を監査ログで確認できませんでした。", what_was_established: undefined });
    } else {
      rows.push(state === finding.evidence_status ? finding : { ...finding, evidence_status: state });
    }
    severity[s]++;
    evidence[state]++;
    matrix[s][state]++;
    const category = knownCategory(finding.category);
    categories[category] = (categories[category] ?? 0) + 1;
  }
  return { rows, severity, evidence, matrix, categories };
}

export interface FindingFilters { severity?: Severity; evidence?: EvidenceStatus; category?: string; finding?: string }
export function findingQuery(filters: FindingFilters = {}) {
  const params = new URLSearchParams({ tab: "findings" });
  for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value);
  return `?${params}`;
}

export function filterFindings(rows: Finding[], params: { get: (key: string) => string | null }) {
  const severity = SEVERITIES.find((key) => key === params.get("severity"));
  const evidence = EVIDENCE.find((key) => key === params.get("evidence"));
  const category = CATEGORIES.find((key) => key === params.get("category"));
  const finding = params.get("finding");
  return rows.filter((row) => (!finding || row.id === finding) && (!severity || row.severity === severity)
    && (!evidence || row.evidence_status === evidence) && (!category || knownCategory(row.category) === category));
}

export function comparableRuns(runs: RunHistoryEntry[], asset: string) {
  const ordered = runs.filter((r) => r.run_id && r.asset_id === asset && r.condition_id &&
    r.score !== null && Number.isFinite(r.score) && Number.isFinite(r.at)).sort((a, b) => a.at - b.at);
  const condition = ordered.at(-1)?.condition_id;
  return ordered.filter((r) => r.condition_id === condition);
}
