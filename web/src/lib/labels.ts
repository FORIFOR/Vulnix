import type { AssessmentState, CveStatus, Finding, PhaseStatus, Severity, Verdict } from "./types";

// Every status is shown with text, never colour alone.
export const SEVERITY: Record<Severity, { label: string; cls: string }> = {
  critical: { label: "重大", cls: "bg-red-600 text-white" },
  high: { label: "高", cls: "bg-orange-500 text-white" },
  medium: { label: "中", cls: "bg-amber-300 text-amber-950" },
  low: { label: "低", cls: "bg-sky-200 text-sky-950" },
  info: { label: "情報", cls: "bg-zinc-200 text-zinc-800" },
};

export const VERDICT: Record<Verdict, { label: string; cls: string; help: string }> = {
  candidate: { label: "未計測の候補", cls: "border-zinc-400 text-zinc-700 dark:text-zinc-300", help: "verdict_unverified" },
  proven: { label: "実証成功", cls: "border-red-500 text-red-700 dark:text-red-300", help: "verdict_proven" },
  detected: { label: "検出（未実証）", cls: "border-amber-500 text-amber-700 dark:text-amber-300", help: "verdict_detected" },
  unverified: { label: "未検証", cls: "border-zinc-400 text-zinc-700 dark:text-zinc-300", help: "verdict_unverified" },
  not_reproduced: { label: "再現せず", cls: "border-emerald-500 text-emerald-700 dark:text-emerald-300", help: "verdict_not_reproduced" },
  aborted: { label: "中止", cls: "border-zinc-500 text-zinc-600 dark:text-zinc-400", help: "verdict_aborted" },
};

export const STATE: Record<AssessmentState, { label: string; cls: string }> = {
  idle: { label: "未開始", cls: "bg-zinc-200 text-zinc-800" },
  running: { label: "診断中", cls: "bg-blue-600 text-white" },
  paused: { label: "一時停止中", cls: "bg-amber-400 text-amber-950" },
  // whether every worker was confirmed stopped is shown next to it (stop report / alerts)
  stopped: { label: "緊急停止", cls: "bg-red-700 text-white" },
  failed: { label: "失敗", cls: "bg-red-200 text-red-900" },
  completed: { label: "完了", cls: "bg-emerald-600 text-white" },
};

export const PHASE: Record<PhaseStatus, { label: string; icon: string }> = {
  pending: { label: "待機", icon: "○" },
  running: { label: "実行中", icon: "◐" },
  done: { label: "完了", icon: "✓" },
  aborted: { label: "中止", icon: "✕" },
  skipped: { label: "未実施", icon: "–" },
};

export const AUDIT_EVENT: Record<string, string> = {
  allow: "実行を許可",
  deny: "実行を拒否",
  result: "実行結果",
  pause: "一時停止",
  resume: "再開",
  emergency_stop: "緊急停止",
  "approval.auto": "自動承認（L1）",
  "approval.approved": "承認",
  "approval.rejected": "却下",
  "auth.login": "ログイン",
  "auth.logout": "ログアウト",
  "auth.password_changed": "パスワード変更",
  "auth.mfa_enabled": "2要素認証 有効化",
  "auth.mfa_disabled": "2要素認証 無効化",
  "chat.asked": "AIコンテキスト質問",
  "system.controls_verified": "安全制御の実機検証",
  "cve.synced": "CVE/KEVフィード同期",
  "proposal.received": "AI提案を受理（サニタイズ済）",
  "proposal.rejected": "不正なAI提案を破棄",
  "agent.thought": "AI推論・検証ステップ",
  "asset.registered": "診断対象・SOW登録",
  "asset.deleted": "診断対象を削除",
  "asset.selected": "診断対象を切替",
  "lab.mode_changed": "検証ラボ防御モード切替",
  "assessment.restarted": "再診断を開始",
  "assessment.failed": "診断中断（エラー）",
};

export const fmtTime = (ts: number | null | undefined) =>
  ts ? new Date(ts * 1000).toLocaleString("ja-JP", { hour12: false }) : "—";

export function completedHeadline(findings: Pick<Finding, "evidence_status" | "demo_fixture">[]): string {
  const actual = findings.filter((f) => !f.demo_fixture);
  const confirmed = actual.filter((f) => f.evidence_status === "detected" || f.evidence_status === "proven").length;
  const candidates = actual.filter((f) => f.evidence_status === "candidate").length;
  const incomplete = actual.filter((f) => f.evidence_status === "incomplete").length;
  const notReproduced = actual.filter((f) => f.evidence_status === "not_reproduced").length;
  return "診断が完了しました。" +
    (confirmed ? `証拠のある問題を${confirmed}件確認しました。` : "問題を確認していません（未検査項目が安全という意味ではありません）。") +
    (candidates ? `未確認の候補${candidates}件。` : "") +
    (incomplete ? `検証が完了していない所見${incomplete}件。` : "") +
    (notReproduced ? `再現できなかった所見${notReproduced}件。` : "");
}

export function threatFeedSummary(
  status: Pick<CveStatus, "cve_count" | "kev_count" | "last_synced_at" | "freshness" | "stale" | "last_sync_error"> | null | undefined,
): string {
  if (!status) return "脅威情報の件数を取得できていません。";
  const base = `NVD 登録 ${status.cve_count} 件 / CISA KEV 悪用確認 ${status.kev_count} 件（最終同期: ${status.last_synced_at ? fmtTime(status.last_synced_at) : "未同期（同梱データのみ）"}）`;
  const freshNote =
    status.freshness === "unfetched" ? "・フィード未取得" :
    status.stale || status.freshness === "stale" ? "・更新期限超過（要同期）" : "";
  const errNote = status.last_sync_error ? "・直近の同期に失敗（以前のデータを保持）" : "";
  return base + freshNote + errNote;
}

// ---- diagnosis loop (docs/DIAGNOSIS_UI_DESIGN.md §4) -----------------------------------
// The API sends fixed ids only. Each one is turned into words here; an id without an
// entry is shown as "未定義の値" with the raw id, never guessed. tests/test_diagnosis_ui_labels.py
// checks that every id the backend can send has an entry.

export const DIAG_CLAIM: Record<string, string> = {
  unauthenticated_exposure: "認証なしで、アカウント資源が読めるか",
  other_account_read: "別のアカウントが、B の資源を読めるか",
  intended_public: "所有者が公開を意図した資源か",
};

// The colour only repeats the word; the word is always shown.
export const DIAG_STATE: Record<string, { label: string; cls: string }> = {
  open: { label: "確認待ち", cls: "border-zinc-400 bg-zinc-50 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-200" },
  supported: { label: "支持（成立）", cls: "border-red-400 bg-red-50 text-red-800 dark:bg-red-950/50 dark:text-red-200" },
  contradicted: { label: "反証（不成立）", cls: "border-emerald-400 bg-emerald-50 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200" },
  inconclusive: { label: "判断不能", cls: "border-amber-400 bg-amber-50 text-amber-900 dark:bg-amber-950/50 dark:text-amber-200" },
  needs_spec: { label: "所有者の仕様が必要", cls: "border-sky-400 bg-sky-50 text-sky-900 dark:bg-sky-950/50 dark:text-sky-200" },
};

/** A confirm-fix hypothesis reads the other way round: contradicted means fixed. */
export const DIAG_FIX_STATE: Record<string, string> = {
  supported: "改善されていない",
  contradicted: "改善を確認",
};

export const DIAG_CHECK: Record<string, string> = {
  l1_http_probe: "認証なしの GET（L1）",
  l2_idor: "別アカウントでの読み取り検査（L2）",
};

/** `{h}` is replaced by the hypothesis id. */
export const DIAG_REASON: Record<string, string> = {
  test_hypothesis: "{h} を確かめるため",
  collect_missing_evidence: "{h} の判断に足りない観測を集めるため",
  confirm_fix: "修正の後に、同じ検査で確かめ直すため",
};

export const DIAG_RULE: Record<string, string> = {
  cross_account_read: "所有者が「認証必須」とした資源を、別のアカウントが読めた",
  spec_missing: "読めたが、誰が読めるべきかの仕様がない",
  intended_public: "所有者の仕様で「公開」とされている",
  denied: "別のアカウントの要求は拒否された（401・403・404）",
  own_resource_only: "返ったのは、要求した本人の資源だった",
  owner_record_absent: "200 が返ったが、所有者 B の対照で得た識別子も B の名前もなく、B の記録ではなかった",
  control_failed: "所有者本人でも資源を確認できず、比べられなかった",
  unrecognised_answer: "応答の形が想定と違い、判断できなかった",
  denied_without_auth: "認証なしの要求は拒否された",
  answered_without_auth_unverified: "認証なしで 200 が返ったが、保護された資源そのものかは確かめられない",
  owner_record_absent_without_auth: "認証なしで 200 が返ったが、所有者 B の識別子も名前もなく、B の記録ではなかった",
  check_not_relevant: "この検査では、この仮説を判断できない",
};

export const DIAG_EVIDENCE_KIND: Record<string, string> = {
  root_response: "ラボのルートの応答",
  account_resource_link: "ルートがアカウント資源へリンクしている",
  owner_spec: "所有者の仕様",
  check_result: "検査の結果",
};

export const DIAG_SOURCE: Record<string, string> = {
  l1: "初回の L1 診断",
  check: "検査",
  owner_spec: "所有者の入力",
};

export const DIAG_REQUIREMENT: Record<string, string> = {
  authentication_required: "認証必須",
  public: "公開",
  unspecified: "未指定",
};

/** Observation attributes (aegis.diagnosis_judge.check_attrs and the L1 observations). */
export const DIAG_ATTR_VALUE: Record<string, Record<string, string>> = {
  auth: { none: "認証なし", other_account: "別アカウント（A）で要求" },
  control: { established: "所有者 B の対照 成立", missing: "所有者 B の対照 不成立" },
  reproduction: {
    proven: "再現 成立", not_reproduced: "再現せず", unverified: "再現 未確認", incomplete: "再現 未完了",
  },
  own_resource: { true: "本人の資源だった", false: "" },
  owner_identifiers_present: { true: "所有者 B の識別子あり", false: "所有者 B の識別子なし" },
  owner_account_present: { true: "所有者 B の名前あり", false: "所有者 B の名前なし" },
  body_kind: {
    json_refusal: "本文 拒否の JSON", json_data: "本文 データの JSON", html_login: "本文 ログイン画面", html_refusal: "本文 拒否の画面", html_other: "本文 その他の HTML",
    text: "本文 テキスト", empty: "本文なし", partial: "本文の一部しか読めていない",
  },
  present: { true: "リンクあり", false: "リンクなし" },
  account_link: { true: "アカウント資源へのリンクあり", false: "アカウント資源へのリンクなし" },
  answer: { unreadable: "応答を読めない" },
};

export const DIAG_PLAN_STATE: Record<string, string> = {
  CREATED: "準備中",
  OBSERVED: "観測を整理中",
  PROPOSED: "検査を選択中",
  AUTHORIZED: "実行を許可済み",
  EXECUTING: "検査を実行中",
  EVIDENCE_RECORDED: "証拠を記録済み",
  COMPLETED: "完了",
  REJECTED: "中止（承認・権限）",
  CANCELLED: "中止（停止・リセット）",
  EXPIRED: "上限で終了",
  FAILED: "整合を確認できず終了",
};

const INTEGRITY = "記録の整合を確かめられなかったため、結果は採用していません";
const LIMIT = "上限に達したため止めました";

/** Why a plan ended (aegis.adaptive_plan_runner `_finish`). `action` is a hint only:
 *  PR-B shows no buttons for it (starting or resuming a diagnosis is PR-C). */
export const DIAG_END: Record<string, { text: string; action: "findings" | "approval" | "audit" | "resume" | null }> = {
  all_settled: { text: "すべての仮説を判断しました", action: "findings" },
  needs_spec: { text: "所有者の仕様がないため、判断を保留しました", action: null },
  no_hypothesis: { text: "確かめる仮説がありませんでした", action: null },
  no_progress: { text: "新しい検査で状況が変わりませんでした。条件を見直してください", action: null },
  stalled: { text: "新しい検査で状況が変わりませんでした。条件を見直してください", action: null },
  max_steps: { text: LIMIT, action: "resume" },
  max_planner_rounds: { text: LIMIT, action: "resume" },
  deadline: { text: LIMIT, action: "resume" },
  planner_cost_limit: { text: LIMIT, action: "resume" },
  paused: { text: "一時停止中のため止めました", action: "resume" },
  stopped_or_reset: { text: "停止またはリセットにより、この周回の結果は採用していません", action: null },
  requester_authority_revoked: { text: "依頼者の権限が失効したため、結果は採用していません", action: null },
  l2_approval_missing: { text: "L2 の承認がないため止めました", action: "approval" },
  planner_failed: { text: "計画を作れなかったため止めました", action: "audit" },
  execute_failed: { text: "検査を実行できなかったため止めました", action: "audit" },
  state_from_another_run: { text: INTEGRITY, action: "audit" },
  audit_failed: { text: INTEGRITY, action: "audit" },
  evidence_mismatch: { text: INTEGRITY, action: "audit" },
  evidence_missing: { text: INTEGRITY, action: "audit" },
  check_mismatch: { text: INTEGRITY, action: "audit" },
  generation_changed: { text: INTEGRITY, action: "audit" },
  judge_failed: { text: INTEGRITY, action: "audit" },
  judgement_not_applied: { text: INTEGRITY, action: "audit" },
  aborted: { text: INTEGRITY, action: "audit" },
};

/** Why the view is refused (aegis.diagnosis_view / AssessmentService._restore_diagnosis_locked). */
export const DIAG_REFUSAL: Record<string, string> = {
  audit_chain_invalid: "監査ログのハッシュの鎖が壊れています",
  state_audit_mismatch: "診断の状態が、監査ログから組み立て直した内容と一致しません",
  journal_unreadable: "監査ログの記録から、診断の状態を組み立てられません",
  evidence_not_in_audit: "観測が指す検査結果が、検証済みの監査ログにありません",
  judgement_not_in_audit: "手順の判定が、監査ログにありません",
  result_not_in_audit: "手順の検査結果が、監査ログにありません",
  observation_not_the_result: "手順の観測が、監査ログの検査結果と対応しません",
  snapshot_missing: "再起動の前の診断の保存ファイルがありません",
  snapshot_unreadable: "再起動の前の診断の保存ファイルを読めません",
  snapshot_mismatch: "保存ファイルが、別の診断のものです",
  // checked in the browser (lib/diagnosisView.ts), not sent by the server
  invalid_response: "サーバーの応答が、確かめられる形になっていません",
};

export const DIAG_FIX_RESULT: Record<string, { label: string; cls: string }> = {
  fixed: { label: "改善を確認", cls: DIAG_STATE.contradicted.cls },
  not_fixed: { label: "改善されていない", cls: DIAG_STATE.supported.cls },
  pending: { label: "確認中", cls: DIAG_STATE.open.cls },
};

/** "What is needed next" (aegis.diagnosis_view._next). */
export const DIAG_NEXT: Record<string, string> = {
  approve_l2: "L2 検査の承認が必要です（承認できるのは依頼者以外の承認者です）",
  needs_spec: "資源を誰が読めるべきか、所有者の仕様が必要です",
  prepare_accounts: "所有者のアカウントで資源を確認できるよう、検証用アカウントを準備してください",
  confirm_fix_available: "修正したら、修正後の確認を行ってください",
  plan_ended: "",
  check_audit: "監査ログを確認してください。確かめられない記録は表示しません",
  none: "",
};

// ---- PR-C: the diagnosis operations (docs/DIAGNOSIS_ACTIONS.md) ------------------------
// tests/test_diagnosis_ui_labels.py checks every kind, state and reason the server can send.
export const DIAG_OP_KIND: Record<string, string> = {
  start: "診断",
  fix_check: "修正後の確認",
};

export const DIAG_OP_STATE: Record<string, string> = {
  awaiting_spec: "所有者の仕様の入力を待っています",
  running: "実行中です",
  waiting_approval: "L2 検査の承認を待っています",
  finished: "終了しました",
  failed: "開始できませんでした",
  interrupted: "サーバーの再起動で中断しました（自動では再開しません）",
};

// why an operation was refused, or why a job ended without a plan
export const DIAG_OP_REASON: Record<string, string> = {
  permission_denied: "この操作の権限がありません",
  idempotency_key_required: "要求の識別子がありません（画面を再読み込みしてください）",
  idempotency_key_reused: "同じ識別子で別の内容が送られました",
  already_accepted: "同じ対象・世代への同じ操作は、すでに受け付けています",
  loop_active: "この評価の診断ループはすでに進行中です",
  loop_running: "診断ループの実行中は仕様を変更できません",
  not_started: "診断ループを開始してから操作してください",
  not_waiting: "この項目は承認を待っていません",
  self_approval: "診断を依頼した本人は、その L2 検査を承認できません",
  self_registered: "自己登録のアカウントは L2 検査を承認できません",
  needs_new_generation: "この仕様に基づく判定がすでにあります。変更は修正後の確認（新しい世代）で入力してください",
  no_proven_finding: "修正前に実証された所見がないため、修正後の確認は開始できません",
  emergency_stopped: "緊急停止中です",
  paused: "一時停止中です",
  authority_revoked: "権限が失効しています。もう一度ログインしてください",
  audit_failed: "監査ログに記録できないため、操作を受け付けませんでした",
  request_not_persisted: "要求を保存できないため、操作を受け付けませんでした",
  request_store_unreadable: "要求の記録を読めないため、操作を受け付けません",
  not_a_lab: "診断ループは登録済みのローカル検証ラボでのみ使用できます",
  closing: "サーバーを停止しています",
  invalid_spec: "仕様は「認証必須」か「公開」のどちらかです",
  item_id_required: "承認する項目がありません",
  unexpected_fields: "要求の形が正しくありません",
  unknown_target: "この対象は、現在の登録済み対象にありません",
  history_refused: "診断の記録が監査ログと一致しないため、新しい診断を始められません",
  // a job that ended before (or instead of) a plan
  server_restarted: "サーバーの再起動で中断しました",
  initial_observation_failed: "初期観測を記録できませんでした",
  hypotheses_failed: "仮説を作成できませんでした",
  loop_failed: "診断ループが異常終了しました",
  stopped_or_reset: "停止またはリセットされました",
  requester_authority_revoked: "依頼者の権限が失効しました",
  spec_timeout: "所有者の仕様が期限内に入力されませんでした",
  item_running: "ARTEX 計画の項目を実行中です。終わってから開始してください",
  authority_revoked_after_request: "権限が失効したため、結果は表示しません",
};

// a finding's current status (aegis.evidence.evidence_status)
export const DIAG_FINDING_STATUS: Record<string, string> = {
  proven: "実証成功",
  detected: "検出（未実証）",
  not_reproduced: "再現せず",
  incomplete: "未完了",
  candidate: "未計測の候補",
  fixture: "見本",
};
