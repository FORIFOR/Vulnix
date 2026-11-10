import type { AssessmentState, PhaseStatus, Severity, Verdict } from "./types";

// Every status is shown with text, never colour alone.
export const SEVERITY: Record<Severity, { label: string; cls: string }> = {
  critical: { label: "重大", cls: "bg-red-600 text-white" },
  high: { label: "高", cls: "bg-orange-500 text-white" },
  medium: { label: "中", cls: "bg-amber-300 text-amber-950" },
  low: { label: "低", cls: "bg-sky-200 text-sky-950" },
  info: { label: "情報", cls: "bg-zinc-200 text-zinc-800" },
};

export const VERDICT: Record<Verdict, { label: string; cls: string; help: string }> = {
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
  stopped: { label: "緊急停止済み", cls: "bg-red-700 text-white" },
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
