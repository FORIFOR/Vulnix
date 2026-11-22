// The local audit anchor's status (docs/AUDIT_ANCHOR.md), as one line for the audit view.
// Kept free of imports so it can be unit-tested with plain Node.

export interface AuditAnchorStatus {
  enabled: boolean;
  /** true only when the anchor is enabled AND its most recent check succeeded */
  protected: boolean;
  last_seq: number | null;
  error: string | null;
}

export interface AuditAnchorLine { tone: "ok" | "off" | "error"; text: string }

const REASONS: Record<string, string> = {
  not_checked: "未確認",
  chain_invalid: "監査ログのハッシュチェーンが不整合",
  rollback: "監査ログが記録済みの位置より短い（巻き戻し）",
  fork: "記録済みの位置の内容が異なる（書き換え）",
  anchor_regressed: "アンカー側の記録が後退した",
  anchor_unavailable: "アンカーに接続できない",
  anchor_bad_response: "アンカーの応答が不正",
  anchor_corrupt: "アンカーの記録ファイルが壊れている",
  anchor_store_unwritable: "アンカーが記録ファイルに書き込めない",
  anchor_store_unreadable: "アンカーが記録ファイルを読めない",
  same_user: "アンカーがサービスと同じ OS ユーザーで動いている（開発用。保護にはなりません）",
  symlink: "監査ログまたはその途中のディレクトリがシンボリックリンク",
  anchor_misconfigured: "アンカーの設定（ソケット・UID・名前・データルート）が不完全",
  anchor_peer_mismatch: "ソケットの相手が指定されたアンカーのユーザーではない",
  anchor_peer_unverified: "ソケットの相手のユーザーを確認できない",
  anchor_unregistered_source: "アンカーにこの記録元が登録されていない",
};

const SCOPE =
  "対象は組織ごとの監査ログです（プラットフォーム全体の platform-audit.jsonl と有料送信の合計 platform-advisor-spend.json は対象外）";

/** "保護あり" only when the server says protected === true (and enabled). */
export function auditAnchorLine(s: AuditAnchorStatus | null | undefined): AuditAnchorLine {
  if (!s) {
    return { tone: "off", text: "巻き戻し検知：状態不明（保護されているとは扱いません）" };
  }
  if (!s.enabled) {
    return {
      tone: "off",
      text: "巻き戻し検知：無効（監査ログと予約ファイルを両方とも古い状態へ戻された場合は検知できません）",
    };
  }
  if (s.protected === true) {
    return {
      tone: "ok",
      text: `巻き戻し検知：保護あり（別権限のアンカーと照合済み${s.last_seq != null ? `・${s.last_seq} 件目まで` : ""}）。${SCOPE}`,
    };
  }
  const reason = (s.error && REASONS[s.error]) || s.error || "理由不明";
  if (s.error === "same_user") {
    return { tone: "error", text: `巻き戻し検知：保護なし（${reason}）。${SCOPE}` };
  }
  return {
    tone: "error",
    text: `巻き戻し検知：保護なし（${reason}）。Worker の実行許可・有料送信・診断と所見の状態変更を停止しています。${SCOPE}`,
  };
}
