// Server-reported conditions the operator has to see, derived from the snapshot.
// Kept free of imports so it can be unit-tested with plain Node.

export interface StatusNotice { tone: "error" | "warn"; title: string; detail: string }

interface NoticeSource {
  state: string;
  is_external_service?: boolean;
  persistence_error?: string | null;
  authority_notice?: string | null;
  failure?: { reason: string; kind: string; at?: number; error?: string } | null;
  l2_isolation?: { ok: boolean; reason: string; mechanism?: string } | null;
}

export function failureHeadline(s: NoticeSource): string {
  const reason = s.failure?.reason?.trim();
  return reason ? `診断は完了していません。${reason}` : "診断を中断しました。ログで理由を確認してください。";
}

export function statusNotices(s: NoticeSource): StatusNotice[] {
  const out: StatusNotice[] = [];
  if (s.persistence_error) {
    out.push({
      tone: "error",
      title: "状態をディスクに保存できません",
      detail: `保存に失敗しています（${s.persistence_error}）。保存できるようになるまで、実サービスへの送信は行いません。結果も保存されていない可能性があります。`,
    });
  }
  if (s.state === "failed" && s.failure) {
    out.push({
      tone: "error",
      title: s.failure.kind === "persistence" ? "結果を保存できなかったため、完了していません" : "診断は完了していません",
      detail: s.failure.reason,
    });
  }
  if (s.authority_notice) {
    out.push({ tone: "warn", title: "所有確認・範囲確認を引き継いでいません", detail: s.authority_notice });
  }
  if (s.is_external_service && s.l2_isolation && !s.l2_isolation.ok) {
    out.push({
      tone: "warn",
      title: "このホストでは実サービスのL2検証を実行しません",
      detail: `L2検証は、Workerのカーネル隔離を適用して確認できる Linux ホストでのみ実行します。${s.l2_isolation.reason}`,
    });
  }
  return out;
}
