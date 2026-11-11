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
  stop_report?: { confirmed: boolean; survivors: number[] } | null;
  unstopped_workers?: { host: string; pids: number[]; at?: number } | null;
}

/** "Stopped" is only claimed when the server confirmed that every worker is gone. */
export function stoppedHeadline(s: NoticeSource): string {
  const survivors = s.unstopped_workers?.pids.length ?? 0;
  if ((s.stop_report && !s.stop_report.confirmed) || survivors > 0) {
    const n = Math.max(survivors, s.stop_report?.survivors.length ?? 0);
    return `緊急停止を実行しましたが、停止を確認できていません（残存 Worker ${n} 件）。確認できるまで新しいWorkerは起動しません。プロセスを確認してください。`;
  }
  if (!s.stop_report) return "緊急停止の状態です。「再診断を実行」で新しい診断を開始できます。";
  return "緊急停止しました。実行許可を失効させ、実行中の処理の終了を確認しました。「再診断を実行」まで検証は実行できません。";
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
  if (s.unstopped_workers && s.unstopped_workers.pids.length > 0) {
    out.push({
      tone: "error",
      title: "Workerの停止を確認できていません",
      detail: `${s.unstopped_workers.host} の診断許可は取り消しましたが、実行中だった Worker（${s.unstopped_workers.pids.length} 件、PID ${s.unstopped_workers.pids.join(", ")}）の停止を確認できていません。取り消しは完了として扱いません。プロセスを確認し、必要ならコントロールプレーンを停止してください。`,
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
