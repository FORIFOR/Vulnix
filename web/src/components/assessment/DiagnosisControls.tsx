"use client";

// PR-C: the diagnosis loop's operations (docs/DIAGNOSIS_ACTIONS.md). Which buttons appear
// follows the reader's permissions from GET .../diagnosis; the server checks every request
// again (login, organization, permission, registered lab, stop, Idempotency-Key). After a
// request the screen changes only through the server's own view (SSE / refresh).
import { useState } from "react";
import { keyFor, postDiagnosisOp, requestSignature, type PendingKey } from "@/lib/diagnosisActions";
import { availableControls, opReasonText, operationText, type DiagnosisControl } from "@/lib/diagnosisView";
import { DIAG_REQUIREMENT } from "@/lib/labels";
import type { DiagnosisView } from "@/lib/types";

const BTN = "inline-flex min-h-11 items-center justify-center rounded-xl px-4 text-sm font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-900 disabled:cursor-not-allowed disabled:opacity-50 dark:focus-visible:outline-white";
const PRIMARY = `${BTN} bg-zinc-900 text-white hover:bg-zinc-700 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-200`;
const SECONDARY = `${BTN} border border-zinc-300 bg-white text-zinc-900 hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800`;
const SPECS = ["authentication_required", "public"] as const;

type Outcome = { ok: boolean; text: string } | null;

function SpecForm({ target, busy, onSend }: { target: string; busy: boolean; onSend: (req: string) => void }) {
  const [choice, setChoice] = useState<string | null>(null);
  return (
    <form
      className="rounded-xl border border-zinc-200 p-3 dark:border-zinc-800"
      onSubmit={(e) => { e.preventDefault(); if (choice) onSend(choice); }}
    >
      <fieldset>
        <legend className="text-sm font-semibold">対象 {target} を、誰が読めるべきですか（所有者の仕様）</legend>
        <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
          {SPECS.map((s) => (
            <label key={s} className="flex min-h-11 cursor-pointer items-center gap-2 rounded-lg border border-zinc-200 px-3 text-sm has-[:checked]:border-zinc-900 dark:border-zinc-700 dark:has-[:checked]:border-white">
              <input type="radio" name={`spec-${target}`} value={s} checked={choice === s}
                     onChange={() => setChoice(s)} className="h-4 w-4" />
              {DIAG_REQUIREMENT[s]}
            </label>
          ))}
        </div>
      </fieldset>
      <p className="mt-2 text-xs text-zinc-500">入力は監査ログに記録されてから反映されます。判定が出た後の変更は、修正後の確認（新しい世代）で行います。</p>
      <button type="submit" className={`${PRIMARY} mt-2 w-full sm:w-auto`} disabled={busy || !choice}>仕様を記録する</button>
    </form>
  );
}

export function DiagnosisControls({ view }: { view: DiagnosisView }) {
  const [pending, setPending] = useState<PendingKey>(null);
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome>(null);
  const { controls, notes } = availableControls(view);
  const op = view.operation ?? null;
  // a confirmation belongs to the moment it was sent: once the job moves on, the job line says it
  const opKey = op ? `${op.id}:${op.state}` : "";
  const [seenOp, setSeenOp] = useState(opKey);
  if (opKey !== seenOp) {
    setSeenOp(opKey);
    if (outcome?.ok) setOutcome(null);
  }

  async function send(name: string, body: Record<string, unknown>, done: string) {
    const sig = requestSignature(name, body);
    const { key } = keyFor(pending, sig);
    setPending({ sig, key });
    setBusy(true);
    setOutcome(null);
    const answer = await postDiagnosisOp(view.assessment_id, name, body, key);
    setBusy(false);
    if (answer === null) {
      // no answer: the same request (same key) may be sent again safely
      setOutcome({ ok: false, text: "応答がありませんでした。もう一度押すと、同じ要求として送り直します" });
      return;
    }
    setPending(null);
    if (answer.status >= 200 && answer.status < 300) {
      setOutcome({ ok: true, text: answer.body.replayed ? `${done}（受付済みの要求）` : done });
    } else {
      const reason = typeof answer.body.reason === "string" ? opReasonText(answer.body.reason)
        : typeof answer.body.error === "string" ? answer.body.error : `HTTP ${answer.status}`;
      // the server says whether the request was taken even when it withholds the result
      setOutcome({ ok: false, text: answer.body.committed === true
        ? `${reason}。操作そのものは受け付け済みです（もう一度は実行されません）` : reason });
    }
  }

  const render = (c: DiagnosisControl) => {
    switch (c.op) {
      case "start":
        return (
          <button key="start" type="button" className={`${PRIMARY} w-full sm:w-auto`} disabled={busy}
                  onClick={() => send("start", {}, "診断ループを開始しました")}>{c.label}</button>
        );
      case "owner-spec":
        return c.targets.map((t) => (
          <SpecForm key={`spec-${t}`} target={t} busy={busy}
                    onSend={(req) => send("owner-spec", { target_ref: t, requirement: req }, "仕様を記録しました")} />
        ));
      case "approve":
        return (
          <div key="approve" id="diag-approve" className="rounded-xl border border-amber-300 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-950/40">
            <p className="text-sm font-semibold">L2 検査（{c.itemId}）の承認</p>
            <p className="mt-1 text-xs text-zinc-700 dark:text-zinc-300">
              ラボの別アカウントの資源を読めるかを、隔離された Worker で1回だけ確かめます。承認はこの1手順だけに有効です。
            </p>
            <button type="button" className={`${PRIMARY} mt-2 w-full sm:w-auto`} disabled={busy}
                    onClick={() => send("approve", { item_id: c.itemId }, "承認しました")}>この L2 検査を承認する</button>
          </div>
        );
      case "fix-check":
        return (
          <button key="fix" type="button" className={`${SECONDARY} w-full sm:w-auto`} disabled={busy}
                  onClick={() => send("fix-check", {}, "修正後の確認を開始しました")}>修正後の確認を開始</button>
        );
    }
  };

  if (!op && controls.length === 0 && notes.length === 0 && !outcome) return null;
  return (
    <div id="diag-controls" className="mt-3 space-y-2" data-testid="diagnosis-controls">
      {op && (
        <p className="text-sm" data-testid="diagnosis-operation">
          <span className="text-zinc-500">操作：</span>
          <span className="font-semibold">{operationText(op)}</span>
          <span className="ml-1 text-xs text-zinc-500">依頼者 {op.requested_by}</span>
        </p>
      )}
      {notes.map((n) => <p key={n} className="text-sm text-zinc-600 dark:text-zinc-400">{n}</p>)}
      {controls.length > 0 && <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-start">{controls.map(render)}</div>}
      {outcome && (
        <p role={outcome.ok ? "status" : "alert"}
           className={`rounded-lg border p-2 text-sm ${outcome.ok
             ? "border-emerald-300 bg-emerald-50 text-emerald-950 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-100"
             : "border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950/40 dark:text-red-100"}`}>
          {outcome.text}
        </p>
      )}
    </div>
  );
}
