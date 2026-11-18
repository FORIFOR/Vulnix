import type { Snapshot } from "./types";

/** Say what actually ran, not what happens to be installed or configured. */
export function diagnosisSource(snap: Pick<Snapshot, "is_external_service" | "planner" | "artex_plan" | "plan_source" | "chat_messages">) {
  const usedModel = snap.chat_messages?.findLast((m) => m.role === "assistant" && m.source === "external_model");
  const kind = snap.artex_plan?.plan?.engine?.kind ?? snap.plan_source?.engine;
  const pinned = snap.artex_plan?.plan?.engine?.pinned ?? snap.plan_source?.pinned;
  const usedArtex = kind === "artex-binary" && pinned;
  const model = snap.plan_source?.model;
  const modelLabel = model ? `（モデル: ${model}）` : "";
  if (snap.is_external_service) {
    return { plan: usedArtex ? `ARTEXで作成した計画${modelLabel}` : "公開ページの設定を確認（AIによる追加検査は未実施）",
      explanation: usedModel ? `${usedModel.actor}を使用` : "解説は内蔵機能で作成" };
  }

  const plan = usedArtex
    ? `ARTEXで作成した計画${modelLabel}`
    : snap.plan_source?.engine === "unverified"
      ? `検証用プランナーの計画${modelLabel}`
    : snap.planner.external_model_configured
      ? "診断手順（提案元はログで確認）"
      : "内蔵の診断手順";
  const explanation = usedModel ? `${usedModel.actor}を使用` : snap.planner.explanation_model_configured
    ? "外部AI解説を設定済み（回答ごとに出所表示）"
    : "解説は内蔵機能で作成";
  return { plan, explanation };
}
