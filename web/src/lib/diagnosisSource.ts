import type { Snapshot } from "./types";

/** Say what actually ran, not what happens to be installed or configured. */
export function diagnosisSource(snap: Pick<Snapshot, "is_external_service" | "planner" | "artex_plan" | "chat_messages">) {
  const usedModel = snap.chat_messages?.findLast((m) => m.role === "assistant" && m.source === "external_model");
  if (snap.is_external_service) {
    return { plan: "公開ページの設定を確認",
      explanation: usedModel ? `${usedModel.actor}を使用` : "解説は内蔵機能で作成" };
  }

  const engine = snap.artex_plan?.plan?.engine;
  const plan = engine?.kind === "artex-binary" && engine.pinned
    ? "ARTEXで作成した計画"
    : snap.planner.external_model_configured
      ? "診断手順（提案元はログで確認）"
      : "内蔵の診断手順";
  const explanation = usedModel ? `${usedModel.actor}を使用` : snap.planner.explanation_model_configured
    ? "外部AI解説を設定済み（回答ごとに出所表示）"
    : "解説は内蔵機能で作成";
  return { plan, explanation };
}
