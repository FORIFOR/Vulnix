/** A finding's current explanation, without presenting an old detection as current. */
export function findingReason(f: {
  evidence_status: string;
  why_detected?: string | null;
  verdict_note?: string | null;
  summary: string;
}): { heading: string; text: string } {
  if (f.evidence_status === "not_reproduced") {
    return { heading: "再確認の結果", text: f.verdict_note || f.summary };
  }
  if (f.evidence_status === "incomplete") {
    return { heading: "確認できなかった理由", text: f.verdict_note || f.summary };
  }
  if (f.evidence_status === "candidate") {
    return { heading: "なぜ確認候補になったか", text: f.why_detected || f.summary };
  }
  return { heading: "なぜ検出されたか", text: f.why_detected || f.summary };
}
