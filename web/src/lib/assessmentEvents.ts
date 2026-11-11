import type { AegisEvent, Approval, ChatMessage, Finding, Snapshot } from "./types";

function upsert<T extends { id: string }>(list: T[], item: T): T[] {
  const i = list.findIndex((x) => x.id === item.id);
  if (i === -1) return [...list, item];
  const next = list.slice();
  next[i] = item;
  return next;
}

export function applyEvent(s: Snapshot, ev: AegisEvent): Snapshot {
  switch (ev.type) {
    case "phase.updated":
      return { ...s, phases: ev.phases as Snapshot["phases"] };
    case "assessment.state":
      return {
        ...s, state: ev.state as Snapshot["state"], risk: ev.risk as Snapshot["risk"],
        // the cause travels with the state; an event without one clears a stale cause
        failure: (ev.failure ?? null) as Snapshot["failure"],
      };
    case "activity.updated":
      return { ...s, activity: ev.activity as Snapshot["activity"] };
    case "approval.updated":
      return { ...s, approvals: upsert(s.approvals, ev.approval as Approval) };
    case "finding.upserted":
      return {
        ...s,
        findings: upsert(s.findings, ev.finding as Finding),
        evidence_summary: ev.evidence_summary as Snapshot["evidence_summary"],
        risk: ev.risk as Snapshot["risk"],
      };
    case "stop.report":
      return { ...s, stop_report: ev.stop_report as Snapshot["stop_report"] };
    case "chat.message": {
      const incoming = (ev.messages as ChatMessage[]) ?? [];
      const cur = s.chat_messages ?? [];
      const seen = new Set(cur.map((m) => m.id));
      const merged = [...cur, ...incoming.filter((m) => !seen.has(m.id))];
      return { ...s, chat_messages: merged };
    }
    default:
      return s;
  }
}


/** Merge a slow chat reply without restoring the pre-request assessment state. */
export function applyChatReply(s: Snapshot, reply: { chat_messages?: ChatMessage[]; planner?: Snapshot["planner"] }): Snapshot {
  const messages = [...(s.chat_messages ?? [])];
  for (const message of reply.chat_messages ?? []) {
    if (!messages.some((m) => m.id === message.id)) messages.push(message);
  }
  return {
    ...s,
    chat_messages: messages,
    planner: reply.planner ? { ...reply.planner, connection_verified: reply.planner.connection_verified || s.planner.connection_verified } : s.planner,
  };
}
