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
    case "artex.plan":
      return { ...s, artex_plan: ev.artex_plan as Snapshot["artex_plan"] };
    case "chat.message": {
      const incoming = (ev.messages as ChatMessage[]) ?? [];
      const cur = s.chat_messages ?? [];
      const seen = new Set(cur.map((m) => m.id));
      const merged = [...cur, ...incoming.filter((m) => !seen.has(m.id))];
      return { ...s, chat_messages: merged, planner: newerPlanner(s.planner, ev.planner as Partial<Snapshot["planner"]> | undefined) };
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
    planner: newerPlanner(s.planner, reply.planner),
  };
}

/** The server numbers every change of the model's connection state. A reply or
 *  event that arrives late carries an older number and must not undo a newer state
 *  (in either direction: a stale "verified" must not hide a newer failure). A
 *  different boot id is a restarted server: its numbering starts over and wins.
 *  An event may carry only the connection fields: they are merged over the rest. */
export function newerPlanner(cur: Snapshot["planner"], incoming?: Partial<Snapshot["planner"]>): Snapshot["planner"] {
  if (!incoming) return cur;
  if (!cur) return incoming as Snapshot["planner"];
  const restarted = incoming.boot_id !== undefined && incoming.boot_id !== cur.boot_id;
  if (restarted || (incoming.status_seq ?? -1) >= (cur.status_seq ?? -1)) return { ...cur, ...incoming };
  // older connection state: keep ours, but take the other (non-connection) fields
  const keep: Partial<Snapshot["planner"]> = {};
  for (const k of CONNECTION_FIELDS) if (k in cur) (keep as Record<string, unknown>)[k] = (cur as Record<string, unknown>)[k];
  return { ...cur, ...incoming, ...keep } as Snapshot["planner"];
}

const CONNECTION_FIELDS = ["connection_state", "connection_verified", "connected", "connection_checked_at",
  "connection_error", "status_seq", "boot_id", "note"] as const;

/** Replace a whole snapshot (refetch, action reply) without letting an older
 *  connection state in it undo a newer one already shown. */
export function withNewerPlanner(prev: Snapshot | null, next: Snapshot | null): Snapshot | null {
  if (!prev || !next) return next;
  return { ...next, planner: newerPlanner(prev.planner, next.planner) };
}
