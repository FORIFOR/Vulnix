"use client";

// Snapshot + SSE sync. Events are applied only if their server `seq` is newer
// than what we have; duplicates are dropped and a gap triggers a full refetch,
// so the screen always converges on server state.
import { useCallback, useEffect, useRef, useState } from "react";
import { getJSON } from "./api";
import type { AegisEvent, Approval, AuditEntry, ChatMessage, Finding, Snapshot } from "./types";

export type Conn = "connecting" | "live" | "reconnecting" | "offline";

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
      return { ...s, state: ev.state as Snapshot["state"], risk: ev.risk as Snapshot["risk"] };
    case "activity.updated":
      return { ...s, activity: ev.activity as Snapshot["activity"] };
    case "approval.updated":
      return { ...s, approvals: upsert(s.approvals, ev.approval as Approval) };
    case "finding.upserted":
      return { ...s, findings: upsert(s.findings, ev.finding as Finding), risk: ev.risk as Snapshot["risk"] };
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

export function useAssessment(id: string) {
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [conn, setConn] = useState<Conn>("connecting");
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [notes, setNotes] = useState<AegisEvent[]>([]);
  const seqRef = useRef(0);
  const auditHashes = useRef(new Set<string>());
  const lastHashRef = useRef<string | null>(null);
  const verifyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refetch = useCallback(async () => {
    try {
      const [s, logs] = await Promise.all([
        getJSON<Snapshot>(`/api/assessments/${id}`),
        getJSON<{ entries: AuditEntry[]; chain_valid: boolean }>(`/api/assessments/${id}/logs`),
      ]);
      seqRef.current = Math.max(seqRef.current, s.last_seq);
      setSnap(s);
      auditHashes.current = new Set(logs.entries.map((e) => e.hash));
      lastHashRef.current = logs.entries.at(-1)?.hash ?? null;
      setAudit(logs.entries);
      setChainValid(logs.chain_valid);
      setError(null);
      return s.last_seq;
    } catch (e) {
      setError((e as Error).message);
      return null;
    }
  }, [id]);

  // Authoritative re-verification against the server, debounced so a burst of
  // new audit entries triggers a single check rather than one per entry.
  const scheduleVerify = useCallback(() => {
    if (verifyTimer.current) clearTimeout(verifyTimer.current);
    verifyTimer.current = setTimeout(async () => {
      try {
        const logs = await getJSON<{ entries: AuditEntry[]; chain_valid: boolean }>(
          `/api/assessments/${id}/logs`,
        );
        setChainValid(logs.chain_valid);
      } catch {
        /* leave the last known value; a reconnect will refetch */
      }
    }, 1200);
  }, [id]);

  useEffect(() => {
    let es: EventSource | null = null;
    let cancelled = false;
    (async () => {
      const last = await refetch();
      if (cancelled || last === null) {
        setConn("offline");
        return;
      }
      es = new EventSource(`/api/assessments/${id}/events?after=${last}`);
      es.onopen = () => setConn("live");
      es.onerror = () => setConn(es?.readyState === EventSource.CLOSED ? "offline" : "reconnecting");
      es.onmessage = (m) => {
        const ev = JSON.parse(m.data) as AegisEvent;
        if (ev.seq <= seqRef.current) return; // duplicate / stale
        const gap = ev.seq > seqRef.current + 1;
        seqRef.current = ev.seq;
        if (gap) {
          void refetch();
          return;
        }
        if (ev.type === "audit.recorded") {
          const entry = ev.entry as AuditEntry;
          if (!auditHashes.current.has(entry.hash)) {
            // Live link check: this entry must chain onto the previous hash.
            if (lastHashRef.current !== null && entry.prev !== lastHashRef.current) {
              setChainValid(false);
            }
            lastHashRef.current = entry.hash;
            auditHashes.current.add(entry.hash);
            setAudit((a) => [...a, entry]);
            scheduleVerify();
          }
          return;
        }
        if (ev.type === "agent.note") setNotes((n) => [...n, ev]);
        setSnap((s) => (s ? applyEvent(s, ev) : s));
      };
    })();
    return () => {
      cancelled = true;
      es?.close();
      if (verifyTimer.current) clearTimeout(verifyTimer.current);
    };
  }, [id, refetch, scheduleVerify]);

  return { snap, setSnap, error, conn, audit, chainValid, notes, refetch };
}
