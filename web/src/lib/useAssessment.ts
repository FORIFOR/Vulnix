"use client";

// Snapshot + SSE sync. Events are applied only if their server `seq` is newer
// than what we have; duplicates are dropped and a gap triggers a full refetch,
// so the screen always converges on server state.
import { useCallback, useEffect, useRef, useState, type SetStateAction } from "react";
import { eventDecision, heartbeatDecision, needsAuthoritativeRefresh, needsPoll, POLL_EVERY_MS, serverRestarted, shouldApplyRequestFailure, shouldApplySnapshot } from "./polling";
import { ApiHttpError, getJSON } from "./api";
import { applyEvent, withNewerPlanner } from "./assessmentEvents";
import { applyDiagnosisEvent, slotFromFetch, type DiagnosisSlot } from "./diagnosisView";
import type { AegisEvent, AuditEntry, Snapshot } from "./types";

export type Conn = "connecting" | "live" | "reconnecting" | "offline";

type DiagnosisFetch = { ok: true; body: unknown } | { ok: false; status: number };

/** GET .../diagnosis. 404 (a real site or an ownership flow) is an answer, not a failure;
 *  401/403 is the same access loss as the snapshot's and is thrown to that path. */
async function fetchDiagnosis(id: string): Promise<DiagnosisFetch> {
  try {
    return { ok: true, body: await getJSON<unknown>(`/api/assessments/${id}/diagnosis`) };
  } catch (e) {
    if (e instanceof ApiHttpError && (e.status === 401 || e.status === 403)) throw e;
    return { ok: false, status: e instanceof ApiHttpError ? e.status : 0 };
  }
}

export function useAssessment(id: string) {
  const accessDeniedRef = useRef(false);
  const [snap, setRawSnap] = useState<Snapshot | null>(null);
  // Every whole-snapshot replacement keeps the newest model connection state.
  const setSnap = useCallback((next: SetStateAction<Snapshot | null>) => {
    if (!accessDeniedRef.current) {
      setRawSnap((prev) => withNewerPlanner(prev, typeof next === "function" ? next(prev) : next));
    }
  }, []);
  const [error, setError] = useState<string | null>(null);
  const [conn, setConn] = useState<Conn>("connecting");
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [notes, setNotes] = useState<AegisEvent[]>([]);
  const [diagnosis, setDiagnosis] = useState<DiagnosisSlot>({ kind: "loading" });
  const seqRef = useRef(0);
  const requestSerialRef = useRef(0);
  const appliedSerialRef = useRef(0);
  const lastSnapshotAtRef = useRef(0);
  const auditHashes = useRef(new Set<string>());
  const lastHashRef = useRef<string | null>(null);
  const verifyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const bootRef = useRef<string | null>(null);
  // set by the stream effect: reopen the event stream from a new sequence (after a restart)
  const reopenRef = useRef<((after: number) => void) | null>(null);
  const streamOpenRef = useRef(false);

  const refetch = useCallback(async () => {
    if (accessDeniedRef.current) return null;
    const requestSerial = ++requestSerialRef.current;
    try {
      const [s, logs] = await Promise.all([
        getJSON<Snapshot>(`/api/assessments/${id}`),
        getJSON<{ entries: AuditEntry[]; chain_valid: boolean }>(`/api/assessments/${id}/logs`),
      ]);
      // Read after the snapshot, never alongside it: the view is then at least as new as
      // the snapshot's last_seq, and an event up to that seq (dropped below as already
      // seen) cannot hold a newer view than the one read here.
      const diag = await fetchDiagnosis(id);
      if (accessDeniedRef.current) return null;
      const restarted = serverRestarted(bootRef.current, s.planner?.boot_id);
      if (restarted) {
        // a new server process numbers its events from zero again
        seqRef.current = 0;
        appliedSerialRef.current = 0;
      }
      if (typeof s.planner?.boot_id === "string" && s.planner.boot_id) bootRef.current = s.planner.boot_id;
      if (!shouldApplySnapshot(s.last_seq, seqRef.current, requestSerial, appliedSerialRef.current)) {
        // An SSE event arrived while the request was in flight. Keep its
        // newer state and try another authoritative read on the next tick.
        lastSnapshotAtRef.current = 0;
        return null;
      }
      seqRef.current = Math.max(seqRef.current, s.last_seq);
      appliedSerialRef.current = requestSerial;
      lastSnapshotAtRef.current = Date.now();
      setSnap(s);
      auditHashes.current = new Set(logs.entries.map((e) => e.hash));
      lastHashRef.current = logs.entries.at(-1)?.hash ?? null;
      setAudit(logs.entries);
      setChainValid(logs.chain_valid);
      // applied only when the snapshot is (no newer event arrived meanwhile)
      setDiagnosis((d) => slotFromFetch(d, diag, id));
      setError(null);
      // the first successful read opens the stream; a restarted server needs a new one
      if (restarted || !streamOpenRef.current) reopenRef.current?.(s.last_seq);
      return s.last_seq;
    } catch (e) {
      if (accessDeniedRef.current) return null;
      if (!shouldApplyRequestFailure(requestSerial, requestSerialRef.current, appliedSerialRef.current)) return null;
      if (e instanceof ApiHttpError && (e.status === 401 || e.status === 403)) {
        accessDeniedRef.current = true;
        setRawSnap(null);
        setAudit([]);
        setChainValid(null);
        setNotes([]);
        setDiagnosis({ kind: "absent" });
        setConn("offline");
      }
      setError((e as Error).message);
      return null;
    }
  }, [id, setSnap]);

  // Authoritative re-verification against the server, debounced so a burst of
  // new audit entries triggers a single check rather than one per entry.
  const scheduleVerify = useCallback(() => {
    if (verifyTimer.current) clearTimeout(verifyTimer.current);
    verifyTimer.current = setTimeout(async () => {
      try {
        const logs = await getJSON<{ entries: AuditEntry[]; chain_valid: boolean }>(
          `/api/assessments/${id}/logs`,
        );
        if (!accessDeniedRef.current && (logs.entries.at(-1)?.hash ?? null) === lastHashRef.current) {
          setChainValid(logs.chain_valid);
        }
      } catch {
        /* leave the last known value; a reconnect will refetch */
      }
    }, 1200);
  }, [id]);

  useEffect(() => {
    let es: EventSource | null = null;
    let cancelled = false;
    // another assessment (or a remount) starts from scratch
    seqRef.current = 0;
    bootRef.current = null;
    let lastEventAt = Date.now();
    lastSnapshotAtRef.current = lastEventAt;
    // backup for paths that hold event streams back (e.g. Cloudflare Quick Tunnels)
    const poll = setInterval(() => {
      const now = Date.now();
      const visible = document.visibilityState === "visible";
      if (needsPoll(lastEventAt, now, visible) ||
          needsAuthoritativeRefresh(lastSnapshotAtRef.current, now, visible)) {
        lastEventAt = Date.now();
        void refetch();
      }
    }, POLL_EVERY_MS);
    const onHeartbeat = (message: Event) => {
      let serverSeq: unknown;
      try {
        serverSeq = (JSON.parse((message as MessageEvent).data) as { seq?: unknown }).seq;
      } catch {
        return; // malformed data must not disable the fallback
      }
      const decision = heartbeatDecision(serverSeq, seqRef.current);
      if (decision === "ignore") return;
      lastEventAt = Date.now();
      if (decision === "refresh") void refetch();
    };
    const onMessage = (m: MessageEvent) => {
      if (accessDeniedRef.current) return;
      lastEventAt = Date.now();
      const ev = JSON.parse(m.data) as AegisEvent;
      const decision = eventDecision(ev.seq, seqRef.current);
      if (decision === "drop") return; // duplicate / stale
      const gap = decision === "refetch";
      seqRef.current = ev.seq;
      // Any snapshot already in flight may predate this event even when its
      // sequence matches. Only a request started after the event can replace it.
      appliedSerialRef.current = requestSerialRef.current + 1;
      if (gap) {
        void refetch();
        return;
      }
      if (ev.type === "audit.recorded") {
        const entry = ev.entry as AuditEntry;
        if (!auditHashes.current.has(entry.hash)) {
          // Live link check: this entry must chain onto the previous hash.
          setChainValid(lastHashRef.current !== null && entry.prev !== lastHashRef.current ? false : null);
          lastHashRef.current = entry.hash;
          auditHashes.current.add(entry.hash);
          setAudit((a) => [...a, entry]);
          scheduleVerify();
        }
        return;
      }
      if (ev.type === "diagnosis.updated") {
        setDiagnosis((d) => applyDiagnosisEvent(d, ev, id));
        return;
      }
      if (ev.type === "agent.note") setNotes((n) => [...n, ev]);
      setSnap((s) => (s ? applyEvent(s, ev) : s));
      if (ev.type === "assessment.state" && (ev.state === "completed" || ev.state === "failed")) void refetch();
    };
    const open = (after: number) => {
      es?.close();
      if (cancelled) return;
      const stream = new EventSource(`/api/assessments/${id}/events?after=${after}`);
      es = stream;
      streamOpenRef.current = true;
      stream.onopen = () => setConn("live");
      stream.onerror = () => {
        setConn(stream.readyState === EventSource.CLOSED ? "offline" : "reconnecting");
        void refetch();
      };
      stream.addEventListener("heartbeat", onHeartbeat);
      stream.onmessage = onMessage;
    };
    reopenRef.current = open;
    // the stream opens on the first successful read (refetch calls `open`)
    (async () => {
      const last = await refetch();
      if (!cancelled && last === null && !streamOpenRef.current && !accessDeniedRef.current) setConn("offline");
    })();
    return () => {
      cancelled = true;
      reopenRef.current = null;
      streamOpenRef.current = false;
      clearInterval(poll);
      es?.close();
      if (verifyTimer.current) clearTimeout(verifyTimer.current);
    };
  }, [id, refetch, scheduleVerify, setSnap]);

  return { snap, setSnap, error, conn, audit, chainValid, notes, diagnosis, refetch };
}
