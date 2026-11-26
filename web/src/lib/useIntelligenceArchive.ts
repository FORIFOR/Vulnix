"use client";

import { useEffect, useState } from "react";
import { ApiHttpError, getJSON } from "./api";
import type { RunHistoryEntry } from "./types";
import type { Conn } from "./useAssessment";

export type Archive = { state: "available" | "audit_unavailable" | "persistence_error"; runs: RunHistoryEntry[] };

export function useIntelligenceArchive(asset: string, state: string, conn: Conn) {
  const [view, setView] = useState<{ asset: string; archive: Archive | null; denied: boolean } | null>(null);
  useEffect(() => {
    let active = true;
    getJSON<Archive>("/api/assets/intelligence").then(
      (archive) => { if (active) setView({ asset, archive, denied: false }); },
      (error) => {
        if (active) setView({ asset, archive: null, denied: error instanceof ApiHttpError && [401, 403].includes(error.status) });
      },
    );
    return () => { active = false; };
  }, [asset, state, conn]);
  return view?.asset === asset ? view : null;
}
