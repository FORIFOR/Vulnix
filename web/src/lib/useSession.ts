"use client";

import { createContext, useContext } from "react";

export interface SessionInfo {
  operator: string;
  roles: string[];
  expires: number;
  mfa_enabled?: boolean;
}

export interface SessionCtx {
  session: SessionInfo | null;
  loading: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

export const SessionContext = createContext<SessionCtx>({
  session: null,
  loading: true,
  refresh: async () => {},
  logout: async () => {},
});

export const useSession = () => useContext(SessionContext);
export const canApprove = (s: SessionInfo | null) => !!s?.roles.includes("approver");
