"use client";

import { createContext, useContext } from "react";
import type { OrgInfo } from "./org";

export interface SessionInfo {
  operator: string;
  roles: string[];
  expires: number;
  mfa_enabled?: boolean;
}

export interface SessionCtx {
  session: SessionInfo | null;
  loading: boolean;
  /** organizations of this account (multi-tenant control plane only) */
  orgs: OrgInfo[];
  multiTenant: boolean;
  org: OrgInfo | null;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

export const SessionContext = createContext<SessionCtx>({
  session: null,
  loading: true,
  orgs: [],
  multiTenant: false,
  org: null,
  refresh: async () => {},
  logout: async () => {},
});

export const useSession = () => useContext(SessionContext);
export const canApprove = (s: SessionInfo | null) => !!s?.roles.includes("approver");
export const isAdmin = (s: SessionInfo | null) => !!s?.roles.includes("admin");
