"use client";

import { createContext, useContext } from "react";
import type { OrgInfo } from "./org";

export interface SessionInfo {
  operator: string;
  roles: string[];
  expires: number;
  mfa_enabled?: boolean;
  /** the account's own roles (platform functions); `roles` are those in the current organization */
  platform_roles?: string[];
}

export interface SessionCtx {
  session: SessionInfo | null;
  loading: boolean;
  /** organizations of this account (multi-tenant control plane only) */
  orgs: OrgInfo[];
  multiTenant: boolean;
  /** Whether the server allows public account registration. */
  selfRegistration: boolean;
  /** the control plane can prove site ownership through Google Search Console */
  googleOwnership: boolean;
  cloudInventoryConfigured: boolean;
  ownershipTrafficMode: "off" | "approved" | "preapproved" | "existing";
  /** Whether an optional second read-only status check is configured. */
  optionalStatusCheck: boolean;
  externalSiteTrafficEnabled: boolean | null;
  org: OrgInfo | null;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

export const SessionContext = createContext<SessionCtx>({
  session: null,
  loading: true,
  orgs: [],
  multiTenant: false,
  selfRegistration: false,
  googleOwnership: false,
  cloudInventoryConfigured: false,
  ownershipTrafficMode: "off",
  optionalStatusCheck: false,
  externalSiteTrafficEnabled: null,
  org: null,
  refresh: async () => {},
  logout: async () => {},
});

export const useSession = () => useContext(SessionContext);
export const canApprove = (s: SessionInfo | null) => !!s?.roles.includes("approver");
export const isAdmin = (s: SessionInfo | null) => !!s?.roles.includes("admin");
/** Platform functions (accounts, site profiles, control self-tests) use the account's own roles. */
export const platformRoles = (s: SessionInfo | null): string[] => s?.platform_roles ?? s?.roles ?? [];
export const isPlatformAdmin = (s: SessionInfo | null) => platformRoles(s).includes("admin");
