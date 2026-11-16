import type { Snapshot } from "./types";

export class ApiHttpError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

export async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new ApiHttpError((await res.json().catch(() => ({}))).error ?? `HTTP ${res.status}`, res.status);
  return res.json();
}

export async function postJSON<T>(path: string, body: unknown = {}): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Aegis-Request": "1" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
  return data as T;
}

export async function command(path: string, body: unknown = {}): Promise<Snapshot | { stop_report: unknown }> {
  return postJSON<Snapshot | { stop_report: unknown }>(path, body);
}
