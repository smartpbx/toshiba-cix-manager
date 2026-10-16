// One fetch helper per verb. The daemon plants an HttpOnly SameSite=Strict
// cookie on the "/" load, so same-origin fetches authenticate with nothing
// added (DESIGN_PLAN 2.2); in dev, Vite proxies /api and auth is off.

import type { UISchema } from "./schema";
import type {
  FullSnapshot,
  Health,
  JobState,
  ProgramResult,
  SessionSnapshot,
  SnapshotHeader,
  SnapshotStart,
} from "./types";

async function jget<T>(path: string): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

async function jpost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  if (!res.ok && res.status >= 500) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

export const api = {
  health: () => jget<Health>("/api/health"),
  schema: () => jget<UISchema>("/api/schema"),

  // connect + snapshot-on-connect (core -> all) — returns session + job ids
  startSnapshot: (p: {
    ip: string;
    community: string;
    port: number;
    reach: string;
    site?: string;
    site_id?: string;
  }) => jpost<SnapshotStart>("/api/snapshot", p),

  job: (id: string) => jget<{ ok: boolean; job: JobState }>(`/api/jobs/${id}`),

  sessionSnapshot: (sessionId: string) =>
    jget<SessionSnapshot>(`/api/sessions/${sessionId}/snapshot`),

  program: (sessionId: string, key: string, refresh = false) =>
    jget<ProgramResult>(
      `/api/sessions/${sessionId}/program/${encodeURIComponent(key)}` +
        (refresh ? "?refresh=1" : ""),
    ),

  // cold start: browse the last snapshot with the device off
  siteSnapshots: (siteId: string) =>
    jget<{ ok: boolean; snapshots: SnapshotHeader[] }>(
      `/api/sites/${encodeURIComponent(siteId)}/snapshots`,
    ),

  siteSnapshotLatest: (siteId: string) =>
    jget<{ ok: boolean; snapshot: FullSnapshot | null }>(
      `/api/sites/${encodeURIComponent(siteId)}/snapshots/latest`,
    ),
};
