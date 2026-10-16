// One fetch helper per verb. The daemon plants an HttpOnly SameSite=Strict
// cookie on the "/" load, so same-origin fetches authenticate with nothing
// added (DESIGN_PLAN 2.2); in dev, Vite proxies /api and auth is off.

import type { UISchema } from "./schema";
import type {
  AnnotatedDiffResult,
  FindResult,
  FullSnapshot,
  Health,
  JobState,
  ModeState,
  OpLog,
  PendingResult,
  ProgramResult,
  ReviewResult,
  SessionSnapshot,
  SnapshotHeader,
  SnapshotStart,
  VmBoxDetail,
  VmBoxRow,
  VmDiff,
  VmEditorModel,
  VmPbxDb,
  VmPlan,
  VmReport,
  VmReportTemplate,
  VmStatus,
  VmSysParams,
} from "./types";

async function jget<T>(path: string): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

async function jbody<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  if (!res.ok && res.status >= 500) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

const jpost = <T>(path: string, body?: unknown) => jbody<T>("POST", path, body);
const s = (id: string) => encodeURIComponent(id);

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

  // -- P2 write path (two-phase; staging/review touch no network) ---------
  // Stage {field: new_value} for one row into the session changeset.
  stagePending: (
    sessionId: string,
    body: { program: string; index: string; changes: Record<string, string>; originals?: Record<string, string> },
  ) => jpost<PendingResult>(`/api/sessions/${s(sessionId)}/pending`, body),

  getPending: (sessionId: string) =>
    jget<PendingResult>(`/api/sessions/${s(sessionId)}/pending`),

  clearPending: (sessionId: string, loc?: { program: string; index: string }) =>
    jbody<{ ok: boolean; field_count: number; row_count: number }>(
      "DELETE",
      `/api/sessions/${s(sessionId)}/pending` +
        (loc ? `?program=${s(loc.program)}&index=${s(loc.index)}` : ""),
    ),

  bulkEdit: (sessionId: string, body: Record<string, unknown>) =>
    jpost<{ ok: boolean; staged_rows?: number; field_count?: number; error?: string }>(
      `/api/sessions/${s(sessionId)}/bulk`,
      body,
    ),

  reviewChangeset: (sessionId: string, body: { simulate?: boolean; refresh?: boolean }) =>
    jpost<{ ok: boolean; review: ReviewResult }>(
      `/api/sessions/${s(sessionId)}/review`,
      body,
    ),

  // The ONE write call — invoked only from ReviewWriteDialog (a backend test
  // greps the UI to enforce that). Simulate opens no socket; live is gated.
  applyChangeset: (
    sessionId: string,
    body: { mode: "simulate" | "live"; confirm?: boolean; site_name_typed?: string },
  ) => jpost<{ ok: boolean; mode?: string; review?: ReviewResult; oplog?: OpLog; result?: unknown; error?: string }>(
    `/api/sessions/${s(sessionId)}/apply`,
    body,
  ),

  undoChangeset: (sessionId: string) =>
    jpost<{ ok: boolean; review?: ReviewResult; error?: string }>(
      `/api/sessions/${s(sessionId)}/undo`,
      {},
    ),

  setMode: (sessionId: string, mode: "disarmed" | "armed" | "simulate") =>
    jpost<{ ok: boolean; mode?: ModeState; error?: string }>(
      `/api/sessions/${s(sessionId)}/mode`,
      { mode },
    ),

  // value index: palette value search + where-used over the working copy
  find: (sessionId: string, q: string, refs = false) =>
    jget<FindResult>(
      `/api/sessions/${s(sessionId)}/find?q=${encodeURIComponent(q)}` +
        (refs ? "&refs=1" : ""),
    ),

  // cold start: browse the last snapshot with the device off
  siteSnapshots: (siteId: string) =>
    jget<{ ok: boolean; snapshots: SnapshotHeader[] }>(
      `/api/sites/${s(siteId)}/snapshots`,
    ),

  siteSnapshotLatest: (siteId: string) =>
    jget<{ ok: boolean; snapshot: FullSnapshot | null }>(
      `/api/sites/${s(siteId)}/snapshots/latest`,
    ),

  // -- Backups page (backups.md §4) ---------------------------------------
  snapshotFull: (siteId: string, sid: string) =>
    jget<{ ok: boolean; snapshot: FullSnapshot | null }>(
      `/api/sites/${s(siteId)}/snapshots/${s(sid)}`,
    ),

  snapshotProgram: (siteId: string, sid: string, key: string) =>
    jget<ProgramResult>(
      `/api/sites/${s(siteId)}/snapshots/${s(sid)}/program/${s(key)}`,
    ),

  snapshotFind: (siteId: string, sid: string, q: string, refs = false) =>
    jget<FindResult>(
      `/api/sites/${s(siteId)}/snapshots/${s(sid)}/find?q=${encodeURIComponent(q)}` +
        (refs ? "&refs=1" : ""),
    ),

  takeSnapshot: (
    siteId: string,
    body: { session?: string; scope?: string; name?: string; tags?: string[] },
  ) => jpost<{ ok: boolean; snapshot?: SnapshotHeader; error?: string }>(
    `/api/sites/${s(siteId)}/snapshots`,
    body,
  ),

  patchSnapshot: (
    siteId: string,
    sid: string,
    body: { name?: string; note?: string; tags?: string[]; pinned?: boolean },
  ) => jbody<{ ok: boolean; snapshot?: SnapshotHeader; error?: string }>(
    "PATCH",
    `/api/sites/${s(siteId)}/snapshots/${s(sid)}`,
    body,
  ),

  deleteSnapshot: (siteId: string, sid: string, force = false) =>
    jbody<{ ok: boolean; reason?: string }>(
      "DELETE",
      `/api/sites/${s(siteId)}/snapshots/${s(sid)}` + (force ? "?force=1" : ""),
    ),

  exportUrl: (
    siteId: string,
    sid: string,
    opts?: { redact?: boolean; container?: "cixbak" | "json" },
  ) =>
    `/api/sites/${s(siteId)}/snapshots/${s(sid)}/export?redact=${
      opts?.redact === false ? "0" : "1"
    }&container=${opts?.container ?? "cixbak"}`,

  diffReview: (body: {
    a: DiffSource;
    b: DiffSource;
    all?: boolean;
    volatile?: boolean;
    cross_site?: boolean;
  }) => jpost<AnnotatedDiffResult>("/api/diff/review", body),

  compareLive: (
    siteId: string,
    body: { snapshot?: string; session?: string; all?: boolean; volatile?: boolean },
  ) => jpost<AnnotatedDiffResult & { b_snapshot?: SnapshotHeader }>(
    `/api/sites/${s(siteId)}/compare-live`,
    body,
  ),

  // -- Voice Mail (Stratagy LVMU) leg (DESIGN_PLAN §8) --------------------
  vm: {
    ports: () => jpost<{ ok: boolean; ports: string[] }>("/api/vm/ports"),
    connect: (spec: Record<string, unknown>) =>
      jpost<{ ok: boolean; status?: VmStatus; error?: string }>("/api/vm/connect", spec),
    disconnect: () => jpost<{ ok: boolean }>("/api/vm/disconnect"),
    status: () => jget<{ ok: boolean; status: VmStatus }>("/api/vm/status"),
    catalog: () => jget<{ ok: boolean; editor: VmEditorModel }>("/api/vm/catalog"),
    boxes: (refresh = false) =>
      jget<{ ok: boolean; boxes: VmBoxRow[] }>(
        "/api/vm/boxes" + (refresh ? "?refresh=1" : ""),
      ),
    box: (id: string, refresh = false) =>
      jget<VmBoxDetail>(
        `/api/vm/boxes/${s(id)}` + (refresh ? "?refresh=1" : ""),
      ),
    saveBox: (id: string, changes: Record<string, unknown>) =>
      jpost<{ ok: boolean; plan: VmPlan }>(`/api/vm/boxes/${s(id)}/save`, { changes }),
    sysparams: (refresh = false) =>
      jget<{ ok: boolean; sysparams: VmSysParams }>(
        "/api/vm/sysparams" + (refresh ? "?refresh=1" : ""),
      ),
    pbxdb: (compare = false) =>
      jget<{ ok: boolean; pbxdb: VmPbxDb }>(
        "/api/vm/pbxdb" + (compare ? "?compare=1" : ""),
      ),
    backupJson: (site?: string) =>
      jpost<{ ok: boolean; backup: Record<string, unknown> }>(
        "/api/vm/backup/json", { site },
      ),
    diff: (a: Record<string, unknown>, b: Record<string, unknown>) =>
      jpost<{ ok: boolean; diff: VmDiff }>("/api/vm/diff", { a, b }),
    reportTemplates: () =>
      jget<{ ok: boolean; templates: VmReportTemplate[] }>("/api/vm/reports/templates"),
    runReport: (template: string, first?: string, last?: string) =>
      jpost<{ ok: boolean; report: VmReport }>("/api/vm/reports/run", {
        template, first, last,
      }),
    traceUrl: () => "/api/vm/trace",
  },
};

export interface DiffSource {
  doc?: unknown;
  site?: string;
  snapshot?: string;
  latest?: boolean;
}
