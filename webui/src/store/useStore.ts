import { create } from "zustand";
import { api } from "@/lib/api";
import type { UISchema } from "@/lib/schema";
import type {
  ConnectionForm,
  Identity,
  JobState,
  ProgramView,
  SnapshotMeta,
} from "@/lib/types";

type Theme = "system" | "light" | "dark";

export interface Tab {
  id: string;
  kind: "home" | "program";
  programKey?: string;
  title: string;
}

export type ConnStatus =
  | "idle"
  | "connecting"
  | "reading"
  | "done"
  | "error"
  | "cold";

interface Progress {
  status: ConnStatus;
  done: number;
  total: number;
  message: string;
  jobId: string | null;
  error?: string | null;
}

interface AppState {
  // schema (static UI data) ------------------------------------------------
  schema: UISchema | null;
  schemaError: string | null;
  loadSchema: () => Promise<void>;
  version: string;

  // connection / session ---------------------------------------------------
  form: ConnectionForm;
  setForm: (patch: Partial<ConnectionForm>) => void;
  connectDrawerOpen: boolean;
  setConnectDrawerOpen: (open: boolean) => void;

  sessionId: string | null;
  identity: Identity | null;
  snapshotMeta: SnapshotMeta | null;
  coldStart: boolean;
  progress: Progress;

  connect: () => Promise<void>;
  openColdSnapshot: (siteId?: string) => Promise<boolean>;

  // SSE handlers -----------------------------------------------------------
  onJob: (job: JobState) => void;
  onSessionPrograms: () => void;
  onIdentity: (identity: Identity) => void;
  refreshSessionIndex: () => Promise<void>;

  // working copy -----------------------------------------------------------
  programViews: Record<string, ProgramView>;
  readKeys: Set<string>;
  rowCounts: Record<string, number>;
  loadingKeys: Set<string>;
  ensureProgram: (key: string) => void;
  refreshProgram: (key: string) => Promise<void>;

  // tabs -------------------------------------------------------------------
  tabs: Tab[];
  activeTabId: string;
  openProgram: (key: string, title: string) => void;
  openHome: () => void;
  closeTab: (id: string) => void;
  setActiveTab: (id: string) => void;

  // nav / palette / theme --------------------------------------------------
  openAreas: Record<string, boolean>;
  toggleArea: (area: string) => void;
  setArea: (area: string, open: boolean) => void;
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
  theme: Theme;
  setTheme: (t: Theme) => void;
}

function readStoredTheme(): Theme {
  try {
    const t = localStorage.getItem("switchroom.theme");
    if (t === "light" || t === "dark" || t === "system") return t;
  } catch {
    /* private mode / blocked storage */
  }
  return "system";
}

const HOME_TAB: Tab = { id: "home", kind: "home", title: "Home" };

export const useStore = create<AppState>((set, get) => ({
  schema: null,
  schemaError: null,
  version: "",
  async loadSchema() {
    try {
      const [schema, health] = await Promise.all([
        api.schema(),
        api.health().catch(() => null),
      ]);
      set({ schema, schemaError: null, version: health?.version ?? "" });
    } catch (e) {
      set({ schemaError: (e as Error).message });
    }
  },

  form: {
    ip: "",
    community: "communityName",
    port: 161,
    reach: "direct",
    site: "",
    site_id: "",
  },
  setForm: (patch) => set((s) => ({ form: { ...s.form, ...patch } })),
  connectDrawerOpen: false,
  setConnectDrawerOpen: (connectDrawerOpen) => set({ connectDrawerOpen }),

  sessionId: null,
  identity: null,
  snapshotMeta: null,
  coldStart: false,
  progress: { status: "idle", done: 0, total: 0, message: "", jobId: null },

  async connect() {
    const { form } = get();
    if (!form.ip.trim()) return;
    set({
      progress: {
        status: "connecting",
        done: 0,
        total: 0,
        message: "Connecting…",
        jobId: null,
      },
    });
    try {
      const res = await api.startSnapshot({
        ip: form.ip.trim(),
        community: form.community.trim() || "communityName",
        port: form.port || 161,
        reach: form.reach,
        site: form.site || undefined,
        site_id: form.site_id || undefined,
      });
      if (!res.ok || !res.session || !res.job) {
        set({
          progress: {
            status: "error",
            done: 0,
            total: 0,
            message: res.error ?? "Connect failed.",
            jobId: null,
            error: res.error,
          },
        });
        return;
      }
      set({
        sessionId: res.session,
        coldStart: false,
        programViews: {},
        readKeys: new Set(),
        rowCounts: {},
        connectDrawerOpen: false,
        form: { ...form, site_id: res.site_id ?? form.site_id },
        progress: {
          status: "reading",
          done: 0,
          total: 0,
          message: "Reading core programs…",
          jobId: res.job,
        },
      });
    } catch (e) {
      set({
        progress: {
          status: "error",
          done: 0,
          total: 0,
          message: (e as Error).message,
          jobId: null,
          error: (e as Error).message,
        },
      });
    }
  },

  async openColdSnapshot(siteId) {
    const id = siteId ?? get().form.site_id;
    if (!id) return false;
    try {
      const res = await api.siteSnapshotLatest(id);
      if (!res.ok || !res.snapshot) return false;
      const snap = res.snapshot;
      const views: Record<string, ProgramView> = {};
      const rowCounts: Record<string, number> = {};
      for (const pv of snap.program_views.programs ?? []) {
        views[pv.catalog_key] = pv;
        rowCounts[pv.catalog_key] = pv.row_count;
      }
      set({
        coldStart: true,
        sessionId: null,
        programViews: views,
        readKeys: new Set(Object.keys(views)),
        rowCounts,
        identity: snap.identity ?? null,
        snapshotMeta: snap.meta ?? null,
        connectDrawerOpen: false,
        progress: {
          status: "cold",
          done: 0,
          total: 0,
          message: `Opened snapshot from ${snap.saved_at}`,
          jobId: null,
        },
      });
      return true;
    } catch {
      return false;
    }
  },

  onJob(job) {
    const { progress } = get();
    if (progress.jobId && job.id !== progress.jobId) return;
    if (job.status === "done") {
      set({
        progress: {
          status: "done",
          done: job.total,
          total: job.total,
          message: "Snapshot complete.",
          jobId: job.id,
        },
      });
      void get().refreshSessionIndex();
    } else if (job.status === "error") {
      set({
        progress: {
          status: "error",
          done: job.done,
          total: job.total,
          message: job.error ?? "Snapshot failed.",
          jobId: job.id,
          error: job.error,
        },
      });
    } else {
      set({
        progress: {
          status: "reading",
          done: job.done,
          total: job.total,
          message: job.message || "Reading…",
          jobId: job.id,
        },
      });
    }
  },

  onSessionPrograms() {
    void get().refreshSessionIndex();
  },

  onIdentity(identity) {
    set({ identity });
  },

  async refreshSessionIndex() {
    const { sessionId } = get();
    if (!sessionId) return;
    try {
      const snap = await api.sessionSnapshot(sessionId);
      if (!snap.ok) return;
      const rowCounts: Record<string, number> = {};
      for (const p of snap.programs) rowCounts[p.catalog_key] = p.row_count;
      set({
        readKeys: new Set(snap.read_keys),
        rowCounts,
        identity: snap.identity ?? get().identity,
        snapshotMeta: snap.meta ?? get().snapshotMeta,
      });
    } catch {
      /* transient */
    }
  },

  programViews: {},
  readKeys: new Set(),
  rowCounts: {},
  loadingKeys: new Set(),
  ensureProgram(key) {
    const { programViews, loadingKeys, sessionId, coldStart } = get();
    if (programViews[key] || loadingKeys.has(key)) return;
    if (coldStart || !sessionId) return; // cold snapshot already holds everything
    const next = new Set(loadingKeys);
    next.add(key);
    set({ loadingKeys: next });
    api
      .program(sessionId, key)
      .then((res) => {
        if (res.ok && res.program) {
          set((s) => ({ programViews: { ...s.programViews, [key]: res.program! } }));
        }
      })
      .catch(() => {})
      .finally(() => {
        const after = new Set(get().loadingKeys);
        after.delete(key);
        set({ loadingKeys: after });
      });
  },
  async refreshProgram(key) {
    const { sessionId } = get();
    if (!sessionId) return;
    const next = new Set(get().loadingKeys);
    next.add(key);
    set({ loadingKeys: next });
    try {
      const res = await api.program(sessionId, key, true);
      if (res.ok && res.program) {
        set((s) => ({
          programViews: { ...s.programViews, [key]: res.program! },
          readKeys: new Set(s.readKeys).add(key),
          rowCounts: { ...s.rowCounts, [key]: res.program!.row_count },
        }));
      }
    } catch {
      /* transient */
    } finally {
      const after = new Set(get().loadingKeys);
      after.delete(key);
      set({ loadingKeys: after });
    }
  },

  tabs: [HOME_TAB],
  activeTabId: "home",
  openProgram(key, title) {
    const id = `prog:${key}`;
    const { tabs } = get();
    if (!tabs.some((t) => t.id === id)) {
      set({ tabs: [...tabs, { id, kind: "program", programKey: key, title }] });
    }
    set({ activeTabId: id });
    get().ensureProgram(key);
  },
  openHome() {
    const { tabs } = get();
    if (!tabs.some((t) => t.id === "home")) set({ tabs: [HOME_TAB, ...tabs] });
    set({ activeTabId: "home" });
  },
  closeTab(id) {
    if (id === "home") return;
    const { tabs, activeTabId } = get();
    const idx = tabs.findIndex((t) => t.id === id);
    const next = tabs.filter((t) => t.id !== id);
    let active = activeTabId;
    if (activeTabId === id) {
      active = (next[idx - 1] ?? next[idx] ?? next[0] ?? HOME_TAB).id;
    }
    set({ tabs: next.length ? next : [HOME_TAB], activeTabId: active });
  },
  setActiveTab(id) {
    set({ activeTabId: id });
    const tab = get().tabs.find((t) => t.id === id);
    if (tab?.kind === "program" && tab.programKey) get().ensureProgram(tab.programKey);
  },

  openAreas: {},
  toggleArea: (area) =>
    set((s) => ({ openAreas: { ...s.openAreas, [area]: !s.openAreas[area] } })),
  setArea: (area, open) =>
    set((s) => ({ openAreas: { ...s.openAreas, [area]: open } })),
  paletteOpen: false,
  setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
  theme: readStoredTheme(),
  setTheme: (theme) => {
    try {
      localStorage.setItem("switchroom.theme", theme);
    } catch {
      /* ignore */
    }
    set({ theme });
  },
}));
