import { create } from "zustand";
import { api } from "@/lib/api";
import type { UISchema } from "@/lib/schema";
import type {
  ConnectionForm,
  Identity,
  JobState,
  ModeState,
  PendingGroup,
  ProgressDetail,
  ProgramStatus,
  ProgramView,
  Site,
  SnapshotHeader,
  SnapshotMeta,
  UpdateApplyResult,
  UpdateInfo,
  Validation,
  VmStatus,
} from "@/lib/types";

type Theme = "system" | "light" | "dark";
export type NavMode = "task" | "emanager";

export type VmScreen =
  | "status"
  | "boxes"
  | "sysparams"
  | "integration"
  | "backup"
  | "reports";

export interface Tab {
  id: string;
  kind: "home" | "program" | "backups" | "vm" | "problems" | "help" | "callflow";
  programKey?: string;
  vmScreen?: VmScreen;
  title: string;
}

export interface FileMode {
  siteId: string;
  sid: string;
  label: string;
  savedAt: string;
  swid?: string | null;
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
  detail?: ProgressDetail | null;
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

  // saved sites (the Connect drawer's one-click reconnect cards) -----------
  sites: Site[];
  loadSites: () => Promise<void>;
  connectToSite: (site: Site) => Promise<void>;
  addSite: (site: Partial<Site>) => Promise<boolean>;
  renameSite: (id: string, name: string) => Promise<void>;
  deleteSite: (id: string) => Promise<void>;

  // SSE handlers -----------------------------------------------------------
  onJob: (job: JobState) => void;
  onSessionPrograms: () => void;
  onIdentity: (identity: Identity) => void;
  refreshSessionIndex: () => Promise<void>;

  // working copy -----------------------------------------------------------
  programViews: Record<string, ProgramView>;
  readKeys: Set<string>;
  rowCounts: Record<string, number>;
  programStatus: Record<string, ProgramStatus>;
  loadingKeys: Set<string>;
  ensureProgram: (key: string) => void;
  refreshProgram: (key: string) => Promise<void>;

  // write path: pending tray + arming mode (P2) ---------------------------
  pending: PendingGroup[];
  pendingFieldCount: number;
  pendingValidation: Validation | null;
  mode: ModeState;
  railOpen: boolean;
  reviewOpen: boolean;
  refreshPending: () => Promise<void>;
  stageRowChanges: (
    programKey: string,
    index: string,
    changes: Record<string, string>,
    originals: Record<string, string>,
  ) => Promise<void>;
  clearPending: (loc?: { program: string; index: string }) => Promise<void>;
  bulkEdit: (body: Record<string, unknown>) => Promise<void>;
  setMode: (mode: "disarmed" | "armed" | "simulate") => Promise<void>;
  setRailOpen: (open: boolean) => void;
  openReview: () => void;
  closeReview: () => void;

  // voicemail (Stratagy LVMU leg) ------------------------------------------
  vmStatus: VmStatus | null;
  vmBusy: boolean;
  refreshVmStatus: () => Promise<void>;
  vmConnect: (spec: Record<string, unknown>) => Promise<string | null>;
  vmDisconnect: () => Promise<void>;

  // tabs -------------------------------------------------------------------
  tabs: Tab[];
  activeTabId: string;
  openProgram: (key: string, title: string) => void;
  openHome: () => void;
  openBackups: () => void;
  openProblems: () => void;
  openCallFlow: () => void;
  openHelp: () => void;
  openVm: (screen: VmScreen, title: string) => void;
  closeTab: (id: string) => void;
  setActiveTab: (id: string) => void;

  // backups / file mode ----------------------------------------------------
  fileMode: FileMode | null;
  siteId: () => string;
  enterFileMode: (siteId: string, header: SnapshotHeader) => Promise<boolean>;
  exitFileMode: () => void;

  // nav / palette / theme --------------------------------------------------
  openAreas: Record<string, boolean>;
  toggleArea: (area: string) => void;
  setArea: (area: string, open: boolean) => void;
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
  theme: Theme;
  setTheme: (t: Theme) => void;

  // tech preferences (per-laptop, persisted to localStorage switchroom.prefs) --
  navMode: NavMode;
  setNavMode: (m: NavMode) => void;
  showProgramNumbers: boolean;
  setShowProgramNumbers: (b: boolean) => void;
  prefsOpen: boolean;
  setPrefsOpen: (open: boolean) => void;
  // the trailing breadcrumb crumb a screen contributes (e.g. the selected
  // station's name on the Stations screen); cleared when that screen unmounts.
  recordCrumb: string | null;
  setRecordCrumb: (s: string | null) => void;

  // manager bridge (Conduit deep-link + Save to cloud) --------------------
  bridge: { active: boolean; component: string | null; systemName: string | null };
  bridgeSaving: boolean;
  bridgeSaveResult: { ok: boolean; text: string } | null;
  initBridge: () => Promise<void>;
  handleDeeplink: () => Promise<void>;
  saveToCloud: () => Promise<void>;
  clearBridgeSaveResult: () => void;

  // self-updater (toshiba_cix/update.py via /api/update) -------------------
  updateInfo: UpdateInfo | null;
  updateChecking: boolean;
  updateApplying: boolean;
  updateRelaunching: boolean;
  updateResult: UpdateApplyResult | null;
  updateDialogOpen: boolean;
  updateToastDismissed: boolean;
  checkUpdate: () => Promise<void>;
  applyUpdate: () => Promise<void>;
  relaunchApp: () => Promise<void>;
  setUpdateDialogOpen: (open: boolean) => void;
  dismissUpdateToast: () => void;
}

// Per-laptop tech preferences live in one JSON key so a tech's theme, menu mode
// and "show program numbers" choice travel together. Every access is guarded
// (private mode / blocked storage throws), and a legacy single-key theme is
// migrated on read so earlier installs keep their choice.
const PREFS_KEY = "switchroom.prefs";

interface StoredPrefs {
  theme?: Theme;
  navMode?: NavMode;
  showProgramNumbers?: boolean;
}

function readStoredPrefs(): StoredPrefs {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (raw) {
      const p = JSON.parse(raw) as StoredPrefs;
      if (p && typeof p === "object") return p;
    }
  } catch {
    /* private mode / blocked storage / bad JSON */
  }
  try {
    const t = localStorage.getItem("switchroom.theme");
    if (t === "light" || t === "dark" || t === "system") return { theme: t };
  } catch {
    /* ignore */
  }
  return {};
}

function persistPrefs(p: {
  theme: Theme;
  navMode: NavMode;
  showProgramNumbers: boolean;
}): void {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(p));
  } catch {
    /* ignore */
  }
}

const STORED_PREFS = readStoredPrefs();

// A saved snapshot records only its non-clean programs (meta.program_problems);
// turn that list into the key→status map the nav / Problems panel read, so a
// cold-opened snapshot still shows which programs failed.
function statusMapFromProblems(
  problems?: ProgramStatus[],
): Record<string, ProgramStatus> {
  const out: Record<string, ProgramStatus> = {};
  for (const p of problems ?? []) out[p.key] = p;
  return out;
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
        programStatus: {},
        pending: [],
        pendingFieldCount: 0,
        pendingValidation: null,
        mode: { mode: "disarmed", expires: null, writable: false },
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
        programStatus: statusMapFromProblems(snap.meta?.program_problems),
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

  sites: [],
  async loadSites() {
    try {
      const res = await api.sites();
      if (res.ok) set({ sites: res.sites ?? [] });
    } catch {
      /* offline / daemon down: leave the list as-is */
    }
  },
  async connectToSite(site) {
    const pbx = site.pbx ?? {};
    set((st) => ({
      form: {
        ...st.form,
        ip: pbx.host ?? "",
        community: pbx.community || "communityName",
        port: pbx.port ?? 161,
        reach: pbx.via === "overlay" ? "remote" : "direct",
        site: site.name ?? "",
        site_id: site.id ?? "",
      },
    }));
    await get().connect();
  },
  async addSite(site) {
    try {
      const res = await api.upsertSite(site);
      await get().loadSites();
      return res.ok;
    } catch {
      return false;
    }
  },
  async renameSite(id, name) {
    try {
      await api.renameSite(id, { name });
    } catch {
      /* ignore */
    }
    await get().loadSites();
  },
  async deleteSite(id) {
    try {
      await api.deleteSite(id);
    } catch {
      /* ignore */
    }
    await get().loadSites();
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
          message: job.message || "Snapshot complete.",
          jobId: job.id,
          detail: job.detail ?? null,
        },
      });
      void get().refreshSessionIndex();
      // The successful connect upserted a saved site server-side; pick it up so
      // it shows as a reconnect card next time the drawer opens.
      void get().loadSites();
    } else if (job.status === "error") {
      set({
        progress: {
          status: "error",
          done: job.done,
          total: job.total,
          message: job.error ?? "Snapshot failed.",
          jobId: job.id,
          error: job.error,
          detail: job.detail ?? null,
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
          detail: job.detail ?? null,
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
        programStatus: snap.program_status ?? get().programStatus,
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
  programStatus: {},
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
          set((s) => ({
            programViews: { ...s.programViews, [key]: res.program! },
            programStatus: res.status
              ? { ...s.programStatus, [key]: res.status }
              : s.programStatus,
          }));
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
          programStatus: res.status
            ? { ...s.programStatus, [key]: res.status }
            : s.programStatus,
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

  pending: [],
  pendingFieldCount: 0,
  pendingValidation: null,
  mode: { mode: "disarmed", expires: null, writable: false },
  railOpen: true,
  reviewOpen: false,
  async refreshPending() {
    const { sessionId } = get();
    if (!sessionId) {
      set({ pending: [], pendingFieldCount: 0, pendingValidation: null });
      return;
    }
    try {
      const res = await api.getPending(sessionId);
      if (res.ok) {
        set({
          pending: res.groups,
          pendingFieldCount: res.field_count,
          pendingValidation: res.validation,
        });
      }
    } catch {
      /* transient */
    }
  },
  async stageRowChanges(programKey, index, changes, originals) {
    const { sessionId } = get();
    if (!sessionId || Object.keys(changes).length === 0) return;
    try {
      const res = await api.stagePending(sessionId, {
        program: programKey,
        index,
        changes,
        originals,
      });
      if (res.ok) {
        set({
          pending: res.groups,
          pendingFieldCount: res.field_count,
          pendingValidation: res.validation,
          railOpen: true,
        });
      }
    } catch {
      /* transient */
    }
  },
  async clearPending(loc) {
    const { sessionId } = get();
    if (!sessionId) return;
    try {
      await api.clearPending(sessionId, loc);
    } catch {
      /* ignore */
    }
    await get().refreshPending();
  },
  async bulkEdit(body) {
    const { sessionId } = get();
    if (!sessionId) return;
    try {
      await api.bulkEdit(sessionId, body);
    } catch {
      /* ignore */
    }
    await get().refreshPending();
  },
  async setMode(mode) {
    const { sessionId } = get();
    if (!sessionId) return;
    try {
      const res = await api.setMode(sessionId, mode);
      if (res.ok && res.mode) set({ mode: res.mode });
    } catch {
      /* transient */
    }
  },
  setRailOpen: (railOpen) => set({ railOpen }),
  openReview: () => set({ reviewOpen: true }),
  closeReview: () => set({ reviewOpen: false }),

  vmStatus: null,
  vmBusy: false,
  async refreshVmStatus() {
    try {
      const res = await api.vm.status();
      if (res.ok) set({ vmStatus: res.status });
    } catch {
      /* transient */
    }
  },
  async vmConnect(spec) {
    set({ vmBusy: true });
    try {
      const res = await api.vm.connect(spec);
      if (res.ok && res.status) {
        set({ vmStatus: res.status });
        return null;
      }
      return res.error ?? "Connect failed.";
    } catch (e) {
      return (e as Error).message;
    } finally {
      set({ vmBusy: false });
    }
  },
  async vmDisconnect() {
    try {
      await api.vm.disconnect();
    } catch {
      /* ignore */
    }
    await get().refreshVmStatus();
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
  openBackups() {
    const { tabs } = get();
    const id = "backups";
    if (!tabs.some((t) => t.id === id)) {
      set({ tabs: [...tabs, { id, kind: "backups", title: "Backups" }] });
    }
    set({ activeTabId: id });
  },
  openProblems() {
    const { tabs } = get();
    const id = "problems";
    if (!tabs.some((t) => t.id === id)) {
      set({ tabs: [...tabs, { id, kind: "problems", title: "Problems" }] });
    }
    set({ activeTabId: id });
  },
  openCallFlow() {
    const { tabs } = get();
    const id = "callflow";
    if (!tabs.some((t) => t.id === id)) {
      set({ tabs: [...tabs, { id, kind: "callflow", title: "Call flow" }] });
    }
    set({ activeTabId: id });
  },
  openHelp() {
    const { tabs } = get();
    const id = "help";
    if (!tabs.some((t) => t.id === id)) {
      set({ tabs: [...tabs, { id, kind: "help", title: "Help" }] });
    }
    set({ activeTabId: id });
  },
  openVm(screen, title) {
    const id = `vm:${screen}`;
    const { tabs } = get();
    if (!tabs.some((t) => t.id === id)) {
      set({ tabs: [...tabs, { id, kind: "vm", vmScreen: screen, title }] });
    }
    set({ activeTabId: id });
    void get().refreshVmStatus();
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

  fileMode: null,
  siteId() {
    const { form, snapshotMeta } = get();
    if (form.site_id) return form.site_id;
    const site = snapshotMeta?.site;
    if (site) return String(site).toLowerCase().replace(/[^a-z0-9._-]+/g, "-");
    return "";
  },
  async enterFileMode(siteId, header) {
    try {
      const res = await api.snapshotFull(siteId, header.sid);
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
        programViews: views,
        readKeys: new Set(Object.keys(views)),
        rowCounts,
        programStatus: statusMapFromProblems(snap.meta?.program_problems),
        identity: snap.identity ?? null,
        snapshotMeta: snap.meta ?? null,
        fileMode: {
          siteId,
          sid: header.sid,
          label: header.name || header.label || header.kind,
          savedAt: header.saved_at,
          swid: header.swid ?? snap.identity?.swid ?? null,
        },
      });
      return true;
    } catch {
      return false;
    }
  },
  exitFileMode() {
    const { sessionId } = get();
    set({ fileMode: null });
    if (sessionId) {
      set({ coldStart: false, programViews: {}, loadingKeys: new Set() });
      void get().refreshSessionIndex();
    }
  },

  openAreas: {},
  toggleArea: (area) =>
    set((s) => ({ openAreas: { ...s.openAreas, [area]: !s.openAreas[area] } })),
  setArea: (area, open) =>
    set((s) => ({ openAreas: { ...s.openAreas, [area]: open } })),
  paletteOpen: false,
  setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
  theme: STORED_PREFS.theme ?? "system",
  setTheme: (theme) => {
    const { navMode, showProgramNumbers } = get();
    persistPrefs({ theme, navMode, showProgramNumbers });
    set({ theme });
  },

  navMode: STORED_PREFS.navMode === "emanager" ? "emanager" : "task",
  setNavMode: (navMode) => {
    const { theme, showProgramNumbers } = get();
    persistPrefs({ theme, navMode, showProgramNumbers });
    set({ navMode });
  },
  showProgramNumbers: STORED_PREFS.showProgramNumbers !== false,
  setShowProgramNumbers: (showProgramNumbers) => {
    const { theme, navMode } = get();
    persistPrefs({ theme, navMode, showProgramNumbers });
    set({ showProgramNumbers });
  },
  prefsOpen: false,
  setPrefsOpen: (prefsOpen) => set({ prefsOpen }),
  recordCrumb: null,
  setRecordCrumb: (recordCrumb) => set({ recordCrumb }),

  bridge: { active: false, component: null, systemName: null },
  bridgeSaving: false,
  bridgeSaveResult: null,
  async initBridge() {
    // On mount: re-establish the Save-to-cloud target if a context is still
    // active engine-side (survives a reload), then act on any pending deep link
    // exactly once. The SSE `deeplink` event handles links that arrive later.
    try {
      const res = await api.bridgeContext();
      if (res.ok && res.context?.active) {
        set({
          bridge: {
            active: true,
            component: res.context.component,
            systemName: res.context.system_name,
          },
        });
      }
    } catch {
      /* offline / daemon down */
    }
    await get().handleDeeplink();
  },
  async handleDeeplink() {
    let dl;
    try {
      const res = await api.deeplinkPending();
      dl = res.ok ? res.deeplink : null;
    } catch {
      return; // transient
    }
    if (!dl) return;
    set({
      bridge: {
        active: true,
        component: dl.component,
        systemName: dl.system_name,
      },
    });
    if (dl.error) {
      // The engine couldn't fetch the connection (Conduit down, token expired).
      // Keep the save target active and let the tech connect manually.
      set({
        connectDrawerOpen: true,
        progress: {
          status: "error",
          done: 0,
          total: 0,
          message: `Conduit: ${dl.error}`,
          jobId: null,
          error: dl.error,
        },
      });
      return;
    }
    const form = dl.form;
    if (form) {
      set((st) => ({
        form: {
          ...st.form,
          ip: form.ip,
          community: form.community || "communityName",
          port: form.port || 161,
          reach: form.reach,
          site: form.site,
        },
      }));
      if (form.ip.trim()) await get().connect();
      else set({ connectDrawerOpen: true });
    }
  },
  async saveToCloud() {
    const { bridge, bridgeSaving, fileMode } = get();
    if (!bridge.active || bridgeSaving) return;
    const siteId = get().siteId();
    if (!siteId) {
      set({
        bridgeSaveResult: { ok: false, text: "Connect to the CIX first." },
      });
      return;
    }
    set({ bridgeSaving: true, bridgeSaveResult: null });
    try {
      const res = await api.bridgeSave({
        site_id: siteId,
        snapshot: fileMode?.sid,
      });
      set({
        bridgeSaveResult: res.ok
          ? { ok: true, text: "Saved to Conduit." }
          : { ok: false, text: res.error ?? "Save failed." },
      });
    } catch (e) {
      set({ bridgeSaveResult: { ok: false, text: (e as Error).message } });
    } finally {
      set({ bridgeSaving: false });
    }
  },
  clearBridgeSaveResult: () => set({ bridgeSaveResult: null }),

  updateInfo: null,
  updateChecking: false,
  updateApplying: false,
  updateRelaunching: false,
  updateResult: null,
  updateDialogOpen: false,
  updateToastDismissed: false,
  async checkUpdate() {
    if (get().updateChecking) return;
    set({ updateChecking: true });
    try {
      const info = await api.checkUpdate();
      set({ updateInfo: info });
    } catch {
      // Offline, or the dev proxy / daemon is down: degrade silently. The
      // on-launch check must never block startup or surface a scary error.
    } finally {
      set({ updateChecking: false });
    }
  },
  async applyUpdate() {
    if (get().updateApplying) return;
    set({ updateApplying: true, updateResult: null });
    try {
      const res = await api.applyUpdate();
      set({ updateResult: res });
      // A successful self-replace finishes with an automatic relaunch — no
      // passive "restart to finish" step. The installer hand-off (.deb/.msi)
      // reports relaunch:false, because the OS installer runs and the user
      // reopens; relaunching then would kill the app mid-install.
      if (res.ok && res.relaunch) void get().relaunchApp();
    } catch (e) {
      set({ updateResult: { ok: false, error: (e as Error).message } });
    } finally {
      set({ updateApplying: false });
    }
  },
  async relaunchApp() {
    if (get().updateRelaunching) return;
    set({ updateRelaunching: true });
    try {
      const res = await api.updateRelaunch();
      // On ok the engine responds, then re-execs (web app) or exits for the
      // Tauri shell to restart it — this page is about to be replaced, so stay
      // in the "restarting" state. Only reset if the request itself was refused.
      if (!res.ok) set({ updateRelaunching: false });
    } catch {
      set({ updateRelaunching: false });
    }
  },
  setUpdateDialogOpen: (updateDialogOpen) => set({ updateDialogOpen }),
  dismissUpdateToast: () => set({ updateToastDismissed: true }),
}));
