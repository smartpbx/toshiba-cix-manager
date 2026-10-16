import { create } from "zustand";
import type {
  BackupDoc,
  CatalogInfo,
  ConnectionForm,
  ReadDoc,
} from "@/lib/types";

export type ViewId =
  | "connect"
  | "overview"
  | "stations"
  | "equipment"
  | "system"
  | "network"
  | "programs"
  | "backup"
  | "export";

export type ConnState = "idle" | "testing" | "ok" | "reading" | "error";
type Theme = "system" | "light" | "dark";

interface Identity {
  software_id?: string;
  chassis_mac?: string;
  latency_ms?: number;
}

interface AppState {
  // connection slice
  form: ConnectionForm;
  setForm: (patch: Partial<ConnectionForm>) => void;
  connState: ConnState;
  setConnState: (s: ConnState) => void;
  identity: Identity | null;
  setIdentity: (i: Identity | null) => void;

  // doc slice (the live read snapshot)
  doc: ReadDoc | null;
  report: string;
  setDoc: (doc: ReadDoc | null, report?: string) => void;

  // backup slice (catalog-driven, for the Programs browser + diff)
  backupA: BackupDoc | null;
  backupB: BackupDoc | null;
  setBackupA: (b: BackupDoc | null) => void;
  setBackupB: (b: BackupDoc | null) => void;

  // catalog slice
  catalog: CatalogInfo | null;
  setCatalog: (c: CatalogInfo | null) => void;
  version: string;
  writesEnabled: boolean;
  setRuntime: (v: { version?: string; writesEnabled?: boolean }) => void;

  // ui slice
  view: ViewId;
  setView: (v: ViewId) => void;
  stationFilter: string;
  setStationFilter: (q: string) => void;
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

export const useStore = create<AppState>((set) => ({
  form: {
    ip: "",
    community: "communityName",
    port: 161,
    scope: "core",
    reach: "direct",
  },
  setForm: (patch) => set((s) => ({ form: { ...s.form, ...patch } })),
  connState: "idle",
  setConnState: (connState) => set({ connState }),
  identity: null,
  setIdentity: (identity) => set({ identity }),

  doc: null,
  report: "",
  setDoc: (doc, report) => set({ doc, report: report ?? "" }),

  backupA: null,
  backupB: null,
  setBackupA: (backupA) => set({ backupA }),
  setBackupB: (backupB) => set({ backupB }),

  catalog: null,
  setCatalog: (catalog) => set({ catalog }),
  version: "",
  writesEnabled: false,
  setRuntime: ({ version, writesEnabled }) =>
    set((s) => ({
      version: version ?? s.version,
      writesEnabled: writesEnabled ?? s.writesEnabled,
    })),

  view: "connect",
  setView: (view) => set({ view }),
  stationFilter: "",
  setStationFilter: (stationFilter) => set({ stationFilter }),
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
