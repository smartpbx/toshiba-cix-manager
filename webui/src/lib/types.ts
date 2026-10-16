// Runtime shapes the Python engine returns for the P1 browse app. The static
// UI schema (labels / controls / menu tree) lives in schema.ts; these are the
// live/snapshot values that flow through it.

export interface Health {
  ok: boolean;
  version?: string;
  writes_enabled?: boolean;
  schema?: { schema_available?: boolean; catalog_version?: string };
}

// enrich.py per-cell contract: the five required keys + additive metadata.
export interface Cell {
  col: number | null;
  field_name: string;
  oid: string;
  raw_value: unknown;
  display_value: string;
  syntax?: string;
  access?: string;
  is_enum?: boolean;
  is_secret?: boolean;
}

export interface Row {
  index: string;
  key: string;
  cells: Cell[];
}

// enrich.py <program_view>: one program's rows plus its catalog metadata.
export interface ProgramView {
  catalog_key: string;
  program_number: string | null;
  program_name: string;
  menu_area: string;
  menu_path: string;
  label: string;
  group_oid?: string;
  row_count: number;
  rows: Row[];
}

export interface Identity {
  swid?: string | null;
  chassis_mac?: string | null;
  software_id?: string | null;
}

export interface SnapshotMeta {
  read_at?: string;
  catalog_version?: string;
  source_ip?: string | null;
  scope?: unknown;
  oids_read?: number;
  walk_error?: string | null;
  site?: string | null;
}

export interface SnapshotStart {
  ok: boolean;
  session?: string;
  site_id?: string;
  job?: string;
  error?: string;
}

export interface JobState {
  id: string;
  kind: string;
  status: "pending" | "running" | "done" | "error";
  done: number;
  total: number;
  message: string;
  error?: string | null;
  result?: unknown;
}

export interface SessionSnapshot {
  ok: boolean;
  identity?: Identity | null;
  meta?: SnapshotMeta;
  read_keys: string[];
  programs: Array<{
    catalog_key: string;
    program_number: string | null;
    menu_area: string;
    row_count: number;
  }>;
}

export interface ProgramResult {
  ok: boolean;
  program?: ProgramView;
  source?: "snapshot" | "live" | "unread";
  error?: string;
}

export interface SnapshotHeader {
  sid: string;
  site_id: string;
  saved_at: string;
  label: string | null;
  pinned: boolean;
  kind: string;
  identity?: Identity;
  counts?: Record<string, number | null>;
}

export interface FullSnapshot {
  sid: string;
  site_id: string;
  saved_at: string;
  identity?: Identity;
  meta?: SnapshotMeta;
  program_views: {
    programs: ProgramView[];
    menu_areas?: unknown[];
    stats?: Record<string, number>;
  };
}

export type Reach = "direct" | "remote";

export interface ConnectionForm {
  ip: string;
  community: string;
  port: number;
  reach: Reach;
  site: string;
  site_id: string;
}
