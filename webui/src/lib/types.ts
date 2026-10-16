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
  // v2 timeline fields
  name?: string | null;
  tags?: string[];
  note?: string | null;
  scope?: unknown;
  swid?: string | null;
  content_hash?: string | null;
  dedupe_of?: string | null;
  bytes?: number;
  redacted?: boolean;
}

// index.py value-search result (palette + where-used)
export interface Occurrence {
  program: string | null;
  program_number: string | null;
  index: string | null;
  row_key: string | null;
  field: string;
  display_no: string;
  menu_path: string | null;
  value: string;
  ref_kind: string | null;
}

export interface FindResult {
  ok: boolean;
  query: string;
  count: number;
  groups?: Array<{
    program: string;
    program_number: string | null;
    menu_path: string | null;
    occurrences: Occurrence[];
  }>;
  occurrences?: Occurrence[]; // when ?refs=1
}

// diff_view.py annotated diff (what the diff pane renders)
export interface DiffLine {
  kind:
    | "field_changed"
    | "field_added"
    | "field_removed"
    | "row_added"
    | "row_removed";
  program: string;
  index: string | null;
  row_key: string | null;
  field?: string;
  display_no?: string;
  title?: string;
  sensitive?: boolean;
  old_display?: string;
  new_display?: string;
  fields?: Array<{ field: string; display: string; sensitive: boolean }>;
  attribution?: { by?: string; at?: string; changeset?: string; outside?: boolean };
}

export interface DiffGroup {
  program: string;
  number: string | null;
  name: string | null;
  menu_area: string | null;
  menu_path: string | null;
  label: string;
  rows_changed: number;
  fields_changed: number;
  lines: DiffLine[];
}

export interface DiffSummary {
  programs_added: number;
  programs_removed: number;
  rows_added: number;
  rows_removed: number;
  fields_changed: number;
  fields_added: number;
  fields_removed: number;
  ignored_readonly: number;
  volatile_hidden: number;
}

export interface AnnotatedDiff {
  a_meta: SnapshotMeta;
  b_meta: SnapshotMeta;
  summary: DiffSummary;
  match_rows_on: string;
  excluded_programs: string[];
  excluded_fields: string[];
  programs_added: string[];
  programs_removed: string[];
  groups: DiffGroup[];
}

export interface AnnotatedDiffResult {
  ok: boolean;
  summary?: DiffSummary;
  annotated?: AnnotatedDiff;
  error?: string;
}

export interface FullSnapshot {
  sid: string;
  site_id: string;
  saved_at: string;
  label?: string | null;
  kind?: string;
  pinned?: boolean;
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
