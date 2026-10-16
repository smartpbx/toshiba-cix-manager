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
  program_problems?: ProgramStatus[];
}

// backup.collect_program status: how one program's read ended. "ok"/"empty"
// are a clean finish; "timeout"/"capped" are a bounded partial read of a slow
// or oversized subtree; "error" is a transport fault. The UI renders each
// distinctly instead of the old ambiguous "no rows for this program".
export type ProgramOutcome = "ok" | "empty" | "timeout" | "capped" | "error";

export interface ProgramStatus {
  key: string;
  number: string | null;
  name: string;
  oids: number | null;
  rounds?: number | null;
  elapsed?: number | null;
  outcome: ProgramOutcome;
  error?: string | null;
}

// job.progress `detail`: the granular, per-program progress the snapshot read
// streams (current program, its index, cumulative OIDs) — not just "28/186".
export interface ProgressDetail {
  phase?: string;
  program?: string | null;
  program_key?: string;
  program_name?: string;
  index?: number;
  rest_total?: number;
  oids?: number;
  problems?: number;
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
  detail?: ProgressDetail | null;
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
  program_status?: Record<string, ProgramStatus>;
  program_problems?: ProgramStatus[];
}

export interface ProgramResult {
  ok: boolean;
  program?: ProgramView;
  source?: "snapshot" | "live" | "unread";
  status?: ProgramStatus | null;
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

// ---- Voice Mail (Stratagy LVMU) leg — DESIGN_PLAN §8 ----------------------
export interface VmStatus {
  connected: boolean;
  transport: string;
  port: string;
  firmware: string;
  admin_box: string;
  log_name: string;
  trace_frames: number;
  shutdown?: string | null;
  writes_enabled: boolean;
}

export interface VmBoxRow {
  box: string;
  name: string;
  reserved: boolean;
}

export interface VmMailbox {
  box: string;
  name: string;
  extension: string;
  comment: string;
  security_code: string;
  created: string | null;
  modified: string | null;
  record_len: number;
  unproven: string[];
  error?: string;
}

export interface VmEditorField {
  name: string;
  tab: string;
  label: string;
  tooltip?: string;
  type: string;
  status: "confirmed" | "inferred" | "unknown";
  dot: "green" | "amber" | "grey";
  writable: boolean;
  range?: string;
  enum?: string[];
  lock?: boolean;
  wire?: string;
}

export interface VmEditorModel {
  tabs: Array<{ tab: string; fields: VmEditorField[] }>;
  writes_enabled: boolean;
  values: Record<string, unknown>;
  meta?: Record<string, unknown>;
}

export interface VmBoxDetail {
  ok: boolean;
  mailbox: VmMailbox;
  editor: VmEditorModel;
  reserved: boolean;
}

export interface VmSysParam {
  name: string;
  value: string;
  raw_value: string;
  enabled: boolean;
  group: string;
  description: string;
  possible: string;
  default: string;
  decoded?: string | null;
}

export interface VmFinding {
  severity: string;
  param: string;
  message: string;
}

export interface VmSysParams {
  params: VmSysParam[];
  groups: string[];
  findings: VmFinding[];
  help_status: string;
}

export interface VmDialCode {
  code: string;
  value: string;
  label: string;
}

export interface VmCompare {
  available: boolean;
  reason?: string;
  model?: string;
  default_name?: string;
  clean?: boolean;
  dial_codes: Array<{ code: string; kind: string; default: string | null; live: string | null; label?: string }>;
  integration: Array<{ pattern: string; kind: string }>;
}

export interface VmPbxDb {
  pbx_name: string;
  model: string;
  dial_codes: VmDialCode[];
  integration: Array<{ index: string; pattern: string }>;
  compare?: VmCompare;
}

export interface VmReportTemplate {
  id: string;
  name: string;
  columns: string[];
}

export interface VmReport {
  template: string;
  columns: Array<{ name: string; label: string }>;
  rows: string[][];
  row_count: number;
}

export interface VmBoxDiff {
  changes: Array<{ field: string; old: unknown; new: unknown; sensitive: boolean }>;
  raw: Record<string, { bytes_differ: number; offsets: number[]; len_a: number; len_b: number }>;
  changed: boolean;
}

export interface VmDiff {
  added: string[];
  removed: string[];
  boxes: Record<string, VmBoxDiff>;
  sysparams: Array<{ name: string; old: unknown; new: unknown }>;
  summary: {
    boxes_added: number;
    boxes_removed: number;
    boxes_changed: number;
    sysparams_changed: number;
  };
}

export interface VmPlan {
  box: string;
  mode: string;
  writes_enabled: boolean;
  planned: Array<Record<string, unknown>>;
  refused: Array<{ field: string; reason: string }>;
  apply_allowed: boolean;
  reason: string;
}

// ---- P2 write path (pending tray · three-way review · Simulate) -----------
export interface PendingOp {
  field: string;
  label: string;
  new_value: string;
  old_value: string | null;
  target_oid: string | null;
  program: string | null;
  column: number | null;
  ber_type: string;
  sendable: boolean;
  note: string;
  native_wire: string | null;
  wire_proven: boolean;
  op_class: string;
  row_create: boolean;
}

export interface PendingGroup {
  program_key: string;
  program_number: string | null;
  menu_path: string | null;
  label: string;
  index: string;
  row_key: string;
  ops: PendingOp[];
}

export interface Finding {
  level: string;
  severity: "error" | "warn";
  field: string;
  oid: string | null;
  message: string;
}

export interface Validation {
  findings: Finding[];
  errors: Finding[];
  warnings: Finding[];
  error_count: number;
  warn_count: number;
  by_field: Record<string, Finding[]>;
}

export interface PendingResult {
  ok: boolean;
  groups: PendingGroup[];
  field_count: number;
  row_count: number;
  validation: Validation;
}

export interface ModeState {
  session?: string;
  mode: "disarmed" | "armed" | "simulate";
  expires: number | null;
  writable: boolean;
}

export interface ReviewRow {
  field: string;
  label: string;
  display_no: string | null;
  program: string | null;
  op_class: string;
  base: string | null;
  live: string | null;
  proposed: string;
  wire: string;
  native_wire: string | null;
  wire_proven: boolean;
  proof: string;
  sendable: boolean;
  note: string;
  conflict: { base: string | null; live: string | null; proposed: string } | null;
  blast: { affects: number | null; note: string };
  excluded: boolean;
  exclude_reason: string;
}

export interface ReviewResult {
  rows: ReviewRow[];
  summary: {
    will_send: number;
    skip_conflict: number;
    skip_unproven_wire: number;
    read_only: number;
    total: number;
    programs: string[];
    affects_line: string;
  };
  conflicts: Array<{ field: string; oid: string; base: string | null; live: string | null; proposed: string }>;
  exclusions: Array<{ field: string; reason: string }>;
  tier: number;
  tier_reasons: string[];
  needs_typed_name: boolean;
  simulate: boolean;
  groups: PendingGroup[];
  validation: Validation;
  writes_enabled: boolean;
  mode: ModeState;
  live_error?: string;
}

export interface OpLogEntry {
  field: string;
  oid: string | null;
  wire: string;
  wire_proven: boolean;
  old_value: string | null;
  new_value: string;
  value_tlv_hex: string;
  note: string;
}

export interface OpLog {
  mode: string;
  would_send: number;
  entries: OpLogEntry[];
  commit: PendingOp | null;
  commit_value_tlv_hex: string | null;
  batch_set_pdu_hex: string | null;
  network: boolean;
  note: string;
}

// ---- P4: config linter / Problems panel ----------------------------------
export interface LintFinding {
  rule: string;
  severity: "error" | "warn" | "info";
  message: string;
  program: string | null;
  program_number: string | null;
  menu_path: string | null;
  index: string | null;
  row_key: string | null;
  field: string | null;
  value: string | null;
  fix: { program_key: string; index: string; changes: Record<string, string> } | null;
}

export interface LintResult {
  ok: boolean;
  findings: LintFinding[];
  counts: { error: number; warn: number; info: number };
  rule_count: number;
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
