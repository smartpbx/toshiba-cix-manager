// Shapes returned by the Python engine (toshiba_cix/webapp.py). These mirror
// the live API; where the concurrent backend enrichment adds fields we keep
// them optional and degrade gracefully (see normalize.ts).

export interface Health {
  ok: boolean;
  version?: string;
  writes_enabled?: boolean;
}

export interface CatalogInfo {
  ok: boolean;
  writes_enabled?: boolean;
  catalog_version?: string;
  programs?: number;
  fields?: number;
  writable?: number;
}

export interface ConnectResult {
  ok: boolean;
  software_id?: string;
  chassis_mac?: string;
  error?: string;
}

export interface DiscoverCandidate {
  ip: string;
  mac?: string;
  software_id?: string;
}
export interface DiscoverResult {
  ok: boolean;
  candidates?: DiscoverCandidate[];
  error?: string;
}

export interface SecurityFinding {
  severity: "high" | "medium" | "low" | string;
  code: string;
  detail: string;
}

export interface StationKey {
  key: number;
  [col: string]: unknown;
}

export interface Station {
  dn: string;
  extension: string | null;
  equipment_port: string | null;
  type: string | null;
  name: string | null;
  flags: Record<string, unknown>;
  keys: StationKey[];
  programs: Record<string, unknown>;
  source_oids: Record<string, string>;
}

export interface ReadDoc {
  system: Record<string, unknown> & {
    software_id?: string;
    chassis_mac?: string;
    status?: Record<string, unknown>;
    numbering_config?: Record<string, unknown>;
  };
  equipment: Array<Record<string, unknown>>;
  stations: Station[];
  network_access: Array<Record<string, unknown>>;
  raw_programs: Record<string, { name: string; rows: Record<string, unknown> }>;
  raw_unknown?: Array<{ oid: string; value: unknown }>;
  stats: {
    stations?: number;
    equipment_rows?: number;
    network_access_rows?: number;
    raw_program_count?: number;
    raw_unknown_count?: number;
  };
  device: {
    ip?: string;
    port?: number;
    community?: string;
    read_at?: string;
    oids_read?: number;
    scope?: string;
    walk_error?: string | null;
  };
  security_findings?: SecurityFinding[];
  raw_oid_walk?: Array<{ oid: string; value: unknown }>;
  program_views?: ProgramViews;
}

export interface ReadResult {
  ok: boolean;
  doc?: ReadDoc;
  report?: string;
  error?: string;
}

// ---- Catalog backup (POST /api/catalog-backup) ----------------------------
// A cell is either a bare decoded value (current engine) OR the enriched
// object the concurrent backend agent is adding. normalize.ts handles both.
export type RawCell =
  | string
  | number
  | boolean
  | null
  | {
      col?: number | string;
      field_name?: string;
      oid?: string;
      raw_value?: unknown;
      display_value?: unknown;
    };

export interface BackupRow {
  index: string;
  key?: string;
  // current engine: {fieldName: value}; enriched: {fieldName: {display_value,...}}
  fields?: Record<string, RawCell>;
  // possible enriched alternative: an ordered cell array
  cells?: Array<{
    col?: number | string;
    field_name: string;
    oid?: string;
    raw_value?: unknown;
    display_value?: unknown;
  }>;
}

export interface BackupProgram {
  number?: string | null;
  name?: string;
  group_oid?: string;
  rows: BackupRow[];
  // enriched, optional:
  catalog_key?: string;
  program_number?: string;
  program_name?: string;
  menu_area?: string;
}

// ---- Enriched program views (enrich.py: build_program_views) --------------
// The catalog-driven contract the engine emits on /api/read (inside doc),
// /api/catalog-backup and /api/view. `programs` is an ARRAY keyed by
// catalog_key; each program carries named, enum-resolved per-cell rows. This is
// what the Programs browser renders so nothing shows as a bare OID.
export interface MenuAreaSummary {
  area: string;
  programs: string[];
  row_count: number;
  cell_count: number;
}
export interface FeatureView {
  key: string;
  title: string;
  programs: string[];
  present: boolean;
}
export interface ProgramViews {
  programs: BackupProgram[];
  menu_areas: MenuAreaSummary[];
  feature_views: FeatureView[];
  uncataloged: Array<{ oid: string; raw_value?: unknown; value?: unknown }>;
  stats: Record<string, number>;
}

export interface BackupDoc {
  format?: string;
  format_version?: number;
  meta?: Record<string, unknown> & {
    swid?: string;
    chassis_mac?: string;
    site?: string | null;
    read_at?: string;
    catalog_version?: string;
    source_ip?: string;
    scope?: unknown;
    oids_read?: number;
    programs_count?: number;
    rows_count?: number;
  };
  programs?: Record<string, BackupProgram>;
  unmatched?: Array<{ oid: string; value: unknown }>;
}

export interface BackupResult {
  ok: boolean;
  backup?: BackupDoc;
  program_views?: ProgramViews;
  report?: string;
  error?: string;
}

export interface DiffResult {
  ok: boolean;
  diff?: unknown;
  report?: string;
  error?: string;
}

export type ReachMode = "direct" | "remote";
export type ReadScope = "core" | "all";

export interface ConnectionForm {
  ip: string;
  community: string;
  port: number;
  scope: ReadScope;
  reach: ReachMode;
}
