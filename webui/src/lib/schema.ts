// The generated UI schema (toshiba_cix/data/ui_schema.json, served at
// /api/schema) is the single source of truth for labels, enum captions,
// display numbers, controls, the eManager menu tree, binary pairs and
// archetypes (DESIGN_PLAN 2.1). Engine and UI read the SAME file, so a program
// is rendered entirely from data — no hand-written form for any of the 186.

export type Control =
  | "readonly"
  | "text"
  | "number"
  | "select"
  | "segmented"
  | "port"
  | "password"
  | "ipaddress"
  | "radio"
  | "time"
  | "hidden"
  | "action";

export type Archetype = "form" | "grid_record" | "special" | "action";

export interface BinarySide {
  label: string;
  raw: number;
}

export interface SchemaField {
  name: string;
  title: string;
  display_no: string;
  col: number | null;
  oid: string;
  syntax: string;
  access: string; // "r" | "rw"
  control: Control;
  enum_values?: Record<string, string> | null;
  binary_pair?: { on: BinarySide; off: BinarySide } | null;
  is_binary_pair: boolean;
  is_enum: boolean;
  is_secret: boolean;
  key: boolean;
  primary: boolean;
  len: string | null;
  enc?: string;
  ui_type?: string;
  writable: boolean;
}

export interface SchemaProgram {
  catalog_key: string;
  program_number: string | null;
  program_name: string;
  menu_area: string;
  menu_path: string;
  label: string;
  title?: string;
  description?: string;
  archetype: Archetype;
  tier: number;
  danger: boolean;
  primary_fields: string[];
  key_fields?: string[];
  fields: SchemaField[];
  special_layout?: string | null;
  level0?: boolean;
  row_keyed?: boolean;
  group_oid?: string;
  field_count?: number;
  never_write?: boolean;
}

export interface MenuItem {
  title: string;
  menu_path: string;
  page_id?: string;
  programs: string[];
  level0: boolean;
}

export interface MenuArea {
  area: string;
  items: MenuItem[];
}

export interface UISchema {
  schema_version: string;
  catalog_version: string;
  counts: Record<string, number>;
  menu_area_order: string[];
  menu_tree: MenuArea[];
  programs: Record<string, SchemaProgram>;
  binary_pairs: Array<{ on: string; off: string }>;
  feature_keys: Array<{ code: string; name: string }>;
  actions: Array<{
    catalog_key: string;
    program_number: string | null;
    menu_area: string;
    title: string;
    danger: boolean;
  }>;
}

// ---- helpers --------------------------------------------------------------

export function fieldByName(
  prog: SchemaProgram | undefined,
  name: string,
): SchemaField | undefined {
  return prog?.fields.find((f) => f.name === name);
}

/** The visible caption for an enum raw value — the schema's title-cased
 *  caption ("DKT", "Enable"), falling back to the program_view display string
 *  or, last, the raw value. Never a bare OID. */
export function enumCaption(
  field: SchemaField | undefined,
  raw: unknown,
  fallback?: unknown,
): string {
  if (field?.enum_values && raw != null) {
    const cap = field.enum_values[String(raw)];
    if (cap) return cap;
  }
  if (fallback != null && fallback !== "") return String(fallback);
  return raw == null ? "" : String(raw);
}

/** All programs in eManager menu order (DESIGN_PLAN 3.2). */
export function programsInMenuOrder(schema: UISchema): SchemaProgram[] {
  const out: SchemaProgram[] = [];
  const seen = new Set<string>();
  for (const area of schema.menu_tree) {
    for (const item of area.items) {
      for (const key of item.programs) {
        if (!seen.has(key) && schema.programs[key]) {
          seen.add(key);
          out.push(schema.programs[key]);
        }
      }
    }
  }
  // any program not reachable from the tree (shouldn't happen) appended stably
  for (const key of Object.keys(schema.programs)) {
    if (!seen.has(key)) out.push(schema.programs[key]);
  }
  return out;
}
