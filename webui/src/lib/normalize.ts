import type { BackupDoc, BackupProgram, BackupRow, RawCell } from "./types";

// eManager menu areas, verbatim and in eManager's order (DESIGN_PLAN §3.2).
export const MENU_AREAS = [
  "System",
  "Station",
  "Trunk",
  "IP-Telephony",
  "LCR/DR",
  "Strata Net",
  "Maintenance",
  "Alarm/Traffic",
  "Other",
] as const;
export type MenuArea = (typeof MENU_AREAS)[number];

// Fallback program-number -> menu-area map, built from the eManager tree in
// DESIGN_PLAN §3.2. Used ONLY when the (concurrent) enriched API does not
// carry `menu_area`. Programs not listed fall through to "Other".
const MENU_BY_NUMBER: Record<string, MenuArea> = {};
function assign(area: MenuArea, numbers: string[]) {
  for (const n of numbers) MENU_BY_NUMBER[n] = area;
}
assign("System", [
  "100", "102", "117", "103", "104", "105", "500", "504", "501", "902", "527",
  "106", "112", "113", "515", "121", "107", "108", "114", "110", "109", "801",
  "803", "804", "512", "513", "514", "115", "579", "580", "120", "118", "119", "116",
]);
assign("Station", [
  "200", "204", "205", "208", "213", "214", "215", "216", "260", "250", "206",
  "540", "541", "209", "218", "502", "503", "400", "210", "517", "518", "519",
  "577", "404", "516", "507", "508", "573", "576", "202", "217", "201", "203",
]);
assign("Trunk", [
  "304", "305", "306", "307", "300", "301", "308", "310", "313", "309", "312",
  "318", "311", "319", "315", "317", "303", "302", "323", "324", "320", "316",
  "321", "322", "550", "650", "325",
]);
assign("IP-Telephony", [
  "150", "151", "153", "152", "161", "163", "326", "327", "328", "329", "165", "166",
]);
assign("LCR/DR", [
  "520", "521", "522", "524", "525", "526", "523", "528", "529", "530", "531",
  "111", "532", "533", "534", "535", "506", "570", "571", "509", "510",
]);
assign("Strata Net", [
  "661", "656", "670", "674", "651", "653", "654", "655", "657", "658", "659",
  "660", "551", "219", "671", "672", "673",
]);
assign("Maintenance", [
  "916", "909", "908", "900", "901", "915", "903", "904", "905", "906", "907",
]);
assign("Alarm/Traffic", ["919", "920", "921", "922"]);

export function menuAreaFor(prog: BackupProgram): MenuArea {
  const enriched = prog.menu_area as MenuArea | undefined;
  if (enriched && (MENU_AREAS as readonly string[]).includes(enriched)) return enriched;
  const num = prog.program_number ?? prog.number ?? undefined;
  if (num && MENU_BY_NUMBER[num]) return MENU_BY_NUMBER[num];
  return "Other";
}

// camelCase OID name -> readable label (fallback only; a native title/field_name
// from the enriched API always wins).
export function humanizeFieldName(name: string): string {
  const spaced = name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

function cellValue(cell: RawCell): string {
  if (cell === null || cell === undefined) return "";
  if (typeof cell === "object") {
    const dv = cell.display_value ?? cell.raw_value;
    return dv === null || dv === undefined ? "" : String(dv);
  }
  return String(cell);
}

export interface NormalizedColumn {
  fieldName: string;
  label: string;
}

export interface NormalizedRow {
  index: string;
  key: string;
  cells: Record<string, string>;
}

export interface NormalizedProgram {
  catalogKey: string;
  number: string;
  name: string;
  menuArea: MenuArea;
  columns: NormalizedColumn[];
  rows: NormalizedRow[];
  rowCount: number;
}

// Turn one program bucket into columns + string cells, GENERICALLY — never a
// bare OID. Handles both the current `fields: {name: value}` shape and the
// enriched `fields: {name: {field_name, display_value, ...}}` / `cells: [...]`.
export function normalizeProgram(
  catalogKey: string,
  prog: BackupProgram,
): NormalizedProgram {
  const colOrder: string[] = [];
  const colLabels: Record<string, string> = {};
  const seen = new Set<string>();

  const addCol = (fieldName: string, label?: string) => {
    if (!seen.has(fieldName)) {
      seen.add(fieldName);
      colOrder.push(fieldName);
    }
    if (label && !colLabels[fieldName]) colLabels[fieldName] = label;
  };

  const rows: NormalizedRow[] = (prog.rows || []).map((row: BackupRow) => {
    const cells: Record<string, string> = {};
    if (Array.isArray(row.cells)) {
      for (const c of row.cells) {
        const fn = c.field_name;
        if (!fn) continue;
        addCol(fn, fn);
        cells[fn] = cellValue(c);
      }
    } else if (row.fields) {
      for (const [fn, raw] of Object.entries(row.fields)) {
        const label =
          typeof raw === "object" && raw && raw.field_name ? raw.field_name : fn;
        addCol(fn, label);
        cells[fn] = cellValue(raw);
      }
    }
    return { index: row.index, key: row.key ?? row.index, cells };
  });

  const columns: NormalizedColumn[] = colOrder.map((fieldName) => ({
    fieldName,
    label: colLabels[fieldName] || humanizeFieldName(fieldName),
  }));

  return {
    catalogKey,
    number: prog.program_number ?? prog.number ?? "—",
    name: prog.program_name ?? prog.name ?? catalogKey,
    menuArea: menuAreaFor(prog),
    columns,
    rows,
    rowCount: rows.length,
  };
}

export interface MenuGroup {
  area: MenuArea;
  programs: NormalizedProgram[];
}

// Group every program in a backup by menu area, in eManager's order.
export function programsByMenuArea(backup: BackupDoc | null): MenuGroup[] {
  const groups = new Map<MenuArea, NormalizedProgram[]>();
  const progs = backup?.programs ?? {};
  for (const [key, bucket] of Object.entries(progs)) {
    const np = normalizeProgram(key, bucket);
    const list = groups.get(np.menuArea) ?? [];
    list.push(np);
    groups.set(np.menuArea, list);
  }
  const ordered: MenuGroup[] = [];
  for (const area of MENU_AREAS) {
    const list = groups.get(area);
    if (list && list.length) {
      list.sort((a, b) => a.number.localeCompare(b.number, undefined, { numeric: true }));
      ordered.push({ area, programs: list });
    }
  }
  return ordered;
}
