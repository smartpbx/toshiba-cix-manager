import * as React from "react";
import { cn } from "@/lib/utils";
import {
  enumCaption,
  fieldByName,
  type SchemaField,
  type SchemaProgram,
} from "@/lib/schema";
import type { Cell, ProgramView, Row } from "@/lib/types";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";
import { GridRecord } from "./GridRecord";

// The five special program pages (DESIGN_PLAN §3.3) are hand-built but data-fed.
// P1 ships the read-only four: Card Assignment slot grid (+ cabinets), the Class
// of Service matrix, and the Station key strip (view). The remaining two
// (group matrix, PRI B-channels) become editable in P2 and fall back to the
// generic Grid + Record until then.
export function SpecialLayout({
  program,
  view,
}: {
  program: SchemaProgram;
  view: ProgramView;
}) {
  switch (program.special_layout) {
    case "card_slot_grid":
      return <CardSlotGrid program={program} view={view} />;
    case "cos_matrix":
      return <CosMatrix program={program} view={view} />;
    case "station_key_strip":
      return <StationKeyStrip program={program} view={view} />;
    default:
      return <GridRecord program={program} view={view} />;
  }
}

function cellMap(row: Row): Record<string, Cell> {
  const m: Record<string, Cell> = {};
  for (const c of row.cells) m[c.field_name] = c;
  return m;
}

function cellText(field: SchemaField | undefined, cell: Cell | undefined): string {
  if (!cell) return "";
  if (field?.is_enum || field?.enum_values) {
    return enumCaption(field, cell.raw_value, cell.display_value);
  }
  return cell.display_value ?? "";
}

// --------------------------------------------------------------------------
// Card Assignment — slot grid grouped into physical cabinets
// --------------------------------------------------------------------------
function parseEquip(key: string): { cabinet: string; slot: string } {
  const k = (key || "").trim();
  if (k.includes("-")) {
    const [cab, ...rest] = k.split("-");
    return { cabinet: cab, slot: rest.join("-") || k };
  }
  if (/^\d{3,}$/.test(k)) {
    return { cabinet: k.slice(0, k.length - 2), slot: k.slice(-2) };
  }
  return { cabinet: "1", slot: k || "—" };
}

function CardSlotGrid({ program, view }: { program: SchemaProgram; view: ProgramView }) {
  const typeField = fieldByName(program, "cardSlotCardType");
  const cabinets = React.useMemo(() => {
    const groups = new Map<string, Array<{ slot: string; type: string; equip: string }>>();
    for (const r of view.rows) {
      const m = cellMap(r);
      const equip = (m.cardSlotEquip?.display_value ?? r.key ?? r.index) || "";
      const { cabinet, slot } = parseEquip(equip);
      const type = cellText(typeField, m.cardSlotCardType);
      if (!groups.has(cabinet)) groups.set(cabinet, []);
      groups.get(cabinet)!.push({ slot, type, equip });
    }
    return [...groups.entries()]
      .sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))
      .map(([cabinet, slots]) => ({
        cabinet,
        slots: slots.sort((a, b) =>
          a.slot.localeCompare(b.slot, undefined, { numeric: true })),
      }));
  }, [view.rows, typeField]);

  return (
    <div className="h-full overflow-auto p-4">
      <p className="mb-3 text-xs text-fg-3">
        Card slots grouped by physical cabinet, from the live card-slot table.
        An empty slot shows no card type. Read-only.
      </p>
      <div className="space-y-4">
        {cabinets.map((cab) => (
          <div key={cab.cabinet} className="rounded-md border border-border bg-surface">
            <div className="border-b border-border bg-surface-2 px-3 py-1.5 text-sm font-semibold">
              Cabinet {cab.cabinet}
              <span className="ml-2 text-2xs font-normal text-fg-3">
                {cab.slots.filter((s) => s.type).length}/{cab.slots.length} slots fitted
              </span>
            </div>
            <div className="grid grid-cols-[repeat(auto-fill,minmax(120px,1fr))] gap-2 p-3">
              {cab.slots.map((s) => (
                <div
                  key={s.equip}
                  className={cn(
                    "rounded-md border px-2 py-1.5",
                    s.type
                      ? "border-border bg-surface-2"
                      : "border-dashed border-border/70 text-fg-3",
                  )}
                  title={s.equip}
                >
                  <div className="font-mono text-2xs text-fg-3">Slot {s.slot}</div>
                  <div className="truncate text-sm font-medium">
                    {s.type || "empty"}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
        {cabinets.length === 0 && (
          <div className="text-sm text-fg-2">No card slots in this snapshot.</div>
        )}
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------
// Class of Service — the 1–32 × options matrix (read-only)
// --------------------------------------------------------------------------
function CosMatrix({ program, view }: { program: SchemaProgram; view: ProgramView }) {
  const optionFields = React.useMemo(
    () => program.fields.filter((f) => !f.key && f.control !== "hidden"),
    [program.fields],
  );
  const rows = React.useMemo(
    () => [...view.rows].sort((a, b) =>
      (a.key || a.index).localeCompare(b.key || b.index, undefined, { numeric: true })),
    [view.rows],
  );

  function compact(field: SchemaField, cell: Cell | undefined): React.ReactNode {
    if (!cell) return <span className="text-fg-3">—</span>;
    if (field.binary_pair) {
      const on = cell.raw_value === field.binary_pair.on.raw;
      return (
        <span className={on ? "text-ok" : "text-fg-3"}
          title={on ? field.binary_pair.on.label : field.binary_pair.off.label}>
          {on ? "●" : "○"}
        </span>
      );
    }
    return <span title={cellText(field, cell)}>{cellText(field, cell) || "—"}</span>;
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="px-4 py-2 text-xs text-fg-3">
        {rows.length} classes × {optionFields.length} options. ● = on / allowed,
        ○ = off; hover any cell for its label. Read-only.
      </div>
      <div className="min-h-0 flex-1 overflow-auto px-4 pb-4">
        <table className="border-collapse text-sm">
          <thead>
            <tr>
              <th className="sticky left-0 z-20 border-b border-r border-line-strong bg-surface-2 px-2 py-1 text-left text-2xs font-semibold uppercase text-fg-2">
                COS
              </th>
              {optionFields.map((f) => (
                <th key={f.name}
                  className="border-b border-line-strong bg-surface-2 px-1 py-1 text-2xs font-semibold text-fg-2"
                  title={f.title}>
                  <span className="field-badge">{f.display_no}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const m = cellMap(r);
              return (
                <tr key={r.index} className="hover:bg-surface-2">
                  <td className="sticky left-0 z-10 border-b border-r border-border bg-surface px-2 py-1 font-mono font-medium">
                    {r.key || r.index}
                  </td>
                  {optionFields.map((f) => (
                    <td key={f.name} className="border-b border-border/60 px-1 py-1 text-center">
                      {compact(f, m[f.name])}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------
// Station Assignments — the drawn key strip (view)
// --------------------------------------------------------------------------
const KEY_PROGRAM = "205FeatureKey";

function StationKeyStrip({ program, view }: { program: SchemaProgram; view: ProgramView }) {
  const { schema, keyView, ensureProgram, featureKeys } = useStore(
    useShallow((s) => ({
      schema: s.schema,
      keyView: s.programViews[KEY_PROGRAM],
      ensureProgram: s.ensureProgram,
      featureKeys: s.schema?.feature_keys ?? [],
    })),
  );
  const [selected, setSelected] = React.useState<string | null>(null);
  const [filter, setFilter] = React.useState("");

  React.useEffect(() => {
    ensureProgram(KEY_PROGRAM);
  }, [ensureProgram]);

  const keyProgram = schema?.programs[KEY_PROGRAM];
  const featureLabel = React.useMemo(() => {
    const m = new Map<string, string>();
    for (const fk of featureKeys) m.set(fk.code, fk.name);
    return m;
  }, [featureKeys]);

  const nameField = fieldByName(program, "stationStationName");
  const typeField = fieldByName(program, "stationType");

  const stations = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    return view.rows
      .map((r) => {
        const m = cellMap(r);
        return {
          dn: r.key || r.index,
          name: cellText(nameField, m.stationStationName),
          type: cellText(typeField, m.stationType),
        };
      })
      .filter((s) => !q || s.dn.toLowerCase().includes(q) || s.name.toLowerCase().includes(q));
  }, [view.rows, filter, nameField, typeField]);

  // Keys for the selected DN, from program 205 (if read), by key number.
  const keys = React.useMemo(() => {
    if (!selected || !keyView || !keyProgram) return null;
    const out: Array<{ keyNo: string; code: string; label: string; params: string }> = [];
    for (const r of keyView.rows) {
      const m = cellMap(r);
      const dn = m.featureDn?.display_value ?? "";
      if (String(dn) !== String(selected)) continue;
      const code = m.featureCode?.display_value ?? "";
      const params = [1, 2, 3]
        .map((n) => m[`featureParameter${n}`]?.display_value ?? "")
        .filter(Boolean)
        .join(" ");
      out.push({
        keyNo: m.featureKeyNo?.display_value ?? "",
        code,
        label: featureLabel.get(code) || code || "—",
        params,
      });
    }
    return out.sort((a, b) =>
      a.keyNo.localeCompare(b.keyNo, undefined, { numeric: true }));
  }, [selected, keyView, keyProgram, featureLabel]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-3 px-4 py-2">
        <input
          placeholder="Filter DN / name…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="h-ctl max-w-xs rounded-md border border-border bg-surface px-2 text-sm"
        />
        <span className="text-xs text-fg-2 tnum">{stations.length} stations</span>
      </div>
      <div className="flex min-h-0 flex-1 gap-3 px-4 pb-4">
        <div className="w-60 shrink-0 overflow-auto rounded-md border border-border bg-surface">
          {stations.map((s) => (
            <button
              key={s.dn}
              onClick={() => setSelected(s.dn)}
              className={cn(
                "flex w-full items-center gap-2 border-b border-border/50 px-2 py-1.5 text-left text-sm",
                s.dn === selected ? "bg-accent-tint text-primary" : "hover:bg-surface-2",
              )}
            >
              <span className="font-mono">{s.dn}</span>
              <span className="min-w-0 flex-1 truncate text-fg-2">{s.name}</span>
              {s.type && <span className="text-2xs text-fg-3">{s.type}</span>}
            </button>
          ))}
        </div>
        <div className="min-w-0 flex-1 overflow-auto rounded-md border border-border bg-surface p-4">
          {!selected ? (
            <div className="flex h-full items-center justify-center text-sm text-fg-2">
              Pick a station to see its key strip.
            </div>
          ) : (
            <>
              <div className="mb-3 text-sm font-semibold">
                DN {selected} — key strip
              </div>
              {keys === null ? (
                <div className="text-sm text-fg-2">
                  Reading Flexible Buttons (205)…
                </div>
              ) : keys.length === 0 ? (
                <div className="text-sm text-fg-2">
                  No flexible buttons recorded for this DN in the snapshot. The
                  Prime DN key is {selected}.
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {keys.map((k) => (
                    <div
                      key={k.keyNo}
                      className="w-40 rounded-md border border-border bg-surface-2 px-2 py-1.5"
                      title={`${k.code} ${k.params}`.trim()}
                    >
                      <div className="font-mono text-2xs text-fg-3">Key {k.keyNo}</div>
                      <div className="truncate text-sm font-medium">{k.label}</div>
                      {k.params && (
                        <div className="truncate text-2xs text-fg-3">{k.params}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              <p className="mt-4 text-xs text-fg-3">
                Drawn from Station (200) + Flexible Buttons (205). Read-only; the
                editable strip with per-model key caps and Copy keys arrives with
                the write path.
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
