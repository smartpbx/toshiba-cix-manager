import * as React from "react";
import { RefreshCw, Search } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  enumCaption,
  fieldByName,
  type SchemaField,
  type SchemaProgram,
} from "@/lib/schema";
import type { Cell, Occurrence, ProgramView, Row } from "@/lib/types";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { RecordForm } from "@/components/program/RecordForm";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

const KEY_PROGRAM = "205FeatureKey";

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
function initials(name: string, dn: string): string {
  const toks = (name || "").split(/\s+/).filter((t) => /[a-z0-9]/i.test(t));
  if (toks.length === 0) return (dn || "?").slice(0, 2);
  return toks
    .slice(0, 2)
    .map((t) => t[0]!.toUpperCase())
    .join("");
}

interface Station {
  index: string;
  dn: string;
  name: string;
  type: string;
  equip: string;
  cos: string;
  row: Row;
}

// Stations (200) — the redesign's master-detail: a searchable list of stations,
// a detail pane with Basics + "Also appears in" + the phone-button strip (from
// 205), and a "Change…" that opens the existing RecordForm edit → stage →
// Review & Write flow. The write path is untouched.
export function StationsScreen({
  program,
  view,
}: {
  program: SchemaProgram;
  view: ProgramView;
}) {
  const {
    schema,
    keyView,
    ensureProgram,
    featureKeys,
    sessionId,
    fileMode,
    loading,
    refreshProgram,
    setRecordCrumb,
  } = useStore(
    useShallow((s) => ({
      schema: s.schema,
      keyView: s.programViews[KEY_PROGRAM],
      ensureProgram: s.ensureProgram,
      featureKeys: s.schema?.feature_keys ?? [],
      sessionId: s.sessionId,
      fileMode: s.fileMode,
      loading: s.loadingKeys.has(program.catalog_key),
      refreshProgram: s.refreshProgram,
      setRecordCrumb: s.setRecordCrumb,
    })),
  );

  const [filter, setFilter] = React.useState("");
  const [selectedIdx, setSelectedIdx] = React.useState<string | null>(null);
  const [changeOpen, setChangeOpen] = React.useState(false);

  React.useEffect(() => {
    ensureProgram(KEY_PROGRAM);
  }, [ensureProgram]);

  const nameField = fieldByName(program, "stationStationName");
  const typeField = fieldByName(program, "stationType");
  const equipField = fieldByName(program, "stationEquipment");
  const cosField = fieldByName(program, "stationCos");
  const keyProgram = schema?.programs[KEY_PROGRAM];

  const stations = React.useMemo<Station[]>(() => {
    return view.rows.map((r) => {
      const m = cellMap(r);
      const dn = r.key || r.index;
      return {
        index: r.index,
        dn,
        name: cellText(nameField, m.stationStationName) || `Station ${dn}`,
        type: cellText(typeField, m.stationType),
        equip: cellText(equipField, m.stationEquipment),
        cos: cellText(cosField, m.stationCos),
        row: r,
      };
    });
  }, [view.rows, nameField, typeField, equipField, cosField]);

  const filtered = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return stations;
    return stations.filter(
      (s) => s.dn.toLowerCase().includes(q) || s.name.toLowerCase().includes(q),
    );
  }, [stations, filter]);

  // Default-select the first station so the detail pane is populated.
  React.useEffect(() => {
    if (selectedIdx && stations.some((s) => s.index === selectedIdx)) return;
    setSelectedIdx(stations[0]?.index ?? null);
  }, [stations, selectedIdx]);

  const selected = stations.find((s) => s.index === selectedIdx) ?? null;

  // Feed the breadcrumb tail, and clear it when leaving the screen.
  React.useEffect(() => {
    setRecordCrumb(selected ? selected.name : null);
    return () => setRecordCrumb(null);
  }, [selected, setRecordCrumb]);

  const featureLabel = React.useMemo(() => {
    const m = new Map<string, string>();
    for (const fk of featureKeys) m.set(fk.code, fk.name);
    return m;
  }, [featureKeys]);

  // Phone buttons for the selected DN, from program 205.
  const keys = React.useMemo(() => {
    if (!selected || !keyView || !keyProgram) return null;
    const out: Array<{ keyNo: string; label: string; params: string; assigned: boolean }> = [];
    for (const r of keyView.rows) {
      const m = cellMap(r);
      const dn = m.featureDn?.display_value ?? "";
      if (String(dn) !== String(selected.dn)) continue;
      const code = String(m.featureCode?.display_value ?? "");
      const params = [1, 2, 3]
        .map((n) => m[`featureParameter${n}`]?.display_value ?? "")
        .filter(Boolean)
        .join(" ");
      out.push({
        keyNo: m.featureKeyNo?.display_value ?? "",
        label: featureLabel.get(code) || code || "—",
        params,
        assigned: !!code && code !== "000",
      });
    }
    return out.sort((a, b) => a.keyNo.localeCompare(b.keyNo, undefined, { numeric: true }));
  }, [selected, keyView, keyProgram, featureLabel]);

  // "Also appears in" — references elsewhere that point at the selected DN.
  const [occ, setOcc] = React.useState<Occurrence[]>([]);
  React.useEffect(() => {
    let live = true;
    setOcc([]);
    const dn = selected?.dn;
    if (!dn) return;
    const p = sessionId
      ? api.find(sessionId, dn, true)
      : fileMode
        ? api.snapshotFind(fileMode.siteId, fileMode.sid, dn, true)
        : null;
    if (!p) return;
    void p
      .then((res) => {
        if (live) setOcc(res.occurrences ?? []);
      })
      .catch(() => {
        if (live) setOcc([]);
      });
    return () => {
      live = false;
    };
  }, [selected?.dn, sessionId, fileMode]);

  const usedIn = React.useMemo(() => {
    const seen = new Set<string>();
    const out: Array<{ label: string; num: string | null }> = [];
    for (const o of occ) {
      const label = (o.menu_path?.split(" - ").pop() || o.program || "").trim();
      const key = `${label}-${o.program_number}-${o.row_key}`;
      if (!label || seen.has(key)) continue;
      seen.add(key);
      out.push({ label, num: o.program_number });
      if (out.length >= 10) break;
    }
    return out;
  }, [occ]);

  const basics: Array<{ title: string; value: string }> = selected
    ? [
        { title: nameField?.title ?? "Display name", value: selected.name },
        { title: typeField?.title ?? "Phone type", value: selected.type || "—" },
        { title: cosField?.title ?? "Class of service", value: selected.cos || "—" },
        { title: equipField?.title ?? "Equipment", value: selected.equip || "—" },
      ]
    : [];

  return (
    <div className="flex h-full min-h-0">
      {/* Master list */}
      <div className="flex w-[340px] shrink-0 flex-col border-r border-border">
        <div className="px-5 pb-3 pt-[18px]">
          <div className="flex items-baseline gap-2">
            <h1 className="text-[20px] font-semibold">Stations</h1>
            <span className="text-fg-3 tnum">{stations.length}</span>
            <span className="flex-1" />
            {sessionId && (
              <button
                onClick={() => refreshProgram(program.catalog_key)}
                disabled={loading}
                className="flex h-6 w-6 items-center justify-center rounded-md text-fg-3 hover:bg-surface-2 disabled:opacity-50"
                title="Re-read stations from the device (read-only)"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              </button>
            )}
            <span className="font-mono text-[11px] text-fg-3 tnum">prog 200</span>
          </div>
          <div className="mt-3 flex h-[34px] items-center gap-1.5 rounded-[9px] border border-border bg-surface px-2.5">
            <Search className="h-3.5 w-3.5 text-fg-3" />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Name or extension"
              className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-fg-3"
            />
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-auto px-2.5 pb-2.5">
          {filtered.map((s) => {
            const active = s.index === selectedIdx;
            return (
              <button
                key={s.index}
                onClick={() => setSelectedIdx(s.index)}
                className={cn(
                  "flex w-full items-center gap-3 rounded-[9px] px-2.5 py-[9px] text-left",
                  active ? "bg-accent-tint" : "hover:bg-surface-2",
                )}
              >
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-surface-3 text-xs font-semibold text-fg-2">
                  {initials(s.name, s.dn)}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{s.name}</span>
                  <span className="block truncate text-xs text-fg-3">
                    Ext <span className="font-mono tnum">{s.dn}</span>
                    {s.type ? ` · ${s.type}` : ""}
                  </span>
                </span>
              </button>
            );
          })}
          {filtered.length === 0 && (
            <div className="px-2.5 py-6 text-center text-sm text-fg-3">No stations match.</div>
          )}
        </div>
      </div>

      {/* Detail */}
      <div className="min-w-0 flex-1 overflow-auto px-8 py-6">
        {!selected ? (
          <div className="flex h-full items-center justify-center text-sm text-fg-2">
            Pick a station to see its details.
          </div>
        ) : (
          <>
            <div className="flex items-center gap-3.5">
              <span className="flex h-[52px] w-[52px] items-center justify-center rounded-full bg-accent-tint text-lg font-semibold text-primary">
                {initials(selected.name, selected.dn)}
              </span>
              <div className="min-w-0 flex-1">
                <h2 className="truncate text-[22px] font-semibold">{selected.name}</h2>
                <div className="mt-0.5 text-fg-2">
                  Extension <span className="font-mono tnum">{selected.dn}</span>
                  {selected.type ? ` · ${selected.type}` : ""}
                  {selected.equip ? (
                    <>
                      {" · port "}
                      <span className="font-mono tnum">{selected.equip}</span>
                    </>
                  ) : null}
                </div>
              </div>
              <button
                onClick={() => setChangeOpen(true)}
                className="h-[34px] rounded-[9px] border border-border bg-surface px-3.5 font-medium hover:bg-surface-2"
              >
                Change…
              </button>
            </div>

            <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
              <div className="flex flex-col gap-5">
                {/* Basics */}
                <div className="rounded-[12px] border border-border bg-surface px-4 pb-1">
                  <div className="py-3 font-semibold">Basics</div>
                  {basics.map((b) => (
                    <div
                      key={b.title}
                      className="flex justify-between gap-2.5 border-t border-border py-2.5"
                    >
                      <span className="text-fg-2">{b.title}</span>
                      <span className="text-right font-medium">{b.value}</span>
                    </div>
                  ))}
                </div>

                {/* Also appears in */}
                <div className="rounded-[12px] border border-border bg-surface px-4 pb-3">
                  <div className="py-3 font-semibold">Also appears in</div>
                  {usedIn.length === 0 ? (
                    <div className="pb-2 text-xs text-fg-3">
                      Nothing else references this station.
                    </div>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {usedIn.map((u, i) => (
                        <span
                          key={`${u.label}-${i}`}
                          className="rounded-[14px] bg-surface-2 px-2.5 py-1 text-[12.5px]"
                        >
                          {u.label}
                          {u.num && (
                            <span className="ml-1 font-mono text-[11px] text-fg-3 tnum">{u.num}</span>
                          )}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Phone buttons (from 205) */}
              <div className="rounded-[12px] border border-border bg-surface px-4 pb-4">
                <div className="flex items-center py-3">
                  <span className="flex-1 font-semibold">Phone buttons</span>
                  <span className="font-mono text-[11px] text-fg-3 tnum">from 205</span>
                </div>
                {keys === null ? (
                  <div className="pb-2 text-sm text-fg-2">Reading Flexible Buttons (205)…</div>
                ) : keys.length === 0 ? (
                  <div className="pb-2 text-sm text-fg-2">
                    No flexible buttons recorded for this DN in the snapshot.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {keys.map((k) => (
                      <div
                        key={k.keyNo}
                        className="flex h-[42px] items-center gap-2.5 rounded-[9px] border border-border bg-background px-3"
                        title={`${k.label} ${k.params}`.trim()}
                      >
                        <span
                          className={cn(
                            "h-2 w-2 shrink-0 rounded-sm",
                            k.assigned ? "bg-ok" : "bg-line-strong",
                          )}
                        />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-[12.5px] font-medium">{k.label}</span>
                          {k.params && (
                            <span className="block truncate font-mono text-[11px] text-fg-3">
                              {k.params}
                            </span>
                          )}
                        </span>
                        <span className="font-mono text-[10.5px] text-fg-3 tnum">{k.keyNo}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {/* Change… — the existing RecordForm edit/stage flow in a dialog. */}
      <Dialog open={changeOpen} onOpenChange={setChangeOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              Change station{selected ? ` — ${selected.name}` : ""}
            </DialogTitle>
          </DialogHeader>
          <div className="max-h-[70vh] overflow-auto">
            {selected && <RecordForm program={program} row={selected.row} />}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
