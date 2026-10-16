import * as React from "react";
import { ChevronDown, ChevronRight, Loader2 } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/PageHeader";
import { DataGrid, type GridColumn } from "@/components/DataGrid";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import {
  programsByMenuArea,
  type NormalizedProgram,
  type NormalizedRow,
} from "@/lib/normalize";
import { useStore } from "@/store/useStore";

export function ProgramsView() {
  const { backupA, setBackupA, programViews, setProgramViews, form } = useStore(
    (s) => ({
      backupA: s.backupA,
      setBackupA: s.setBackupA,
      programViews: s.programViews,
      setProgramViews: s.setProgramViews,
      form: s.form,
    }),
  );

  // Prefer the enriched program_views (named columns, enum display values,
  // catalog menu areas, feature views); fall back to the raw backup doc only
  // when enrichment is absent (lean reader build / catalog unavailable).
  const source =
    programViews && programViews.programs.length ? programViews : backupA;
  const featureViews = (programViews?.feature_views ?? []).filter(
    (f) => f.present,
  );
  const groups = React.useMemo(() => programsByMenuArea(source), [source]);
  const [openAreas, setOpenAreas] = React.useState<Record<string, boolean>>({});
  const [selectedKey, setSelectedKey] = React.useState<string | null>(null);
  const [filter, setFilter] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);

  // Default: open the first area and select its first program.
  React.useEffect(() => {
    if (groups.length && !selectedKey) {
      setOpenAreas({ [groups[0].area]: true });
      setSelectedKey(groups[0].programs[0]?.catalogKey ?? null);
    }
  }, [groups, selectedKey]);

  const selected: NormalizedProgram | null = React.useMemo(() => {
    for (const g of groups) {
      const p = g.programs.find((pr) => pr.catalogKey === selectedKey);
      if (p) return p;
    }
    return null;
  }, [groups, selectedKey]);

  const readCatalog = async () => {
    if (!form.ip.trim()) {
      setErr("Set a CIX address on the Connect page first.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const res = await api.catalogBackup({
        ip: form.ip.trim(),
        community: form.community.trim() || "communityName",
        port: form.port || 161,
      });
      if (res.ok && res.backup) {
        setBackupA(res.backup);
        setProgramViews(res.program_views ?? null);
      } else setErr(res.error || "Catalog read failed.");
    } catch (e) {
      setErr(`Request failed: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const columns: GridColumn<NormalizedRow>[] = React.useMemo(() => {
    if (!selected) return [];
    const keyCol: GridColumn<NormalizedRow> = {
      key: "__key",
      header: "Row",
      width: 110,
      sticky: true,
      mono: true,
      cell: (r) => r.key,
    };
    const fieldCols: GridColumn<NormalizedRow>[] = selected.columns.map((c) => ({
      key: c.fieldName,
      header: c.label, // field_name / native title — NEVER a bare OID
      width: 160,
      cell: (r) => r.cells[c.fieldName] ?? "",
    }));
    return [keyCol, ...fieldCols];
  }, [selected]);

  const filteredRows = React.useMemo(() => {
    if (!selected) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return selected.rows;
    return selected.rows.filter(
      (r) =>
        r.key.toLowerCase().includes(q) ||
        Object.values(r.cells).some((v) => v.toLowerCase().includes(q)),
    );
  }, [selected, filter]);

  if (!source) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader title="Programs" subtitle="Browse by eManager menu area" />
        <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
          <p className="max-w-md text-sm text-fg-2">
            The Programs browser renders a full catalog backup — every program
            grouped under its eManager menu area. Read one now, or run it from
            Backup &amp; Diff.
          </p>
          {err && <p className="text-sm text-bad">{err}</p>}
          <Button onClick={readCatalog} disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            Read full catalog
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Programs"
        subtitle="Browse by eManager menu area"
        actions={
          <Button variant="outline" size="sm" onClick={readCatalog} disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            Re-read
          </Button>
        }
      />
      <div className="flex min-h-0 flex-1">
        {/* menu-area tree */}
        <div className="w-64 shrink-0 overflow-auto border-r border-border p-2">
          {featureViews.length > 0 && (
            <div className="mb-2 border-b border-border pb-2">
              <div className="px-1.5 py-1 text-2xs font-semibold uppercase tracking-wide text-fg-3">
                Feature views
              </div>
              <div className="flex flex-wrap gap-1 px-1">
                {featureViews.map((f) => (
                  <button
                    key={f.key}
                    title={f.title}
                    onClick={() => {
                      const firstKey = f.programs[0];
                      if (!firstKey) return;
                      const area = groups.find((g) =>
                        g.programs.some((p) => p.catalogKey === firstKey),
                      )?.area;
                      if (area) setOpenAreas((s) => ({ ...s, [area]: true }));
                      setSelectedKey(firstKey);
                    }}
                    className="rounded-full border border-border px-2 py-0.5 text-2xs text-fg-2 hover:bg-surface-2 hover:text-primary"
                  >
                    {f.title}
                  </button>
                ))}
              </div>
            </div>
          )}
          {groups.map((g) => {
            const open = openAreas[g.area];
            return (
              <div key={g.area} className="mb-1">
                <button
                  onClick={() => setOpenAreas((s) => ({ ...s, [g.area]: !s[g.area] }))}
                  className="flex w-full items-center gap-1 rounded-md px-1.5 py-1 text-2xs font-semibold uppercase tracking-wide text-fg-2 hover:bg-surface-2"
                >
                  {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                  {g.area}
                  <span className="ml-auto text-fg-3">{g.programs.length}</span>
                </button>
                {open &&
                  g.programs.map((p) => (
                    <button
                      key={p.catalogKey}
                      onClick={() => setSelectedKey(p.catalogKey)}
                      className={cn(
                        "flex w-full items-center gap-2 rounded-md px-2 py-1 text-sm",
                        selectedKey === p.catalogKey
                          ? "bg-accent-tint text-primary"
                          : "hover:bg-surface-2",
                      )}
                    >
                      <span className="field-badge">{p.number}</span>
                      <span className="flex-1 truncate text-left">{p.name}</span>
                      <span className="text-2xs text-fg-3 tnum">{p.rowCount}</span>
                    </button>
                  ))}
              </div>
            );
          })}
        </div>

        {/* selected program grid */}
        <div className="flex min-w-0 flex-1 flex-col">
          {selected ? (
            <>
              <div className="flex items-center gap-3 px-4 py-2">
                <div className="flex items-center gap-2">
                  <span className="field-badge">{selected.number}</span>
                  <span className="text-sm font-semibold">{selected.name}</span>
                  <span className="text-xs text-fg-3">{selected.menuArea}</span>
                </div>
                <Input
                  placeholder="Filter rows…"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  className="ml-auto max-w-xs"
                />
                <span className="text-xs text-fg-2 tnum">
                  {filteredRows.length} / {selected.rowCount}
                </span>
              </div>
              <div className="min-h-0 flex-1 px-4 pb-4">
                <DataGrid
                  columns={columns}
                  rows={filteredRows}
                  rowKey={(r) => r.index}
                  emptyLabel="This program has no rows in the snapshot."
                />
              </div>
            </>
          ) : (
            <EmptyState message="Select a program on the left." />
          )}
        </div>
      </div>
    </div>
  );
}
