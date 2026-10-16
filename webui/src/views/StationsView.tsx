import * as React from "react";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type GridColumn } from "@/components/DataGrid";
import { Input } from "@/components/ui/input";
import type { Station } from "@/lib/types";
import { useStore } from "@/store/useStore";

const COLUMNS: GridColumn<Station>[] = [
  { key: "dn", header: "DN", width: 96, sticky: true, mono: true, cell: (s) => s.dn },
  { key: "name", header: "Name", width: 220, cell: (s) => s.name || <span className="text-fg-3">(unnamed)</span> },
  { key: "type", header: "Type", width: 110, cell: (s) => s.type || "" },
  { key: "port", header: "Equipment", width: 130, mono: true, cell: (s) => s.equipment_port || "" },
  { key: "ext", header: "Extension", width: 120, mono: true, cell: (s) => s.extension || "" },
  { key: "keys", header: "Keys", width: 80, mono: true, cell: (s) => (s.keys?.length ? String(s.keys.length) : "") },
];

export function StationsView() {
  const { doc, stationFilter, setStationFilter } = useStore((s) => ({
    doc: s.doc,
    stationFilter: s.stationFilter,
    setStationFilter: s.setStationFilter,
  }));
  const [filter, setFilter] = React.useState(stationFilter);
  const [selected, setSelected] = React.useState<string | undefined>(undefined);

  // Pick up a DN jump coming from the command palette.
  React.useEffect(() => {
    if (stationFilter) {
      setFilter(stationFilter);
      setSelected(stationFilter);
    }
  }, [stationFilter]);

  const stations = doc?.stations ?? [];
  const filtered = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return stations;
    return stations.filter(
      (s) =>
        s.dn.toLowerCase().includes(q) ||
        (s.name ?? "").toLowerCase().includes(q) ||
        (s.type ?? "").toLowerCase().includes(q) ||
        (s.equipment_port ?? "").toLowerCase().includes(q),
    );
  }, [stations, filter]);

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Station Assignments"
        subtitle="Station › 200, 204, 205, 208, 214, 216"
        actions={
          <div className="text-xs text-fg-2 tnum">
            {filtered.length} of {stations.length} stations
          </div>
        }
      />
      <div className="flex items-center gap-2 px-4 py-2">
        <Input
          placeholder="Filter DN / name / type / port…"
          value={filter}
          onChange={(e) => {
            setFilter(e.target.value);
            if (stationFilter) setStationFilter("");
          }}
          className="max-w-xs"
          autoFocus
        />
      </div>
      <div className="min-h-0 flex-1 px-4 pb-4">
        <DataGrid
          columns={COLUMNS}
          rows={filtered}
          rowKey={(s) => s.dn}
          selectedKey={selected}
          onRowClick={(s) => setSelected(s.dn)}
          emptyLabel="No stations match."
        />
      </div>
    </div>
  );
}
