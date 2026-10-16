import * as React from "react";
import { DataGrid, type GridColumn } from "@/components/DataGrid";
import { humanizeFieldName } from "@/lib/normalize";

type Rec = Record<string, unknown>;

function render(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.join(".");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

// Generic grid for an array of flat records (equipment, network/FTP rows).
// Columns are the union of keys in appearance order; the first column is pinned.
export function RecordGrid({
  rows,
  rowKey,
  preferredFirst,
  emptyLabel,
  colWidth = 150,
}: {
  rows: Rec[];
  rowKey: (r: Rec, i: number) => string;
  preferredFirst?: string;
  emptyLabel?: string;
  colWidth?: number;
}) {
  const columns = React.useMemo<GridColumn<Rec>[]>(() => {
    const keys: string[] = [];
    const seen = new Set<string>();
    if (preferredFirst) {
      keys.push(preferredFirst);
      seen.add(preferredFirst);
    }
    for (const r of rows) {
      for (const k of Object.keys(r)) {
        if (!seen.has(k)) {
          seen.add(k);
          keys.push(k);
        }
      }
    }
    return keys.map((k, i) => ({
      key: k,
      header: humanizeFieldName(k),
      width: i === 0 ? 120 : colWidth,
      sticky: i === 0,
      mono: i === 0,
      cell: (r: Rec) => render(r[k]),
    }));
  }, [rows, preferredFirst, colWidth]);

  return (
    <DataGrid
      columns={columns}
      rows={rows}
      rowKey={rowKey}
      emptyLabel={emptyLabel}
    />
  );
}
