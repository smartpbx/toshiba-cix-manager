import * as React from "react";
import { X } from "lucide-react";
import { DataGrid, type GridColumn } from "@/components/DataGrid";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { enumCaption, fieldByName, type SchemaField, type SchemaProgram } from "@/lib/schema";
import type { Cell, ProgramView, Row } from "@/lib/types";
import { RecordForm } from "./RecordForm";

function cellText(field: SchemaField | undefined, cell: Cell | undefined): string {
  if (!cell) return "";
  if (field?.is_enum || field?.enum_values) {
    return enumCaption(field, cell.raw_value, cell.display_value);
  }
  return cell.display_value ?? "";
}

// Grid + Record (DESIGN_PLAN 3.3/5.3): the grid of all rows is the default
// surface; selecting a row opens the record pane with that record's read-only
// form. The grid is virtualised with a sticky header and sticky key column
// (DataGrid), so a 1,000-station 200 scrolls without the header overlapping.
export function GridRecord({
  program,
  view,
}: {
  program: SchemaProgram;
  view: ProgramView;
}) {
  const [selected, setSelected] = React.useState<string | null>(null);
  const [filter, setFilter] = React.useState("");

  // Columns: the key column + the program's primary fields (named, never OIDs).
  const columnFields = React.useMemo(() => {
    const names = program.primary_fields?.length
      ? program.primary_fields
      : program.fields
          .filter((f) => f.control !== "hidden" && !f.key)
          .slice(0, 4)
          .map((f) => f.name);
    return names
      .map((n) => fieldByName(program, n))
      .filter((f): f is SchemaField => !!f);
  }, [program]);

  const rowCells = React.useMemo(() => {
    const m = new Map<string, Record<string, Cell>>();
    for (const r of view.rows) {
      const byName: Record<string, Cell> = {};
      for (const c of r.cells) byName[c.field_name] = c;
      m.set(r.index, byName);
    }
    return m;
  }, [view.rows]);

  const columns: GridColumn<Row>[] = React.useMemo(() => {
    const keyCol: GridColumn<Row> = {
      key: "__key",
      header: "Row",
      width: 120,
      sticky: true,
      mono: true,
      cell: (r) => r.key || r.index,
    };
    const cols = columnFields.map<GridColumn<Row>>((f) => ({
      key: f.name,
      header: (
        <span className="flex items-center gap-1">
          <span className="field-badge">{f.display_no}</span>
          <span className="truncate">{f.title}</span>
        </span>
      ),
      width: 170,
      cell: (r) => cellText(f, rowCells.get(r.index)?.[f.name]),
    }));
    return [keyCol, ...cols];
  }, [columnFields, rowCells]);

  const rows = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return view.rows;
    return view.rows.filter((r) => {
      if ((r.key || r.index).toLowerCase().includes(q)) return true;
      return r.cells.some((c) => (c.display_value ?? "").toLowerCase().includes(q));
    });
  }, [view.rows, filter]);

  const selectedRow = React.useMemo(
    () => view.rows.find((r) => r.index === selected) ?? null,
    [view.rows, selected],
  );

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-3 px-4 py-2">
        <Input
          placeholder="Filter DN / name / value…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="max-w-xs"
        />
        <span className="text-xs text-fg-2 tnum">
          {rows.length} / {view.row_count} rows
        </span>
      </div>
      <div className="flex min-h-0 flex-1 gap-3 px-4 pb-4">
        <div className={cn("min-w-0 flex-1")}>
          <DataGrid
            columns={columns}
            rows={rows}
            rowKey={(r) => r.index}
            selectedKey={selected ?? undefined}
            onRowClick={(r) => setSelected(r.index)}
            emptyLabel="No rows in this snapshot."
          />
        </div>
        {selectedRow && (
          <div className="flex w-[360px] shrink-0 flex-col overflow-hidden rounded-md border border-border bg-surface">
            <div className="flex items-center gap-2 border-b border-border bg-surface-2 px-3 py-2">
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-semibold">
                  {program.program_number ? `${program.program_number} · ` : ""}
                  {selectedRow.key || selectedRow.index}
                </div>
                <div className="truncate text-2xs text-fg-3">{program.label}</div>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="text-fg-3 hover:text-fg-2"
                aria-label="Close record"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="min-h-0 flex-1 overflow-auto px-3 py-2">
              <RecordForm program={program} row={selectedRow} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
