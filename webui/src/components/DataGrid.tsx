import * as React from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@/lib/utils";

export interface GridColumn<T> {
  key: string;
  header: React.ReactNode;
  /** px width; columns are fixed-width so header + body cells stay aligned. */
  width?: number;
  /** pin to the left edge (the key column) — stays put on horizontal scroll. */
  sticky?: boolean;
  mono?: boolean;
  cell: (row: T) => React.ReactNode;
}

interface DataGridProps<T> {
  columns: GridColumn<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  rowHeight?: number;
  onRowClick?: (row: T) => void;
  selectedKey?: string;
  className?: string;
  emptyLabel?: string;
}

// A virtualised grid (CIX670s carry 1,000+ stations / 800 speed dials).
//
// The current hand-rolled UI had a bug where the sticky header overlapped the
// first rows. We avoid it structurally: the header is an OPAQUE sibling that
// comes first in the scroll container with `position: sticky; top: 0` and a
// higher z-index than the rows, so rows scroll *under* it and are never hidden
// beneath a transparent bar. The body is a separate relative box whose height
// equals the virtualiser's total size, so nothing is positioned over the header.
export function DataGrid<T>({
  columns,
  rows,
  rowKey,
  rowHeight = 28,
  onRowClick,
  selectedKey,
  className,
  emptyLabel = "No rows.",
}: DataGridProps<T>) {
  const parentRef = React.useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 12,
  });

  const totalWidth = columns.reduce((sum, c) => sum + (c.width ?? 140), 0);
  const items = virtualizer.getVirtualItems();

  const cellStyle = (c: GridColumn<T>, zBase: number): React.CSSProperties => ({
    width: c.width ?? 140,
    minWidth: c.width ?? 140,
    maxWidth: c.width ?? 140,
    ...(c.sticky
      ? { position: "sticky", left: 0, zIndex: zBase }
      : {}),
  });

  return (
    <div
      ref={parentRef}
      className={cn(
        "relative h-full overflow-auto rounded-md border border-border bg-surface",
        className,
      )}
    >
      <div style={{ width: Math.max(totalWidth, 0) }}>
        {/* Sticky, opaque header. z-30 so it sits over every row. */}
        <div className="sticky top-0 z-30 flex border-b border-line-strong bg-surface-2">
          {columns.map((c) => (
            <div
              key={c.key}
              style={cellStyle(c, 40)}
              className={cn(
                "flex h-row items-center px-2 text-2xs font-semibold uppercase tracking-wide text-fg-2",
                c.sticky && "bg-surface-2 border-r border-line-strong",
              )}
            >
              <span className="truncate" title={typeof c.header === "string" ? c.header : undefined}>
                {c.header}
              </span>
            </div>
          ))}
        </div>

        {rows.length === 0 ? (
          <div className="px-3 py-6 text-sm text-fg-2">{emptyLabel}</div>
        ) : (
          <div
            style={{ height: virtualizer.getTotalSize(), position: "relative" }}
          >
            {items.map((vi) => {
              const row = rows[vi.index];
              const key = rowKey(row, vi.index);
              const selected = selectedKey != null && key === selectedKey;
              return (
                <div
                  key={key}
                  data-state={selected ? "selected" : undefined}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={cn(
                    "absolute left-0 flex w-full border-b border-border",
                    onRowClick && "cursor-pointer",
                    selected ? "bg-surface-3" : "hover:bg-surface-2",
                  )}
                  style={{
                    height: vi.size,
                    transform: `translateY(${vi.start}px)`,
                  }}
                >
                  {columns.map((c) => (
                    <div
                      key={c.key}
                      style={cellStyle(c, 10)}
                      className={cn(
                        "flex items-center px-2 text-sm",
                        c.mono && "font-mono tnum",
                        // the pinned column needs the row's own bg so text
                        // beneath it never shows through on horizontal scroll
                        c.sticky &&
                          (selected
                            ? "bg-surface-3 border-r border-border"
                            : "bg-surface border-r border-border"),
                      )}
                    >
                      <span className="truncate">{c.cell(row)}</span>
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
