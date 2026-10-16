import * as React from "react";
import { ArrowUpRight } from "lucide-react";
import { api } from "@/lib/api";
import type { Occurrence } from "@/lib/types";
import { useStore } from "@/store/useStore";

// "↗ used by N" — the typed where-used chip (improvements.md §2.1): for the
// selected row's key (a DN / COS / hunt number), ask the value index which
// reference fields elsewhere point at it. One mechanism (index.references_to)
// behind the chip; it appears only when there is at least one reference, and
// expands to the list. Works live (session) and in file mode (snapshot).
export function WhereUsedChip({ rowKey }: { rowKey: string }) {
  const { sessionId, fileMode } = useStore((s) => ({
    sessionId: s.sessionId,
    fileMode: s.fileMode,
  }));
  const [occ, setOcc] = React.useState<Occurrence[] | null>(null);
  const [open, setOpen] = React.useState(false);

  React.useEffect(() => {
    let live = true;
    setOcc(null);
    setOpen(false);
    const key = (rowKey || "").split("/").pop() || rowKey; // seq1/201 -> 201
    if (!key) return;
    const p = sessionId
      ? api.find(sessionId, key, true)
      : fileMode
        ? api.snapshotFind(fileMode.siteId, fileMode.sid, key, true)
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
  }, [rowKey, sessionId, fileMode]);

  if (!occ || occ.length === 0) return null;
  return (
    <div className="mt-1">
      <button
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-1.5 py-0.5 text-2xs text-fg-2 hover:border-line-strong"
        title="Reference fields elsewhere that point at this row"
      >
        <ArrowUpRight className="h-3 w-3" /> used by {occ.length}
      </button>
      {open && (
        <ul className="mt-1 max-h-40 space-y-0.5 overflow-auto rounded border border-border bg-surface p-1 text-2xs">
          {occ.map((o, i) => (
            <li key={`${o.program}-${o.index}-${o.field}-${i}`} className="flex items-center gap-1">
              <span className="font-mono tnum text-fg-2">{o.row_key || o.index}</span>
              <span className="text-fg-3">· {o.field}</span>
              <span className="ml-auto truncate text-fg-3">{o.menu_path || o.program}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
