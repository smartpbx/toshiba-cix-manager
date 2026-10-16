import { Loader2 } from "lucide-react";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

function relativeTime(iso?: string | null): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  return `${Math.round(mins / 60)} h ago`;
}

// Status bar (DESIGN_PLAN 3.1): snapshot age (amber past 30 min), counts, and
// the long-op progress on the right while a read runs.
export function StatusBar() {
  const { progress, meta, readCount, schema, version, coldStart } = useStore(
    useShallow((s) => ({
      progress: s.progress,
      meta: s.snapshotMeta,
      readCount: s.readKeys.size,
      schema: s.schema,
      version: s.version,
      coldStart: s.coldStart,
    })),
  );

  const reading = progress.status === "reading" || progress.status === "connecting";
  const age = relativeTime(meta?.read_at);
  const stale =
    meta?.read_at && Date.now() - Date.parse(meta.read_at) > 30 * 60 * 1000;

  return (
    <footer className="flex h-statusbar shrink-0 items-center gap-3 border-t border-border bg-surface px-3 text-2xs text-fg-2 tnum">
      {meta ? (
        <>
          <span>
            SNMP {meta.walk_error ? "⚠ partial" : "ok"}
          </span>
          <span className="text-fg-3">·</span>
          <span className={stale ? "text-warn" : undefined}>
            snapshot {age}
            {coldStart ? " (from disk)" : ""}
          </span>
          <span className="text-fg-3">·</span>
          <span>{readCount} programs read</span>
          {meta.oids_read != null && (
            <>
              <span className="text-fg-3">·</span>
              <span>{meta.oids_read} OIDs</span>
            </>
          )}
        </>
      ) : (
        <span>No snapshot yet — connect to a CIX.</span>
      )}
      <span className="flex-1" />
      {reading && (
        <span className="flex items-center gap-1.5 text-fg">
          <Loader2 className="h-3 w-3 animate-spin" />
          {progress.message}
          {progress.total > 0 && (
            <span className="text-fg-3">
              {progress.done}/{progress.total}
            </span>
          )}
        </span>
      )}
      {progress.status === "error" && (
        <span className="text-bad">{progress.message}</span>
      )}
      {schema && (
        <span className="text-fg-3">
          catalog {schema.counts.programs} prg · {schema.counts.fields} fields
        </span>
      )}
      {version && <span className="text-fg-3">v{version}</span>}
    </footer>
  );
}
