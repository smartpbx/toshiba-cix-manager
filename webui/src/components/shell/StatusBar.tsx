import { useStore } from "@/store/useStore";

function relativeTime(iso?: string): string {
  if (!iso) return "";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  return `${hrs} h ago`;
}

export function StatusBar() {
  const { doc, catalog, version } = useStore((s) => ({
    doc: s.doc,
    catalog: s.catalog,
    version: s.version,
  }));

  const dev = doc?.device;
  return (
    <footer className="flex h-statusbar shrink-0 items-center gap-3 border-t border-border bg-surface px-3 text-2xs text-fg-2 tnum">
      {dev ? (
        <>
          <span>SNMP {dev.walk_error ? "⚠" : "ok"}</span>
          <span className="text-fg-3">·</span>
          <span>snapshot {relativeTime(dev.read_at)}</span>
          <span className="text-fg-3">·</span>
          <span>{dev.oids_read ?? 0} OIDs</span>
          <span className="text-fg-3">·</span>
          <span>{doc?.stations?.length ?? 0} stations</span>
          <span className="text-fg-3">·</span>
          <span>scope {dev.scope}</span>
        </>
      ) : (
        <span>No snapshot yet — connect and read a CIX.</span>
      )}
      <span className="flex-1" />
      {catalog?.catalog_version && (
        <span className="text-fg-3">
          catalog {catalog.programs} prg · {catalog.fields} fields
        </span>
      )}
      {version && <span className="text-fg-3">v{version}</span>}
    </footer>
  );
}
