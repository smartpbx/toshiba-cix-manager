import * as React from "react";
import { ChevronDown, ChevronRight, Info, MinusCircle, PlusCircle, TriangleAlert } from "lucide-react";
import type { AnnotatedDiff, DiffGroup, DiffLine } from "@/lib/types";

// The diff pane (backups.md §4.2 / DESIGN_PLAN 7.4). This is the one component
// the P2 Review & Write dialog reuses, so it renders the annotated diff only
// and takes the restore picker as props — in this read-only release the line
// checkboxes are shown but inert (restore arrives with the write path).

interface Props {
  annotated: AnnotatedDiff;
  showReadonly: boolean;
  showVolatile: boolean;
  onToggleReadonly: (v: boolean) => void;
  onToggleVolatile: (v: boolean) => void;
  onExport?: (format: "markdown" | "csv" | "text" | "json") => void;
  loading?: boolean;
}

function Attribution({ line }: { line: DiffLine }) {
  const a = line.attribution;
  if (!a) return null;
  if (a.outside) {
    return (
      <span className="ml-auto flex items-center gap-1 text-2xs text-warn" title="No matching write in this app's log">
        <TriangleAlert className="h-3 w-3" /> changed outside this app
      </span>
    );
  }
  return (
    <span className="ml-auto flex items-center gap-1 text-2xs text-fg-3" title={a.changeset || ""}>
      <Info className="h-3 w-3" /> by {a.by || "?"}
      {a.at ? ` · ${a.at}` : ""}
    </span>
  );
}

function Line({ line }: { line: DiffLine }) {
  if (line.kind === "row_added" || line.kind === "row_removed") {
    const added = line.kind === "row_added";
    return (
      <div className="flex items-start gap-2 py-1 pl-6 pr-2 text-sm">
        <input type="checkbox" disabled className="mt-1" title="Restore arrives with the write release" />
        {added ? (
          <PlusCircle className="mt-0.5 h-4 w-4 shrink-0 text-ok" />
        ) : (
          <MinusCircle className="mt-0.5 h-4 w-4 shrink-0 text-bad" />
        )}
        <div className="min-w-0">
          <span className="font-mono tnum">{line.row_key || line.index}</span>
          <span className="ml-2 text-fg-3">{added ? "row added" : "row removed"}</span>
          {line.fields && line.fields.length > 0 && (
            <div className="mt-0.5 truncate text-2xs text-fg-3">
              {line.fields.slice(0, 6).map((f) => `${f.field}=${f.display}`).join(" · ")}
              {line.fields.length > 6 ? " …" : ""}
            </div>
          )}
        </div>
      </div>
    );
  }
  const changed = line.kind === "field_changed";
  return (
    <div className="flex items-center gap-2 py-1 pl-6 pr-2 text-sm">
      <input type="checkbox" disabled title="Restore arrives with the write release" />
      {line.display_no && <span className="field-badge">{line.display_no}</span>}
      <span className="truncate text-fg-2">{line.title}</span>
      <span className="truncate font-mono tnum text-2xs text-fg-3">{line.row_key}</span>
      <span className="ml-2 flex items-center gap-1 font-mono tnum">
        {changed ? (
          <>
            <span className="text-fg-3 line-through">{line.old_display}</span>
            <span className="text-fg-3">→</span>
            <span className="font-medium text-foreground">{line.new_display}</span>
          </>
        ) : line.kind === "field_added" ? (
          <span className="text-ok">+ {line.new_display}</span>
        ) : (
          <span className="text-bad">− {line.old_display}</span>
        )}
      </span>
      <Attribution line={line} />
    </div>
  );
}

function Group({ group }: { group: DiffGroup }) {
  const [open, setOpen] = React.useState(true);
  return (
    <div className="border-b border-border/60">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 bg-surface px-2 py-1.5 text-left text-sm font-medium hover:bg-surface-2"
      >
        {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        {group.number && <span className="field-badge">{group.number}</span>}
        <span className="truncate">{group.menu_path || group.label}</span>
        <span className="ml-auto shrink-0 text-2xs text-fg-3">
          {group.rows_changed ? `${group.rows_changed} rows · ` : ""}
          {group.fields_changed} fields
        </span>
      </button>
      {open && (
        <div className="divide-y divide-border/40">
          {group.lines.map((ln, i) => (
            <Line key={`${ln.kind}-${ln.field || ln.index}-${i}`} line={ln} />
          ))}
        </div>
      )}
    </div>
  );
}

export function DiffPane({
  annotated,
  showReadonly,
  showVolatile,
  onToggleReadonly,
  onToggleVolatile,
  onExport,
  loading,
}: Props) {
  const s = annotated.summary;
  const nothing = annotated.groups.length === 0;
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border bg-surface px-3 py-2 text-xs">
        <span className="text-fg-2">
          rows <span className="text-ok">+{s.rows_added}</span>{" "}
          <span className="text-bad">−{s.rows_removed}</span> · fields ~{s.fields_changed}{" "}
          (+{s.fields_added} −{s.fields_removed})
        </span>
        <span className="text-fg-3">read-only hidden {s.ignored_readonly}</span>
        <span className="text-fg-3">volatile hidden {s.volatile_hidden}</span>
        <label className="flex items-center gap-1 text-fg-2">
          <input type="checkbox" checked={showReadonly} onChange={(e) => onToggleReadonly(e.target.checked)} />
          show read-only
        </label>
        <label className="flex items-center gap-1 text-fg-2">
          <input type="checkbox" checked={showVolatile} onChange={(e) => onToggleVolatile(e.target.checked)} />
          show volatile
        </label>
        {onExport && (
          <span className="ml-auto flex items-center gap-1">
            <span className="text-fg-3">export</span>
            {(["markdown", "csv", "text", "json"] as const).map((f) => (
              <button
                key={f}
                onClick={() => onExport(f)}
                className="rounded border border-border px-1.5 py-0.5 text-2xs text-fg-2 hover:bg-surface-2"
              >
                {f === "markdown" ? "md" : f}
              </button>
            ))}
          </span>
        )}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {loading ? (
          <div className="p-6 text-center text-sm text-fg-2">Comparing…</div>
        ) : nothing ? (
          <div className="p-6 text-center text-sm text-fg-2">
            No programming differences{s.ignored_readonly + s.volatile_hidden > 0
              ? ` (${s.ignored_readonly + s.volatile_hidden} read-only / volatile changes hidden)`
              : ""}
            .
          </div>
        ) : (
          annotated.groups.map((g) => <Group key={g.program} group={g} />)
        )}
      </div>
      <div className="shrink-0 border-t border-border bg-surface px-3 py-1.5 text-2xs text-fg-3">
        Restore selected from A → live arrives with the write release (every line is a
        checkbox because the diff is the restore picker). This build is read-only.
      </div>
    </div>
  );
}
