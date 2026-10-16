import { AlertTriangle, ChevronRight, Trash2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";
import type { PendingOp } from "@/lib/types";

// The pending-changes rail (DESIGN_PLAN 5.5): staged edits, coalesced per field,
// nothing on the wire. "Review & write" opens the one modal. The rail is the
// only path to the write dialog.
function OpLine({ op }: { op: PendingOp }) {
  if (!op.sendable) {
    return (
      <div className="flex items-center gap-1.5 py-0.5 text-2xs text-fg-3">
        <span className="field-badge">{op.column ?? "—"}</span>
        <span className="truncate line-through">{op.label}</span>
        <span className="truncate italic">— {op.note || "skipped"}</span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-1.5 py-0.5 text-xs">
      <span className="field-badge">{op.column ?? "—"}</span>
      <span className="min-w-0 flex-1 truncate" title={op.label}>
        {op.label}
      </span>
      <span className="truncate text-fg-3 line-through" title={op.old_value ?? ""}>
        {op.old_value ?? "—"}
      </span>
      <ChevronRight className="h-3 w-3 shrink-0 text-fg-3" />
      <span className="truncate font-medium text-foreground" title={op.new_value}>
        {op.new_value || "(empty)"}
      </span>
      {!op.wire_proven && (
        <span
          className="text-warn"
          title="catalog-derived wire type (not seen on the wire)"
        >
          <AlertTriangle className="h-3 w-3" />
        </span>
      )}
    </div>
  );
}

export function PendingRail() {
  const {
    sessionId,
    pending,
    count,
    validation,
    railOpen,
    setRailOpen,
    clearPending,
    openReview,
  } = useStore(
    useShallow((s) => ({
      sessionId: s.sessionId,
      pending: s.pending,
      count: s.pendingFieldCount,
      validation: s.pendingValidation,
      railOpen: s.railOpen,
      setRailOpen: s.setRailOpen,
      clearPending: s.clearPending,
      openReview: s.openReview,
    })),
  );

  if (!sessionId || count === 0) return null;
  const errorCount = validation?.error_count ?? 0;

  if (!railOpen) {
    return (
      <button
        onClick={() => setRailOpen(true)}
        className="flex w-10 shrink-0 flex-col items-center gap-2 border-l border-border bg-surface py-3 text-xs text-fg-2 hover:bg-surface-2"
        title="Show pending changes"
      >
        <Badge variant={errorCount ? "bad" : "warn"}>{count}</Badge>
        <span className="[writing-mode:vertical-rl]">Pending</span>
      </button>
    );
  }

  return (
    <aside className="flex w-[320px] shrink-0 flex-col border-l border-border bg-surface">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <span className="text-sm font-semibold">Pending changes</span>
        <Badge variant={errorCount ? "bad" : "warn"}>{count}</Badge>
        <div className="flex-1" />
        <button
          onClick={() => clearPending()}
          className="text-fg-3 hover:text-bad"
          title="Clear all staged changes"
        >
          <Trash2 className="h-4 w-4" />
        </button>
        <button
          onClick={() => setRailOpen(false)}
          className="text-fg-3 hover:text-fg-2"
          title="Collapse"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto px-2 py-2">
        {pending.map((g) => (
          <div
            key={`${g.program_key}:${g.index}`}
            className="mb-2 rounded-md border border-border bg-surface-2"
          >
            <div className="flex items-center gap-1.5 border-b border-border/60 px-2 py-1">
              {g.program_number && (
                <span className="field-badge">{g.program_number}</span>
              )}
              <span className="min-w-0 flex-1 truncate text-xs font-medium">
                {g.label} · {g.row_key}
              </span>
              <button
                onClick={() => clearPending({ program: g.program_key, index: g.index })}
                className="text-fg-3 hover:text-bad"
                title="Remove this row's changes"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
            <div className="px-2 py-1">
              {g.ops.map((op, i) => (
                <OpLine key={`${op.field}:${i}`} op={op} />
              ))}
            </div>
          </div>
        ))}
      </div>

      {errorCount > 0 && (
        <div className="flex items-center gap-1.5 border-t border-border bg-bad-tint px-3 py-1.5 text-xs text-bad">
          <AlertTriangle className="h-3.5 w-3.5" />
          {errorCount} validation {errorCount === 1 ? "error" : "errors"} — fix
          before writing
        </div>
      )}

      <div className="border-t border-border p-2">
        <Button
          className={cn("w-full")}
          onClick={openReview}
          title="Open the Review & Write dialog"
        >
          Review &amp; write {count}
        </Button>
      </div>
    </aside>
  );
}
