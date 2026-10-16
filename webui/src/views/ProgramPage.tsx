import * as React from "react";
import { Loader2, RefreshCw, Terminal } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { RecordForm } from "@/components/program/RecordForm";
import { GridRecord } from "@/components/program/GridRecord";
import { useStore } from "@/store/useStore";

export function ProgramPage({ programKey }: { programKey: string }) {
  const { schema, view, loading, sessionId, ensureProgram, refreshProgram, coldStart } =
    useStore((s) => ({
      schema: s.schema,
      view: s.programViews[programKey],
      loading: s.loadingKeys.has(programKey),
      sessionId: s.sessionId,
      ensureProgram: s.ensureProgram,
      refreshProgram: s.refreshProgram,
      coldStart: s.coldStart,
    }));

  React.useEffect(() => {
    ensureProgram(programKey);
  }, [programKey, ensureProgram]);

  const prog = schema?.programs[programKey];
  if (!prog) return <EmptyState message="Unknown program." />;

  const header = (
    <PageHeader
      title={
        <span className="flex items-center gap-2">
          {prog.program_number && (
            <span className="field-badge">{prog.program_number}</span>
          )}
          {prog.label}
        </span>
      }
      subtitle={prog.menu_path}
      actions={
        sessionId ? (
          <Button
            variant="outline"
            size="sm"
            onClick={() => refreshProgram(programKey)}
            disabled={loading}
            title="Re-read this program from the device (read-only)"
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Refresh
          </Button>
        ) : null
      }
    />
  );

  let body: React.ReactNode;
  if (prog.archetype === "action") {
    body = (
      <div className="max-w-xl p-6">
        <div className="flex items-start gap-3 rounded-md border border-border bg-surface p-4">
          <Terminal className="mt-0.5 h-5 w-5 text-fg-3" />
          <div>
            <div className="font-semibold">{prog.title ?? prog.label}</div>
            <p className="mt-1 text-sm text-fg-2">
              This is a one-shot command. Running it is an editing action, which
              arrives with the write path in a later release — this read-only
              build shows its definition only.
            </p>
            {prog.description && (
              <p className="mt-2 text-xs text-fg-3">{prog.description}</p>
            )}
          </div>
        </div>
      </div>
    );
  } else if (!view) {
    body = loading ? (
      <div className="flex h-full items-center justify-center gap-2 text-sm text-fg-2">
        <Loader2 className="h-4 w-4 animate-spin" /> Reading {prog.label}…
      </div>
    ) : coldStart ? (
      <EmptyState message="No data for this program in the snapshot." />
    ) : (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-sm text-fg-2">
        <p>Not read yet.</p>
        <Button size="sm" onClick={() => refreshProgram(programKey)}>
          Read now
        </Button>
      </div>
    );
  } else if (view.row_count === 0) {
    body = <EmptyState message="No rows for this program in the snapshot." />;
  } else if (prog.archetype === "form" || (view.row_count === 1 && prog.archetype !== "grid_record")) {
    // Scalar / Form program: the single record as a full-width grouped form.
    body = (
      <div className="max-w-2xl overflow-auto p-4">
        <RecordForm program={prog} row={view.rows[0]} />
      </div>
    );
  } else {
    body = <GridRecord program={prog} view={view} />;
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      {header}
      <div className="min-h-0 flex-1 overflow-hidden">{body}</div>
    </div>
  );
}
