import * as React from "react";
import { AlertTriangle, Loader2, RefreshCw, Terminal } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { RecordForm } from "@/components/program/RecordForm";
import { GridRecord } from "@/components/program/GridRecord";
import { SpecialLayout } from "@/components/program/SpecialLayout";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

// A bounded/failed program read carries a reason; show it (and let the tech
// re-read just this program) instead of the old ambiguous "No rows".
function ReadFailed({
  title,
  reason,
  onRetry,
  canRetry,
}: {
  title: string;
  reason: string;
  onRetry: () => void;
  canRetry: boolean;
}) {
  return (
    <div className="mx-auto flex h-full max-w-md flex-col items-center justify-center gap-3 p-6 text-center">
      <AlertTriangle className="h-7 w-7 text-warn" />
      <div className="text-sm font-semibold">{title}</div>
      <p className="text-xs text-fg-2">{reason}</p>
      {canRetry && (
        <Button size="sm" onClick={onRetry}>
          <RefreshCw className="h-4 w-4" />
          Try reading it now
        </Button>
      )}
    </div>
  );
}

export function ProgramPage({ programKey }: { programKey: string }) {
  const { schema, view, status, loading, sessionId, ensureProgram, refreshProgram, coldStart } =
    useStore(
      useShallow((s) => ({
        schema: s.schema,
        view: s.programViews[programKey],
        status: s.programStatus[programKey],
        loading: s.loadingKeys.has(programKey),
        sessionId: s.sessionId,
        ensureProgram: s.ensureProgram,
        refreshProgram: s.refreshProgram,
        coldStart: s.coldStart,
      })),
    );

  React.useEffect(() => {
    ensureProgram(programKey);
  }, [programKey, ensureProgram]);

  const prog = schema?.programs[programKey];
  if (!prog) return <EmptyState message="Unknown program." />;

  const outcome = status?.outcome;
  const failedRead =
    outcome === "error" || outcome === "timeout" || outcome === "capped";
  const failTitle =
    outcome === "error"
      ? "This program could not be read"
      : "This program was only read in part";
  const failReason =
    status?.error ??
    (outcome === "error"
      ? "The device did not answer for this program during the snapshot."
      : "The read hit its per-program budget before finishing.");

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
  } else if (loading && !view) {
    body = (
      <div className="flex h-full items-center justify-center gap-2 text-sm text-fg-2">
        <Loader2 className="h-4 w-4 animate-spin" /> Reading {prog.label}…
      </div>
    );
  } else if (view && view.row_count > 0) {
    // Data arrived (possibly a partial read of a slow/oversized table). Show
    // it, with a banner when the read did not finish so the rows aren't
    // mistaken for the whole program.
    const data =
      prog.archetype === "special" ? (
        <SpecialLayout program={prog} view={view} />
      ) : prog.archetype === "form" ||
        (view.row_count === 1 && prog.archetype !== "grid_record") ? (
        <div className="max-w-2xl overflow-auto p-4">
          <RecordForm program={prog} row={view.rows[0]} />
        </div>
      ) : (
        <GridRecord program={prog} view={view} />
      );
    body = failedRead ? (
      <div className="flex h-full min-h-0 flex-col">
        <div className="flex items-center gap-2 border-b border-warn/40 bg-warn/10 px-3 py-1.5 text-2xs text-fg-2">
          <AlertTriangle className="h-3.5 w-3.5 text-warn" />
          <span>Partial read — {failReason}</span>
          {sessionId && (
            <button
              className="ml-auto underline underline-offset-2"
              onClick={() => refreshProgram(programKey)}
            >
              re-read now
            </button>
          )}
        </div>
        <div className="min-h-0 flex-1 overflow-hidden">{data}</div>
      </div>
    ) : (
      data
    );
  } else if (failedRead) {
    body = (
      <ReadFailed
        title={failTitle}
        reason={failReason}
        onRetry={() => refreshProgram(programKey)}
        canRetry={!!sessionId}
      />
    );
  } else if (outcome === "empty") {
    body = <EmptyState message="Read — this program has no rows programmed." />;
  } else if (coldStart) {
    body = <EmptyState message="No data for this program in this snapshot." />;
  } else if (view) {
    // Fetched, catalogued, but no rows and no status yet — treat as empty.
    body = <EmptyState message="No rows for this program in the snapshot." />;
  } else {
    body = (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-sm text-fg-2">
        <p>Not read yet.</p>
        {sessionId && (
          <Button size="sm" onClick={() => refreshProgram(programKey)}>
            Read now
          </Button>
        )}
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      {header}
      <div className="min-h-0 flex-1 overflow-hidden">{body}</div>
    </div>
  );
}
