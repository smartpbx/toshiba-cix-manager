import * as React from "react";
import { AlertTriangle, Info, Loader2, RefreshCw, XCircle } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";
import { useStore } from "@/store/useStore";
import type { LintFinding, LintResult } from "@/lib/types";

// The Problems panel (DESIGN_PLAN §6): the config linter's L3 findings over the
// working copy. Each finding jumps to its program/row; a finding with a safe
// known remedy stages that fix into the pending tray (never an auto-write).
const SEV_ICON = {
  error: <XCircle className="h-4 w-4 text-bad" />,
  warn: <AlertTriangle className="h-4 w-4 text-warn" />,
  info: <Info className="h-4 w-4 text-fg-3" />,
};

function FindingRow({ f }: { f: LintFinding }) {
  const openProgram = useStore((s) => s.openProgram);
  const stageRowChanges = useStore((s) => s.stageRowChanges);
  const schema = useStore((s) => s.schema);

  const loc = [
    f.program_number ? `${f.program_number}` : null,
    f.row_key,
    f.field,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <div className="flex items-start gap-2 border-b border-border/60 px-3 py-2">
      <span className="mt-0.5">{SEV_ICON[f.severity]}</span>
      <div className="min-w-0 flex-1">
        <div className="text-sm">{f.message}</div>
        <div className="mt-0.5 flex items-center gap-2 text-2xs text-fg-3">
          <span className="font-mono">{f.rule}</span>
          {loc && <span>· {loc}</span>}
          {f.value && <span>· value {JSON.stringify(f.value)}</span>}
        </div>
      </div>
      {f.program && schema?.programs[f.program] && (
        <Button
          size="sm"
          variant="ghost"
          onClick={() =>
            openProgram(f.program!, schema.programs[f.program!].label)
          }
        >
          Open
        </Button>
      )}
      {f.fix && (
        <Button
          size="sm"
          variant="outline"
          onClick={() =>
            stageRowChanges(f.fix!.program_key, f.fix!.index, f.fix!.changes, {})
          }
          title="Stage the suggested fix into the pending tray"
        >
          Fix
        </Button>
      )}
    </div>
  );
}

export function ProblemsView() {
  const sessionId = useStore((s) => s.sessionId);
  const [result, setResult] = React.useState<LintResult | null>(null);
  const [loading, setLoading] = React.useState(false);

  const refresh = React.useCallback(() => {
    if (!sessionId) {
      setResult(null);
      return;
    }
    setLoading(true);
    api
      .lint(sessionId)
      .then((r) => setResult(r))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [sessionId]);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  const header = (
    <PageHeader
      title="Problems"
      subtitle="Config linter — holes eManager could not see"
      actions={
        sessionId ? (
          <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Re-check
          </Button>
        ) : null
      }
    />
  );

  let body: React.ReactNode;
  if (!sessionId) {
    body = <EmptyState message="Connect to a system to lint its programming." />;
  } else if (loading && !result) {
    body = (
      <div className="flex h-full items-center justify-center gap-2 text-sm text-fg-2">
        <Loader2 className="h-4 w-4 animate-spin" /> Checking…
      </div>
    );
  } else if (!result || result.findings.length === 0) {
    body = <EmptyState message="No problems found in this snapshot." />;
  } else {
    body = (
      <div className="min-h-0 flex-1 overflow-auto">
        <div className="flex items-center gap-2 px-3 py-2">
          {result.counts.error > 0 && (
            <Badge variant="bad">{result.counts.error} error</Badge>
          )}
          {result.counts.warn > 0 && (
            <Badge variant="warn">{result.counts.warn} warning</Badge>
          )}
          {result.counts.info > 0 && (
            <Badge variant="secondary">{result.counts.info} info</Badge>
          )}
          <span className="text-2xs text-fg-3">
            {result.rule_count} rules
          </span>
        </div>
        {result.findings.map((f, i) => (
          <FindingRow key={`${f.rule}:${i}`} f={f} />
        ))}
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
