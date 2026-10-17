import * as React from "react";
import { AlertTriangle, Loader2, Maximize2, RefreshCw, Search, ZoomIn, ZoomOut } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";
import { CallFlowCanvas } from "@/callflow/CallFlowCanvas";
import type { CallFlowCanvasHandle } from "@/callflow/CallFlowCanvas";
import { NodeInspector } from "@/callflow/NodeInspector";
import { DEFAULT_HIDDEN_EDGES, edgeKind, nodeKind } from "@/callflow/kinds";
import type {
  CallFlowCoverage, CallFlowGraph, EdgeKind, LayoutModel, NodeKind,
} from "@/callflow/types";

// The Call flow tab: fetch the neutral routing graph for the active working
// copy (live session or cold/file snapshot) and render it with the ported
// SVG canvas + inspector. The whole diagram is read-only.
export function CallFlowView() {
  const { sessionId, coldStart, fileMode, siteId } = useStore(
    useShallow((s) => ({
      sessionId: s.sessionId,
      coldStart: s.coldStart,
      fileMode: s.fileMode,
      siteId: s.siteId(),
    })),
  );

  const [loading, setLoading] = React.useState(false);
  const [graph, setGraph] = React.useState<CallFlowGraph | null>(null);
  const [notAvailable, setNotAvailable] = React.useState<string | null>(null);
  const [err, setErr] = React.useState<string | null>(null);
  // Entry points were drawn but nothing routes onward: carry the honest reason
  // + read coverage so the diagram shows a clear banner, not a bare canvas.
  const [routingNotice, setRoutingNotice] =
    React.useState<{ reason: string | null; coverage: CallFlowCoverage | null } | null>(null);

  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const [focusId, setFocusId] = React.useState<string | null>(null);
  const [hiddenEdges, setHiddenEdges] = React.useState<Set<string>>(
    () => new Set<string>(DEFAULT_HIDDEN_EDGES),
  );
  const [muted, setMuted] = React.useState<Set<string>>(() => new Set<string>());
  const [hiddenNodes, setHiddenNodes] = React.useState<Set<string>>(() => new Set<string>());
  const [query, setQuery] = React.useState("");
  const [matchIds, setMatchIds] = React.useState<Set<string>>(() => new Set<string>());
  const [model, setModel] = React.useState<LayoutModel | null>(null);

  const canvas = React.useRef<CallFlowCanvasHandle>(null);
  const hasSource = (!!sessionId && !coldStart) || !!fileMode || (coldStart && !!siteId);

  const load = React.useCallback(() => {
    setErr(null);
    setNotAvailable(null);
    setRoutingNotice(null);
    if (!hasSource) { setGraph(null); return; }
    setLoading(true);
    const resolve = async () => {
      if (sessionId && !coldStart) return api.callflow(sessionId);
      if (fileMode) return api.snapshotCallflow(fileMode.siteId, fileMode.sid);
      // cold "latest": find the newest snapshot id for this site, then build.
      const snaps = await api.siteSnapshots(siteId);
      const sid = snaps.ok && snaps.snapshots?.length ? snaps.snapshots[0].sid : null;
      if (!sid) return { ok: false, available: false, reason: "No saved snapshot to read." };
      return api.snapshotCallflow(siteId, sid);
    };
    resolve()
      .then((res) => {
        if (!res.ok) { setErr(res.reason ?? "Could not build the call flow."); setGraph(null); return; }
        if (!res.available) { setNotAvailable(res.reason ?? "Routing programs not in this read."); setGraph(null); return; }
        setGraph(res.graph ?? null);
        // Available, but the entry points may not route anywhere in this read —
        // keep the diagram AND surface the reason as a banner above it.
        setRoutingNotice(
          res.routing_complete === false
            ? { reason: res.reason ?? null, coverage: res.coverage ?? null }
            : null,
        );
        setSelectedId(null);
        setFocusId(null);
      })
      .catch((e) => setErr((e as Error).message))
      .finally(() => setLoading(false));
  }, [hasSource, sessionId, coldStart, fileMode, siteId]);

  React.useEffect(() => { load(); }, [load]);

  // Node search: highlight matches (num / label / meta) and centre the first.
  React.useEffect(() => {
    const q = query.trim().toLowerCase();
    if (!q || !graph) { setMatchIds(new Set()); return; }
    const hits = graph.nodes.filter(
      (n) => n.num.toLowerCase().includes(q)
        || n.label.toLowerCase().includes(q)
        || n.meta.toLowerCase().includes(q),
    );
    setMatchIds(new Set(hits.map((n) => n.id)));
    if (hits[0]) requestAnimationFrame(() => canvas.current?.centreOn(hits[0].id));
  }, [query, graph]);

  const toggleEdge = (k: EdgeKind) =>
    setHiddenEdges((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k); else next.add(k);
      return next;
    });

  const entrypoints = React.useMemo(() => {
    if (!graph) return [];
    const by = new Map(graph.nodes.map((n) => [n.id, n]));
    return graph.entrypoints.map((id) => by.get(id)).filter((n): n is NonNullable<typeof n> => !!n);
  }, [graph]);

  // Which edge kinds / node kinds the graph actually uses (for a tight legend).
  const presentEdgeKinds = React.useMemo(() => {
    const s = new Set<EdgeKind>();
    graph?.edges.forEach((e) => s.add(e.kind));
    return [...s];
  }, [graph]);
  const presentNodeKinds = React.useMemo(() => {
    const s = new Set<NodeKind>();
    graph?.nodes.forEach((n) => s.add(n.kind));
    return [...s];
  }, [graph]);

  const header = (
    <PageHeader
      title="Call flow"
      subtitle="Inbound routing — DIDs and incoming line / trunk groups"
      actions={
        hasSource ? (
          <div className="flex items-center gap-1.5">
            <Button variant="outline" size="sm" onClick={() => canvas.current?.zoomBy(1.2)} title="Zoom in">
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" onClick={() => canvas.current?.zoomBy(1 / 1.2)} title="Zoom out">
              <ZoomOut className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" onClick={() => canvas.current?.fit()} title="Fit to window">
              <Maximize2 className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" onClick={load} disabled={loading} title="Rebuild">
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            </Button>
          </div>
        ) : null
      }
    />
  );

  let body: React.ReactNode;
  if (!hasSource) {
    body = <EmptyState message="Connect to a CIX (or open a snapshot) to map its inbound call routing." />;
  } else if (loading && !graph) {
    body = (
      <div className="flex h-full items-center justify-center gap-2 text-sm text-fg-2">
        <Loader2 className="h-4 w-4 animate-spin" /> Building the call flow…
      </div>
    );
  } else if (err) {
    body = <EmptyState message={err} />;
  } else if (notAvailable) {
    body = <EmptyState message={notAvailable} />;
  } else if (!graph || graph.nodes.length === 0) {
    body = <EmptyState message="No inbound routing found in this snapshot." />;
  } else {
    body = (
      <div className="flex min-h-0 flex-1">
        <div className="flex min-w-0 flex-1 flex-col">
          {/* toolbar: entrypoint picker + search + stats */}
          <div className="flex flex-wrap items-center gap-2 border-b border-border bg-surface px-3 py-2">
            <label className="flex items-center gap-1.5 text-xs text-fg-2">
              Start at
              <select
                className="h-7 rounded-md border border-border bg-surface px-2 text-xs"
                value={focusId ?? ""}
                onChange={(e) => {
                  const v = e.target.value || null;
                  setFocusId(v);
                  if (v) requestAnimationFrame(() => canvas.current?.centreOn(v));
                }}
              >
                <option value="">All entry points ({entrypoints.length})</option>
                {entrypoints.map((n) => (
                  <option key={n.id} value={n.id}>
                    {nodeKind(n.kind).label}: {n.num || n.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="flex items-center gap-1.5 rounded-md border border-border bg-surface px-2">
              <Search className="h-3.5 w-3.5 text-fg-3" />
              <input
                className="h-7 w-40 bg-transparent text-xs outline-none"
                placeholder="Find a node…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            <div className="ml-auto flex items-center gap-2 text-2xs text-fg-3">
              <span>{graph.stats.nodes} nodes · {graph.stats.edges} edges</span>
              {graph.stats.unresolved > 0 && (
                <span className="rounded bg-bad-tint px-1.5 py-0.5 font-semibold text-bad">
                  {graph.stats.unresolved} unresolved
                </span>
              )}
            </div>
          </div>

          {routingNotice && (
            <RoutingNotice
              reason={routingNotice.reason}
              coverage={routingNotice.coverage}
            />
          )}

          <div className="relative min-h-0 flex-1">
            <CallFlowCanvas
              ref={canvas}
              graph={graph}
              hiddenEdgeKinds={hiddenEdges}
              hiddenNodeIds={hiddenNodes}
              mutedNodeIds={muted}
              focusId={focusId}
              selectedId={selectedId}
              matchIds={matchIds}
              onSelect={(id) => setSelectedId((cur) => (cur === id ? null : id))}
              onLaidOut={setModel}
            />
            {/* legend / edge-kind filter, floating bottom-left */}
            <div className="absolute bottom-2 left-2 max-w-[60%] rounded-md border border-border bg-surface/95 p-2 text-2xs shadow-sm">
              <div className="mb-1 flex flex-wrap gap-x-3 gap-y-0.5">
                {presentNodeKinds.map((k) => (
                  <span key={k} className="flex items-center gap-1 text-fg-2">
                    <span className="h-2 w-2 rounded-sm" style={{ background: nodeKind(k).color }} />
                    {nodeKind(k).label}
                  </span>
                ))}
              </div>
              <div className="flex flex-wrap gap-1.5 border-t border-border pt-1">
                {presentEdgeKinds.map((k) => {
                  const off = hiddenEdges.has(k);
                  return (
                    <button
                      key={k}
                      type="button"
                      onClick={() => toggleEdge(k)}
                      className={`flex items-center gap-1 rounded px-1.5 py-0.5 ${off ? "opacity-40" : ""} hover:bg-surface-2`}
                      title={off ? "Hidden — click to show" : "Shown — click to hide"}
                    >
                      <span className="inline-block h-0.5 w-3 rounded" style={{ background: edgeKind(k).color }} />
                      {edgeKind(k).label}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <NodeInspector
          model={model}
          selectedId={selectedId}
          focusId={focusId}
          muted={muted}
          onSelect={setSelectedId}
          onToggleFocus={(id) => setFocusId((cur) => (cur === id ? null : id))}
          onMuteNode={(id) =>
            setMuted((prev) => {
              const next = new Set(prev);
              if (next.has(id)) next.delete(id); else next.add(id);
              return next;
            })
          }
          onHideNode={(id) => {
            setHiddenNodes((prev) => new Set(prev).add(id));
            setSelectedId(null);
          }}
        />
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

const COVERAGE_STATUS: Record<string, { label: string; cls: string }> = {
  present: { label: "read", cls: "bg-ok-tint text-fg-2" },
  empty: { label: "no rows", cls: "bg-warn-tint text-warn" },
  missing: { label: "not read", cls: "bg-bad-tint text-bad" },
};

// Shown above the canvas when entry points were drawn but nothing routes onward
// (an incomplete read, or a system whose inbound routing isn't in the SNMP
// tables). The diagram stays visible below — the entry points + their member
// ports are still useful — but the reason is no longer a mystery.
function RoutingNotice({
  reason, coverage,
}: {
  reason: string | null;
  coverage: CallFlowCoverage | null;
}) {
  const programs = coverage ? Object.entries(coverage.programs) : [];
  return (
    <div className="flex items-start gap-2 border-b border-warn/40 bg-warn-tint/60 px-3 py-2">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
      <div className="min-w-0 text-xs">
        <div className="font-semibold text-fg">Inbound routing isn’t drawn</div>
        {reason && <div className="mt-0.5 text-fg-2">{reason}</div>}
        {programs.length > 0 && (
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {programs.map(([num, p]) => {
              const s = COVERAGE_STATUS[p.status] ?? COVERAGE_STATUS.missing;
              return (
                <span
                  key={num}
                  className={`rounded px-1.5 py-0.5 text-2xs font-medium ${s.cls}`}
                  title={p.title}
                >
                  {num} · {s.label}
                </span>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
