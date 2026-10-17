import * as React from "react";
import { nodeKind, edgeKind } from "./kinds";
import { pressOrder } from "./layout";
import type { LaidEdge, LayoutModel } from "./types";

/**
 * Click-to-explore panel: every connection in and out of the selected node,
 * each clickable to walk the tree. A React port of callflow-map's
 * NodeInspector.vue, styled with the Switchroom theme tokens.
 */
export function NodeInspector({
  model, selectedId, focusId, muted, onSelect, onToggleFocus, onMuteNode, onHideNode,
}: {
  model: LayoutModel | null;
  selectedId: string | null;
  focusId: string | null;
  muted: Set<string>;
  onSelect: (id: string) => void;
  onToggleFocus: (id: string) => void;
  onMuteNode: (id: string) => void;
  onHideNode: (id: string) => void;
}) {
  const node = selectedId && model ? model.byId.get(selectedId) ?? null : null;

  const outgoing = React.useMemo<LaidEdge[]>(() => {
    if (!node || !model) return [];
    return [...(model.out.get(node.id) || [])].sort((a, b) => {
      const d = pressOrder(a.label) - pressOrder(b.label);
      return d !== 0 ? d : String(a.label).localeCompare(String(b.label));
    });
  }, [node, model]);
  const incoming = React.useMemo<LaidEdge[]>(
    () => (node && model ? model.inc.get(node.id) || [] : []),
    [node, model],
  );

  const peer = (e: LaidEdge, dir: "out" | "in") =>
    model?.byId.get(dir === "out" ? e.tgt : e.src);
  const describe = (e: LaidEdge) => e.label || edgeKind(e.kind).label;
  const isMuted = !!node && muted.has(node.id);

  return (
    <aside className="flex h-full w-72 shrink-0 flex-col overflow-y-auto border-l border-border bg-surface p-4">
      <h2 className="mb-3 text-2xs font-bold uppercase tracking-wide text-fg-3">Details</h2>

      {!node ? (
        <>
          <p className="text-sm text-fg-2">Select a node to explore it.</p>
          <p className="mt-4 border-t border-border pt-3 text-xs leading-relaxed text-fg-3">
            Scroll to zoom, drag the background to pan, drag a node to rearrange.
            Use the legend to show or hide connection types, or{" "}
            <strong className="font-semibold text-fg-2">Focus this path</strong> to
            narrow the view.
          </p>
        </>
      ) : (
        <>
          <span className="mb-2 inline-block w-fit rounded-full bg-accent-tint px-2 py-0.5 text-2xs font-semibold text-primary">
            {nodeKind(node.kind).label}
          </span>
          <p className="text-base font-bold leading-snug">{node.label || nodeKind(node.kind).label}</p>
          <p className="mb-3 font-mono text-sm font-semibold text-primary">{node.num || "—"}</p>

          {node.meta && (
            <p className="mb-4 rounded-md border border-border bg-surface-2 p-2 text-xs leading-relaxed text-fg-2">
              {node.meta}
            </p>
          )}

          {node.ports && node.ports.length > 0 && (
            <div className="mb-4">
              <h3 className="mb-1 text-2xs font-bold uppercase tracking-wide text-fg-3">
                Member ports ({node.ports.length})
              </h3>
              <ul className="list-none p-0">
                {node.ports.map((p) => (
                  <li key={p.id} className="flex items-baseline justify-between gap-2 border-t border-border py-1 text-xs">
                    <span className="min-w-0 flex-1 truncate">{p.label}</span>
                    <span className="shrink-0 rounded bg-surface-2 px-1 text-2xs text-fg-3">{p.type}</span>
                    <span className="shrink-0 font-mono text-2xs text-fg-2">{p.equipment || "—"}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="mb-4 flex flex-wrap gap-2">
            <button type="button"
              className="rounded-md border border-border bg-surface px-3 py-1.5 text-sm font-semibold text-fg-2 hover:bg-surface-2"
              onClick={() => onToggleFocus(node.id)}>
              {focusId === node.id ? "Clear focus" : "Focus this path"}
            </button>
            <button type="button" title="Keep this node but drop its connections"
              className="rounded-md border border-border bg-surface px-3 py-1.5 text-sm font-semibold text-fg-2 hover:bg-surface-2"
              onClick={() => onMuteNode(node.id)}>
              {isMuted ? "Show connections" : "Hide connections"}
            </button>
            <button type="button" title="Remove this node and its connections from the view"
              className="rounded-md border border-border bg-surface px-3 py-1.5 text-sm font-semibold text-fg-2 hover:bg-surface-2"
              onClick={() => onHideNode(node.id)}>
              Hide node
            </button>
          </div>

          <h2 className="mb-2 text-2xs font-bold uppercase tracking-wide text-fg-3">
            Routes to ({outgoing.length})
          </h2>
          {outgoing.length ? (
            <ul className="mb-4 list-none p-0">
              {outgoing.map((e, i) => (
                <li key={`o${i}`} className="flex items-baseline gap-2 border-t border-border py-2 text-sm">
                  <span className="max-w-36 shrink-0 font-mono text-2xs text-fg-3">{describe(e)}</span>
                  <button type="button" className="text-left font-semibold text-primary hover:underline"
                    onClick={() => onSelect(e.tgt)}>
                    {peer(e, "out")?.num} {peer(e, "out")?.label || nodeKind(peer(e, "out")?.kind || "unknown").label}
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mb-4 text-sm text-fg-3">Terminal — nothing onward.</p>
          )}

          <h2 className="mb-2 text-2xs font-bold uppercase tracking-wide text-fg-3">
            Reached from ({incoming.length})
          </h2>
          {incoming.length ? (
            <ul className="list-none p-0">
              {incoming.map((e, i) => (
                <li key={`i${i}`} className="flex items-baseline gap-2 border-t border-border py-2 text-sm">
                  <span className="max-w-36 shrink-0 font-mono text-2xs text-fg-3">{describe(e)}</span>
                  <button type="button" className="text-left font-semibold text-primary hover:underline"
                    onClick={() => onSelect(e.src)}>
                    {peer(e, "in")?.num} {peer(e, "in")?.label || nodeKind(peer(e, "in")?.kind || "unknown").label}
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-fg-3">Entry point — nothing routes here.</p>
          )}
        </>
      )}
    </aside>
  );
}
