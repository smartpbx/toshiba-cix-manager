import * as React from "react";
import {
  layout, edgeGeometry, placeLabels, pointAt, groupNodeHeight,
  NODE_W, NODE_H, PORT_HEADER, PORT_ROW_H,
} from "./layout";
import type { PlacedLabel } from "./layout";
import { nodeKind, edgeKind, QUIET_EDGES, SHORT_LABEL, keyBadge } from "./kinds";
import type {
  CallFlowGraph, LaidEdge, LaidNode, LayoutModel,
} from "./types";

/**
 * The graph canvas: pan, zoom, node drag, collision-avoided labels. A React
 * port of callflow-map's FlowCanvas.vue (SVG + imperative drag/pan/zoom). Group
 * nodes (line_group / trunk_group) render their member-port list inside a taller
 * box, so every port + equipment location shows on the diagram.
 *
 * Two notes carried from the Vue original:
 *  - Dragging mutates the dragged node's transform + only its edges in the DOM;
 *    a full re-render mid-drag kills the element holding pointer capture.
 *  - Panning is a transform on a wrapper <g>, so zoom can anchor on the cursor.
 */

export interface CallFlowCanvasProps {
  graph: CallFlowGraph;
  hiddenNodeKinds?: Set<string>;
  hiddenEdgeKinds?: Set<string>;
  hiddenNodeIds?: Set<string>;
  mutedNodeIds?: Set<string>;
  focusId?: string | null;
  selectedId?: string | null;
  matchIds?: Set<string>;
  onSelect?: (id: string) => void;
  onLaidOut?: (m: LayoutModel) => void;
}

export interface CallFlowCanvasHandle {
  fit: () => void;
  zoomBy: (f: number) => void;
  relayout: () => void;
  centreOn: (id: string, minZoom?: number) => void;
  model: () => LayoutModel;
}

const EMPTY = new Set<string>();

// Fit may zoom IN, not just out: a handful of nodes used to sit tiny in the
// middle of a big canvas because fit was clamped at 1×. Cap the zoom-in so a
// small graph fills the viewport without the boxes becoming cartoonishly large.
const FIT_MAX_ZOOM = 1.6;

export const CallFlowCanvas = React.forwardRef<CallFlowCanvasHandle, CallFlowCanvasProps>(
  function CallFlowCanvas(props, ref) {
    const {
      graph,
      hiddenNodeKinds = EMPTY,
      hiddenEdgeKinds = EMPTY,
      hiddenNodeIds = EMPTY,
      mutedNodeIds = EMPTY,
      focusId = null,
      selectedId = null,
      matchIds = EMPTY,
      onSelect,
      onLaidOut,
    } = props;

    const canvasRef = React.useRef<HTMLDivElement>(null);
    const svgRef = React.useRef<SVGSVGElement>(null);
    const view = React.useRef({ zoom: 1, tx: 0, ty: 0 });
    const pinned = React.useRef(new Map<string, { x: number; y: number }>());
    const [version, setVersion] = React.useState(0);
    const [panning, setPanning] = React.useState(false);

    const model = React.useMemo<LayoutModel>(
      () =>
        layout(graph, {
          hiddenNodeKinds, hiddenEdgeKinds, hiddenNodeIds, mutedNodeIds,
          focusId, positions: pinned.current, nodeHeight: groupNodeHeight,
        }),
      // version forces a recompute after a drag pins a node.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      [graph, hiddenNodeKinds, hiddenEdgeKinds, hiddenNodeIds, mutedNodeIds, focusId, version],
    );

    const geoms = React.useMemo(
      () =>
        model.edges.map((e) => ({
          e,
          g: edgeGeometry(model.byId.get(e.src)!, model.byId.get(e.tgt)!, e),
        })),
      [model],
    );

    const labels = React.useMemo<PlacedLabel[]>(() => {
      const seen = new Set<string>();
      const cands: Array<PlacedLabel | import("./layout").LabelCandidate> = [];
      geoms.forEach(({ e, g }, i) => {
        if (!e.label) return;
        const hot = !!selectedId && (e.src === selectedId || e.tgt === selectedId);
        if (!hot && QUIET_EDGES.has(e.kind)) return;
        if (!hot && e.dupOf) return;
        const key = `${e.src}>${e.tgt}>${e.label}`;
        if (!hot && seen.has(key)) return;
        seen.add(key);
        const badge = e.kind === "option" ? keyBadge(e.label) : null;
        if (badge) {
          cands.push({ i, badge, text: badge, poly: g.poly, t0: g.t0, colour: edgeKind(e.kind).color });
          return;
        }
        const text = SHORT_LABEL[e.label] || e.label;
        cands.push({ i, text: text.length > 30 ? `${text.slice(0, 29)}…` : text, poly: g.poly, t0: g.t0 });
      });
      const boxes = model.nodes.map((n) => ({
        x1: n.x - 3, y1: n.y - 3, x2: n.x + NODE_W + 3, y2: n.y + n.h + 3,
      }));
      return placeLabels(cands as import("./layout").LabelCandidate[], boxes);
    }, [geoms, model, selectedId]);

    const applyView = React.useCallback(() => {
      const vp = svgRef.current?.querySelector("#cfm-vp");
      if (vp) {
        vp.setAttribute(
          "transform",
          `translate(${view.current.tx},${view.current.ty}) scale(${view.current.zoom})`,
        );
      }
    }, []);

    const zoomAt = React.useCallback((z: number, sx: number, sy: number) => {
      const next = Math.min(4, Math.max(0.1, z));
      const wx = (sx - view.current.tx) / view.current.zoom;
      const wy = (sy - view.current.ty) / view.current.zoom;
      view.current.zoom = next;
      view.current.tx = sx - wx * next;
      view.current.ty = sy - wy * next;
      applyView();
    }, [applyView]);

    const fit = React.useCallback(() => {
      const c = canvasRef.current;
      if (!c) return;
      if (!c.clientWidth || !c.clientHeight) { requestAnimationFrame(fit); return; }
      const pad = 28;
      view.current.zoom = Math.max(0.1, Math.min(
        (c.clientWidth - pad * 2) / model.width,
        (c.clientHeight - pad * 2) / model.height,
        FIT_MAX_ZOOM,
      ));
      view.current.tx = (c.clientWidth - model.width * view.current.zoom) / 2;
      view.current.ty = Math.max(pad, (c.clientHeight - model.height * view.current.zoom) / 2);
      applyView();
    }, [model, applyView]);

    const zoomBy = React.useCallback((f: number) => {
      const c = canvasRef.current;
      if (c) zoomAt(view.current.zoom * f, c.clientWidth / 2, c.clientHeight / 2);
    }, [zoomAt]);

    const relayout = React.useCallback(() => {
      pinned.current = new Map();
      setVersion((v) => v + 1);
      requestAnimationFrame(fit);
    }, [fit]);

    const centreOn = React.useCallback((id: string, minZoom = 0.85) => {
      const n = model.byId.get(id);
      const c = canvasRef.current;
      if (!n || !c) return;
      if (view.current.zoom < minZoom) view.current.zoom = minZoom;
      view.current.tx = c.clientWidth / 2 - (n.x + NODE_W / 2) * view.current.zoom;
      view.current.ty = c.clientHeight / 2 - (n.y + n.h / 2) * view.current.zoom;
      applyView();
    }, [model, applyView]);

    React.useImperativeHandle(ref, () => ({ fit, zoomBy, relayout, centreOn, model: () => model }),
      [fit, zoomBy, relayout, centreOn, model]);

    // Fit whenever the model changes; notify the parent of the new model.
    React.useEffect(() => { requestAnimationFrame(fit); }, [fit]);
    React.useEffect(() => { onLaidOut?.(model); }, [model, onLaidOut]);
    React.useEffect(() => {
      const onResize = () => applyView();
      window.addEventListener("resize", onResize);
      return () => window.removeEventListener("resize", onResize);
    }, [applyView]);

    const onWheel = (ev: React.WheelEvent) => {
      ev.preventDefault();
      const r = canvasRef.current!.getBoundingClientRect();
      if (ev.shiftKey) { view.current.tx -= ev.deltaY; applyView(); return; }
      zoomAt(view.current.zoom * 0.999 ** ev.deltaY, ev.clientX - r.left, ev.clientY - r.top);
    };

    const pan = React.useRef<{
      kind: "node" | "view"; id?: string; sx: number; sy: number;
      ox: number; oy: number; moved: boolean; el?: Element | null;
    } | null>(null);

    const onPointerDown = (ev: React.PointerEvent) => {
      const nodeEl = (ev.target as Element).closest("[data-node]");
      if (nodeEl) {
        const n = model.byId.get((nodeEl as HTMLElement).dataset.node!);
        if (!n) return;
        ev.preventDefault();
        pan.current = { kind: "node", id: n.id, sx: ev.clientX, sy: ev.clientY, ox: n.x, oy: n.y, moved: false, el: nodeEl };
      } else {
        pan.current = { kind: "view", sx: ev.clientX, sy: ev.clientY, ox: view.current.tx, oy: view.current.ty, moved: false };
        setPanning(true);
      }
      svgRef.current!.setPointerCapture(ev.pointerId);
    };

    const onPointerMove = (ev: React.PointerEvent) => {
      const p = pan.current;
      if (!p) return;
      const dx = ev.clientX - p.sx;
      const dy = ev.clientY - p.sy;
      if (!p.moved && Math.abs(dx) + Math.abs(dy) < 4) return;
      p.moved = true;
      if (p.kind === "view") {
        view.current.tx = p.ox + dx; view.current.ty = p.oy + dy; applyView(); return;
      }
      const n = model.byId.get(p.id!)!;
      n.x = p.ox + dx / view.current.zoom;
      n.y = p.oy + dy / view.current.zoom;
      p.el?.setAttribute("transform", `translate(${n.x},${n.y})`);
      geoms.forEach(({ e }, i) => {
        if (e.src !== p.id && e.tgt !== p.id) return;
        const g = edgeGeometry(model.byId.get(e.src)!, model.byId.get(e.tgt)!, e);
        svgRef.current!.querySelector(`[data-edge="${i}"]`)?.setAttribute("d", g.d);
        const t = svgRef.current!.querySelector(`[data-label="${i}"]`);
        if (t) {
          const pt = pointAt(g.poly, g.t0);
          t.setAttribute("x", pt.x.toFixed(1));
          t.setAttribute("y", pt.y.toFixed(1));
        }
      });
    };

    const onPointerUp = (ev: React.PointerEvent) => {
      const p = pan.current;
      if (!p) return;
      pan.current = null;
      setPanning(false);
      try { svgRef.current!.releasePointerCapture(ev.pointerId); } catch { /* released */ }
      if (p.kind === "node") {
        if (p.moved) {
          const n = model.byId.get(p.id!)!;
          pinned.current.set(p.id!, { x: n.x, y: n.y });
        } else onSelect?.(p.id!);
      } else if (!p.moved && selectedId) onSelect?.(selectedId);
    };

    const dimmed = (id: string) => {
      if (matchIds.has(id)) return false;
      if (!selectedId || focusId) return false;
      if (id === selectedId) return false;
      return !(model.out.get(selectedId) || []).some((e) => e.tgt === id)
        && !(model.inc.get(selectedId) || []).some((e) => e.src === id);
    };
    const edgeDimmed = (e: LaidEdge) =>
      !!selectedId && !focusId && e.src !== selectedId && e.tgt !== selectedId;

    function edgeStroke(e: LaidEdge) {
      const hot = !!selectedId && (e.src === selectedId || e.tgt === selectedId);
      let width = hot ? 2.4 : 1.3;
      let opacity = 1;
      let dash: string | undefined;
      if (e.kind === "cf_off") { dash = "5 4"; opacity = 0.45; }
      else if (e.kind === "vm") { dash = "2 3"; opacity = 0.55; }
      else if (e.kind === "cf_on") width = Math.max(width, 2);
      return { stroke: edgeKind(e.kind).color, width, opacity, dash };
    }

    return (
      <div
        ref={canvasRef}
        className="relative h-full w-full overflow-hidden"
        style={{ width: "100%", height: "100%", touchAction: "none", cursor: panning ? "grabbing" : "grab", background: "#ffffff" }}
        onWheel={onWheel}
      >
        <svg
          ref={svgRef}
          className="block h-full w-full"
          style={{ display: "block", width: "100%", height: "100%" }}
          role="img"
          aria-label="Call flow graph"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={onPointerUp}
        >
          <defs>
            <marker id="cfm-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                    markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <polygon points="0,1 10,5 0,9" fill="#9ca3af" />
            </marker>
          </defs>

          <g id="cfm-vp">
            <g>
              {geoms.map(({ e, g }, i) => {
                const s = edgeStroke(e);
                return (
                  <path
                    key={`e${i}`}
                    data-edge={i}
                    d={g.d}
                    fill="none"
                    stroke={s.stroke}
                    strokeWidth={s.width}
                    strokeDasharray={g.back && !s.dash ? "5 4" : s.dash}
                    opacity={edgeDimmed(e) ? 0.16 : s.opacity}
                    markerEnd="url(#cfm-arrow)"
                  />
                );
              })}
            </g>

            <g>
              {model.nodes.map((n) => (
                <NodeGroup
                  key={n.id}
                  n={n}
                  selected={selectedId === n.id}
                  isFocus={focusId === n.id}
                  isMatch={matchIds.has(n.id)}
                  dim={dimmed(n.id)}
                  onSelect={onSelect}
                />
              ))}
            </g>

            <g style={{ pointerEvents: "none" }}>
              {labels.map((L) =>
                L.badge ? (
                  <g key={`l${L.i}`} data-label={L.i}>
                    <circle cx={L.x.toFixed(1)} cy={L.y.toFixed(1)} r={9}
                            fill="#ffffff" stroke={L.colour} strokeWidth={1.5} />
                    <text x={L.x.toFixed(1)} y={L.y.toFixed(1)} textAnchor="middle"
                          dominantBaseline="central"
                          fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                          fontSize={11} fontWeight={700} fill={L.colour}>{L.badge}</text>
                  </g>
                ) : (
                  <text
                    key={`l${L.i}`}
                    data-label={L.i}
                    x={L.x.toFixed(1)}
                    y={L.y.toFixed(1)}
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    fontSize={11}
                    fontWeight={600}
                    fill="#374151"
                    paintOrder="stroke"
                    stroke="#ffffff"
                    strokeWidth={4.5}
                    strokeLinejoin="round"
                  >{L.text}</text>
                ),
              )}
            </g>
          </g>
        </svg>
      </div>
    );
  },
);

function NodeGroup({
  n, selected, isFocus, isMatch, dim, onSelect,
}: {
  n: LaidNode;
  selected: boolean;
  isFocus: boolean;
  isMatch: boolean;
  dim: boolean;
  onSelect?: (id: string) => void;
}) {
  const kind = nodeKind(n.kind);
  const ports = (n.kind === "line_group" || n.kind === "trunk_group") ? n.ports ?? [] : [];
  return (
    <g
      data-node={n.id}
      transform={`translate(${n.x},${n.y})`}
      tabIndex={0}
      role="button"
      opacity={dim ? 0.16 : 1}
      aria-label={`${kind.label} ${n.num} ${n.label}`}
      onKeyDown={(ev) => {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); onSelect?.(n.id); }
      }}
    >
      {isFocus && (
        <rect x={-5} y={-5} width={NODE_W + 10} height={n.h + 10} rx={8}
              fill="none" stroke="#4f46e5" strokeWidth={1.5} strokeDasharray="4 3" />
      )}
      {isMatch && (
        <rect x={-4} y={-4} width={NODE_W + 8} height={n.h + 8} rx={8}
              fill="none" stroke="#d97706" strokeWidth={3} opacity={0.9} />
      )}
      <rect width={NODE_W} height={n.h} rx={5} fill="#ffffff"
            stroke={kind.color} strokeWidth={selected ? 3 : 1.5} />
      <rect width={4} height={n.h} rx={1.5} fill={kind.color} />
      <text x={13} y={19} fontSize={12} fontWeight={600} fill="#111827"
            fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace">
        {(n.num || kind.label).slice(0, 20)}
      </text>
      <text x={13} y={35} fontSize={11} fill="#6b7280">
        {(n.label || kind.label).slice(0, 25)}
      </text>
      {ports.length > 0 && (
        <>
          <line x1={8} y1={NODE_H} x2={NODE_W - 8} y2={NODE_H} stroke="#e5e7eb" strokeWidth={1} />
          <text x={13} y={NODE_H + 15} fontSize={9} fontWeight={700} fill="#9ca3af"
                letterSpacing="0.04em">
            {`MEMBER PORTS (${ports.length})`}
          </text>
          {ports.map((p, i) => {
            const y = NODE_H + PORT_HEADER + i * PORT_ROW_H;
            return (
              <g key={p.id}>
                <rect x={10} y={y} width={5} height={5} rx={1} fill={kind.color} opacity={0.7} />
                <text x={20} y={y + 5} fontSize={9.5} fill="#374151">
                  {p.label.slice(0, 20)}
                </text>
                <text x={NODE_W - 10} y={y + 5} fontSize={9.5} textAnchor="end" fill="#6b7280"
                      fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace">
                  {p.equipment || "—"}
                </text>
              </g>
            );
          })}
        </>
      )}
    </g>
  );
}
