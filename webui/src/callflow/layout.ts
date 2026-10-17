/**
 * Layered ("Sugiyama") graph layout — ported VERBATIM from callflow-map's
 * dependency-free layout.js (resources/js/Components/CallFlow/layout.js), typed
 * for TS. Deliberately no graph library.
 *
 * Four stages, all load-bearing:
 *   1. layer assignment    — longest path from the roots, cycles broken
 *   2. dummy chains        — a >1-layer edge gets a waypoint per column crossed
 *   3. crossing reduction  — median heuristic + adjacent transpose, best kept
 *   4. coordinate assignment — barycenter relaxation, re-pack, squeeze bands
 *
 * The one addition over the Vue original: `opts.nodeHeight(node)` gives a group
 * node a taller box sized to its port list (the contract's `ports` display).
 * `src`/`tgt` edge fields are consumed verbatim.
 */
import type {
  CallFlowGraph, CallFlowNode, LaidEdge, LaidNode, LayoutModel, LayoutOpts,
} from "./types";

export const NODE_W = 180;
export const NODE_H = 46;
export const H_GAP = 150;
export const V_GAP = 30;
const DUMMY_H = 10;

type WNode = LaidNode;
type WEdge = LaidEdge;

interface Item {
  id: string;
  real: boolean;
  node: WNode | null;
  layer: number;
  h: number;
  y: number;
  x: number;
  _m: number;
}

export function layout(graph: CallFlowGraph, opts: LayoutOpts = {}): LayoutModel {
  const hideN = opts.hiddenNodeKinds || new Set<string>();
  const hideE = opts.hiddenEdgeKinds || new Set<string>();
  const hideId = opts.hiddenNodeIds || new Set<string>();
  const muteId = opts.mutedNodeIds || new Set<string>();
  const pinned = opts.positions || new Map<string, { x: number; y: number }>();
  const focusId = opts.focusId || null;
  const nodeHeight = opts.nodeHeight || (() => NODE_H);

  let nodes: WNode[] = graph.nodes
    .filter((n) => !hideN.has(n.kind) && !hideId.has(n.id))
    .map((n) => ({ ...n, x: 0, y: 0, layer: 0, h: 0, ord: Infinity }));
  let byId = new Map<string, WNode>(nodes.map((n) => [n.id, n]));
  let edges: WEdge[] = graph.edges
    .filter((e) => !hideE.has(e.kind)
      && !muteId.has(e.src) && !muteId.has(e.tgt)
      && byId.has(e.src) && byId.has(e.tgt))
    .map((e) => ({
      ...e, waypoints: [], wp: [], pi: 0, pn: 1, li: 0, ln: 1, t0: 0.5,
      dupOf: null,
    }));

  if (focusId && byId.has(focusId)) {
    const fwd = new Map<string, string[]>();
    const rev = new Map<string, string[]>();
    for (const e of edges) {
      if (!fwd.has(e.src)) fwd.set(e.src, []);
      if (!rev.has(e.tgt)) rev.set(e.tgt, []);
      fwd.get(e.src)!.push(e.tgt);
      rev.get(e.tgt)!.push(e.src);
    }
    const reach = (m: Map<string, string[]>) => {
      const seen = new Set<string>([focusId]);
      const stack = [focusId];
      while (stack.length) {
        for (const next of m.get(stack.pop()!) || []) {
          if (!seen.has(next)) { seen.add(next); stack.push(next); }
        }
      }
      return seen;
    };
    const keep = new Set<string>([...reach(fwd), ...reach(rev)]);
    nodes = nodes.filter((n) => keep.has(n.id));
    edges = edges.filter((e) => keep.has(e.src) && keep.has(e.tgt));
    byId = new Map(nodes.map((n) => [n.id, n]));
  }

  // An unrouted entrypoint (DID or line/trunk group) is a finding worth
  // showing; anything else with no edges is noise.
  const ENTRY = new Set(["did", "trunk_group", "line_group"]);
  const touched = new Set<string>();
  edges.forEach((e) => { touched.add(e.src); touched.add(e.tgt); });
  nodes = nodes.filter((n) => touched.has(n.id) || ENTRY.has(n.kind) || muteId.has(n.id));
  byId = new Map(nodes.map((n) => [n.id, n]));
  edges = edges.filter((e) => byId.has(e.src) && byId.has(e.tgt));

  const out = new Map<string, WEdge[]>();
  const inc = new Map<string, WEdge[]>();
  nodes.forEach((n) => { out.set(n.id, []); inc.set(n.id, []); });
  edges.forEach((e) => { out.get(e.src)!.push(e); inc.get(e.tgt)!.push(e); });

  // ---- 1. layers -----------------------------------------------------------
  const depth = new Map<string, number>();
  const state = new Map<string, number>();
  const visit = (id: string, d: number) => {
    if (state.get(id) === 1) return;
    if (!depth.has(id) || depth.get(id)! < d) depth.set(id, d);
    else if (state.get(id) === 2) return;
    state.set(id, 1);
    for (const e of out.get(id)!) visit(e.tgt, depth.get(id)! + 1);
    state.set(id, 2);
  };
  nodes.filter((n) => inc.get(n.id)!.length === 0).forEach((n) => visit(n.id, 0));
  nodes.forEach((n) => { if (!depth.has(n.id)) visit(n.id, 0); });
  nodes.forEach((n) => { n.layer = depth.get(n.id) ?? 0; });

  // Order IVR targets by the digit that reaches them.
  nodes.forEach((n) => {
    const ords = (inc.get(n.id) || [])
      .filter((e) => e.kind === "option")
      .map((e) => pressOrder(e.label));
    n.ord = ords.length ? Math.min(...ords) : Infinity;
  });

  const L = nodes.reduce((m, n) => Math.max(m, n.layer), 0);
  const order: Item[][] = Array.from({ length: L + 1 }, () => [] as Item[]);
  const item = new Map<string, Item>();
  nodes.forEach((n) => {
    const h = nodeHeight(n);
    n.h = h;
    const it: Item = { id: n.id, real: true, node: n, layer: n.layer, h, y: 0, x: 0, _m: 0 };
    item.set(n.id, it);
    order[n.layer].push(it);
  });

  // ---- 2. dummy chains -----------------------------------------------------
  const seg: Array<[Item, Item]> = [];
  edges.forEach((e, ei) => {
    const a = item.get(e.src);
    const b = item.get(e.tgt);
    if (!a || !b) return;
    e.waypoints = [];
    if (b.layer > a.layer + 1) {
      let prev = a;
      for (let l = a.layer + 1; l < b.layer; l++) {
        const d: Item = { id: `d:${ei}:${l}`, real: false, node: null, layer: l, h: DUMMY_H, y: 0, x: 0, _m: 0 };
        item.set(d.id, d);
        order[l].push(d);
        e.waypoints.push(d.id);
        seg.push([prev, d]);
        prev = d;
      }
      seg.push([prev, b]);
    } else {
      seg.push([a, b]);
    }
  });

  const up = new Map<string, string[]>();
  const down = new Map<string, string[]>();
  seg.forEach(([u, v]) => {
    if (!down.has(u.id)) down.set(u.id, []);
    if (!up.has(v.id)) up.set(v.id, []);
    down.get(u.id)!.push(v.id);
    up.get(v.id)!.push(u.id);
  });

  // ---- 3. crossing reduction ----------------------------------------------
  const pos = new Map<string, number>();
  const reindex = () => order.forEach((row) => row.forEach((it, i) => pos.set(it.id, i)));
  order.forEach((row) => row.sort((x, y) => {
    if (x.real !== y.real) return x.real ? -1 : 1;
    if (!x.real) return 0;
    if (x.node!.ord !== y.node!.ord) return x.node!.ord - y.node!.ord;
    return x.node!.kind === y.node!.kind
      ? String(x.node!.num).localeCompare(String(y.node!.num))
      : x.node!.kind.localeCompare(y.node!.kind);
  }));
  reindex();

  const crossings = () => {
    let c = 0;
    for (let l = 0; l < L; l++) {
      const pairs: Array<[number, number]> = [];
      for (const u of order[l]) {
        for (const v of down.get(u.id) || []) pairs.push([pos.get(u.id)!, pos.get(v)!]);
      }
      for (let i = 0; i < pairs.length; i++) {
        for (let j = i + 1; j < pairs.length; j++) {
          if ((pairs[i][0] - pairs[j][0]) * (pairs[i][1] - pairs[j][1]) < 0) c++;
        }
      }
    }
    return c;
  };
  const median = (it: Item, side: "up" | "down") => {
    const nb = (side === "up" ? up : down).get(it.id) || [];
    const v = nb.map((x) => pos.get(x)).filter((x): x is number => x !== undefined)
      .sort((a, b) => a - b);
    if (!v.length) return -1;
    const m = v.length >> 1;
    return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
  };

  let best = order.map((r) => r.slice());
  let bestC = crossings();
  for (let pass = 0; pass < 8; pass++) {
    const side: "up" | "down" = pass % 2 ? "down" : "up";
    const idx = [...Array(L + 1).keys()];
    for (const l of side === "up" ? idx : idx.reverse()) {
      order[l].forEach((it) => { it._m = median(it, side); });
      order[l] = order[l]
        .map((it, i) => ({ it, i }))
        .sort((x, y) => {
          const a = x.it._m; const b = y.it._m;
          const tie = () => {
            const xo = x.it.real ? x.it.node!.ord : Infinity;
            const yo = y.it.real ? y.it.node!.ord : Infinity;
            return xo !== yo ? xo - yo : x.i - y.i;
          };
          if (a < 0 && b < 0) return tie();
          if (a < 0) return -1;
          if (b < 0) return 1;
          return a === b ? tie() : a - b;
        })
        .map((o) => o.it);
      reindex();
    }
    let improved = true;
    let guard = 0;
    while (improved && guard++ < 4) {
      improved = false;
      for (let l = 0; l <= L; l++) {
        for (let i = 0; i + 1 < order[l].length; i++) {
          const before = crossings();
          [order[l][i], order[l][i + 1]] = [order[l][i + 1], order[l][i]];
          reindex();
          if (crossings() < before) improved = true;
          else { [order[l][i], order[l][i + 1]] = [order[l][i + 1], order[l][i]]; reindex(); }
        }
      }
    }
    const c = crossings();
    if (c < bestC) { bestC = c; best = order.map((r) => r.slice()); }
  }
  for (let l = 0; l <= L; l++) order[l] = best[l];
  reindex();

  // Put IVR key presses back in dialed order within the slots they occupy.
  for (let l = 0; l <= L; l++) {
    const groups = new Map<string, number[]>();
    order[l].forEach((it, i) => {
      if (!it.real) return;
      const optsIn = (inc.get(it.id) || []).filter((e) => e.kind === "option");
      if (optsIn.length !== 1) return;
      const src = optsIn[0].src;
      if (!groups.has(src)) groups.set(src, []);
      groups.get(src)!.push(i);
    });
    groups.forEach((slots) => {
      if (slots.length < 2) return;
      const members = slots.map((i) => order[l][i]).sort((a, b) => a.node!.ord - b.node!.ord);
      slots.forEach((slot, k) => { order[l][slot] = members[k]; });
    });
  }
  reindex();

  // ---- 4. coordinates ------------------------------------------------------
  const gap = (p: Item, q: Item) => (p.real && q.real ? V_GAP : V_GAP * 0.35);
  order.forEach((row) => {
    let y = 28;
    row.forEach((it) => { it.y = y; y += it.h + V_GAP; });
  });
  const centre = (id: string) => { const o = item.get(id); return o ? o.y + o.h / 2 : null; };
  const want = (it: Item, side: "up" | "down") => {
    const v = ((side === "up" ? up : down).get(it.id) || []).map(centre)
      .filter((x): x is number => x !== null);
    return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
  };
  const repack = (row: Item[]) => {
    for (let i = 1; i < row.length; i++) {
      const lo = row[i - 1].y + row[i - 1].h + gap(row[i - 1], row[i]);
      if (row[i].y < lo) row[i].y = lo;
    }
    for (let i = row.length - 2; i >= 0; i--) {
      const hi = row[i + 1].y - row[i].h - gap(row[i], row[i + 1]);
      if (row[i].y > hi) row[i].y = hi;
    }
  };
  for (let pass = 0; pass < 10; pass++) {
    const side: "up" | "down" = pass % 2 ? "down" : "up";
    const idx = [...Array(L + 1).keys()];
    for (const l of side === "up" ? idx : idx.reverse()) {
      order[l].forEach((o) => { const t = want(o, side); if (t !== null) o.y = t - o.h / 2; });
      repack(order[l]);
    }
  }
  const all = order.flat();
  const minY = Math.min(...all.map((o) => o.y));
  all.forEach((o) => { o.y += 28 - minY; });

  // Squeeze out empty vertical bands.
  const MAX_GAP = V_GAP * 2;
  const byY = all.slice().sort((a, b) => a.y - b.y);
  const cuts: Array<{ from: number; amount: number }> = [];
  let prevEnd: number | null = null;
  for (const o of byY) {
    if (prevEnd !== null && o.y - prevEnd > MAX_GAP) {
      cuts.push({ from: o.y, amount: (o.y - prevEnd) - MAX_GAP });
    }
    prevEnd = prevEnd === null ? o.y + o.h : Math.max(prevEnd, o.y + o.h);
  }
  if (cuts.length) {
    all.forEach((o) => {
      let shift = 0;
      for (const c of cuts) if (o.y >= c.from) shift += c.amount;
      o.y -= shift;
    });
  }
  order.forEach((row, l) => row.forEach((it) => {
    it.x = l * (NODE_W + H_GAP) + 28;
    if (it.real && it.node) {
      const p = pinned.get(it.id);
      if (p) { it.x = p.x; it.y = p.y; }
      it.node.x = it.x;
      it.node.y = it.y;
      it.node.layer = l;
      it.node.h = it.h;
    }
  }));

  edges.forEach((e) => {
    e.wp = (e.waypoints || []).map((id) => {
      const d = item.get(id)!;
      return { x: d.x + NODE_W / 2, y: d.y + d.h / 2 };
    });
  });

  // fan parallel edges apart, and spread each source's labels along its curve
  const pair = new Map<string, WEdge[]>();
  edges.forEach((e) => {
    const k = `${e.src}>${e.tgt}`;
    if (!pair.has(k)) pair.set(k, []);
    pair.get(k)!.push(e);
  });
  pair.forEach((a) => a.forEach((e, i) => { e.pi = i; e.pn = a.length; }));
  const bySrc = new Map<string, WEdge[]>();
  edges.forEach((e) => {
    if (!bySrc.has(e.src)) bySrc.set(e.src, []);
    bySrc.get(e.src)!.push(e);
  });
  bySrc.forEach((a) => a.forEach((e, i) => { e.li = i; e.ln = a.length; }));

  // Anchor each label at the LESS CROWDED end of its edge.
  edges.forEach((e) => {
    const od = (out.get(e.src) || []).length;
    const id = (inc.get(e.tgt) || []).length;
    e.t0 = od > id ? 0.84 : (id > od ? 0.16 : 0.5);
  });

  // Dedupe many identical labels into one node.
  const sameLabel = new Map<string, WEdge[]>();
  edges.forEach((e) => {
    if (!e.label) return;
    const k = `${e.tgt}>${e.label}`;
    if (!sameLabel.has(k)) sameLabel.set(k, []);
    sameLabel.get(k)!.push(e);
  });
  sameLabel.forEach((group) => {
    if (group.length < 3) return;
    const keep = group[Math.floor(group.length / 2)];
    group.forEach((e) => { e.dupOf = e === keep ? null : keep; });
  });

  const boxes = all.map((o) => ({ x: o.x, y: o.y, w: NODE_W, h: o.h }));
  return {
    nodes,
    edges,
    byId: new Map(nodes.map((n) => [n.id, n])),
    out,
    inc,
    crossings: bestC,
    width: Math.max(400, Math.max(...boxes.map((b) => b.x + b.w)) + 40),
    height: Math.max(240, Math.max(...boxes.map((b) => b.y + b.h)) + 40),
  };
}

export interface EdgeGeom {
  d: string;
  back: boolean;
  poly: Array<{ x: number; y: number }>;
  t0: number;
}

/** Cubic path through an edge's waypoints; back edges bow out instead. */
export function edgeGeometry(a: LaidNode, b: LaidNode, e: LaidEdge): EdgeGeom {
  const off = e.pn > 1 ? (e.pi - (e.pn - 1) / 2) * 12 : 0;
  const p0 = { x: a.x + NODE_W, y: a.y + NODE_H / 2 + off };
  const p1 = { x: b.x, y: b.y + NODE_H / 2 + off };
  const jitter = e.ln > 1 ? (e.li / (e.ln - 1) - 0.5) * 0.12 : 0;
  const t0 = Math.min(0.9, Math.max(0.1, (e.t0 ?? 0.5) + jitter));

  if (b.layer <= a.layer || p1.x < p0.x + 24) {
    const bulge = Math.max(70, Math.abs(p1.y - p0.y) * 0.5) + Math.abs(off);
    return {
      d: `M${p0.x},${p0.y} C${p0.x + bulge},${p0.y} ${p1.x - bulge},${p1.y} ${p1.x},${p1.y}`,
      back: true,
      poly: [p0, { x: (p0.x + p1.x) / 2, y: (p0.y + p1.y) / 2 - Math.min(40, bulge / 2) }, p1],
      t0,
    };
  }

  const pts = [p0, ...(e.wp || []), p1];
  let d = `M${pts[0].x},${pts[0].y}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const A = pts[i]; const B = pts[i + 1]; const mx = (A.x + B.x) / 2;
    d += ` C${mx},${A.y} ${mx},${B.y} ${B.x},${B.y}`;
  }
  return { d, back: false, poly: pts, t0 };
}

/** Point a fraction along a polyline — seeds edge-label positions. */
export function pointAt(poly: Array<{ x: number; y: number }>, t: number) {
  if (!poly || poly.length < 2) return { x: 0, y: 0 };
  const segs: number[] = [];
  let total = 0;
  for (let i = 0; i < poly.length - 1; i++) {
    const len = Math.hypot(poly[i + 1].x - poly[i].x, poly[i + 1].y - poly[i].y) || 1e-6;
    segs.push(len);
    total += len;
  }
  let want = Math.max(0, Math.min(1, t)) * total;
  for (let i = 0; i < segs.length; i++) {
    if (want <= segs[i]) {
      const f = want / segs[i];
      return {
        x: poly[i].x + (poly[i + 1].x - poly[i].x) * f,
        y: poly[i].y + (poly[i + 1].y - poly[i].y) * f,
      };
    }
    want -= segs[i];
  }
  return poly[poly.length - 1];
}

/** Sort key for an IVR key press ("press 0".."press 9", then *, #, then rest). */
export function pressOrder(label: string | undefined | null): number {
  const m = /^press\s+(.+)$/.exec(String(label || "").trim());
  if (!m) return 900;
  const k = m[1].trim();
  if (/^\d+$/.test(k)) return Number(k);
  if (k === "*") return 100;
  if (k === "#") return 101;
  return 200;
}

const overlaps = (
  a: { x1: number; y1: number; x2: number; y2: number },
  b: { x1: number; y1: number; x2: number; y2: number },
) => !(a.x2 < b.x1 || b.x2 < a.x1 || a.y2 < b.y1 || b.y2 < a.y1);

export interface LabelCandidate {
  i: number;
  badge?: string | null;
  text: string;
  poly: Array<{ x: number; y: number }>;
  t0: number;
  colour?: string;
}
export interface PlacedLabel extends LabelCandidate {
  x: number;
  y: number;
}

/** Slide each label along its curve until it clears every box; drop if nothing fits. */
export function placeLabels(
  candidates: LabelCandidate[],
  nodeBoxes: Array<{ x1: number; y1: number; x2: number; y2: number }>,
): PlacedLabel[] {
  const placed: Array<{ x1: number; y1: number; x2: number; y2: number }> = [];
  const kept: PlacedLabel[] = [];
  const TS = [0, -0.12, 0.12, -0.22, 0.22, -0.32, 0.32];
  const DYS = [-9, 9, -20, 20, -31, 31];

  for (const c of candidates) {
    let got: { x: number; y: number; box: { x1: number; y1: number; x2: number; y2: number } } | null = null;
    for (const dt of TS) {
      const t = Math.min(0.88, Math.max(0.12, c.t0 + dt));
      const pt = pointAt(c.poly, t);
      for (const dy of DYS) {
        const w = c.badge ? 20 : c.text.length * 6.15 + 6;
        const h = c.badge ? 20 : 13;
        const box = { x1: pt.x - w / 2, y1: pt.y + dy - h / 2, x2: pt.x + w / 2, y2: pt.y + dy + h / 2 };
        if (nodeBoxes.some((n) => overlaps(box, n))) continue;
        if (placed.some((q) => overlaps(box, q))) continue;
        got = { x: pt.x, y: pt.y + dy, box };
        break;
      }
      if (got) break;
    }
    if (got) { placed.push(got.box); kept.push({ ...c, x: got.x, y: got.y }); }
  }
  return kept;
}

/** A group node's box height: header + one row per member port (min NODE_H). */
export const PORT_ROW_H = 16;
export const PORT_HEADER = 24;
export function groupNodeHeight(node: CallFlowNode): number {
  const ports = node.ports;
  if ((node.kind === "line_group" || node.kind === "trunk_group") && ports && ports.length) {
    return NODE_H + PORT_HEADER + ports.length * PORT_ROW_H + 8;
  }
  return NODE_H;
}
