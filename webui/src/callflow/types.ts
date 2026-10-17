/**
 * Call Flow — neutral graph contract types.  [FROZEN v1.0.0 — 2026-10-17]
 *
 * Mirrors callflow-port/contract/callflow.ts. The Python adapter PRODUCES this
 * shape and the React renderer CONSUMES it. Edge source/target fields are
 * `src`/`tgt` VERBATIM so the ported layout engine needs no edits.
 */

export type NodeKind =
  | "did"
  | "trunk_group"
  | "line_group"
  | "ivr_menu"
  | "time_switch"
  | "ring_group"
  | "queue"
  | "extension"
  | "attendant"
  | "voicemail"
  | "fax"
  | "conference"
  | "recording"
  | "external"
  | "feature"
  | "hangup"
  | "unknown";

export type EntrypointKind = "did" | "trunk_group" | "line_group";

export type EdgeKind =
  | "route"
  | "option"
  | "member"
  | "open"
  | "closed"
  | "always"
  | "cf_on"
  | "cf_off"
  | "timeout"
  | "fwd"
  | "vm";

export type Condition =
  | "day" | "day2" | "night" | "holiday" | "open" | "closed" | "always"
  | "no_answer" | "busy" | "busy_no_answer" | "dnd" | "not_registered"
  | "timeout" | "overflow" | "invalid"
  | "immediate" | "delay1" | "delay2"
  | "forward";

export type PortType =
  | "loop_start" | "ground_start" | "e_and_m"
  | "t1" | "pri" | "bri" | "isdn" | "sip"
  | "did" | "analog_co" | "digital" | "unknown";

export interface PortMember {
  id: string;
  label: string;
  equipment: string;
  type: PortType;
}

export interface CallFlowNode {
  id: string;
  kind: NodeKind;
  num: string;
  label: string;
  meta: string;
  ports?: PortMember[];
}

export interface CallFlowEdge {
  src: string;
  tgt: string;
  kind: EdgeKind;
  label: string;
  condition?: Condition | null;
}

export interface CallFlowStats {
  nodes: number;
  edges: number;
  unresolved: number;
}

export interface CallFlowGraph {
  version?: string;
  entrypoints: string[];
  nodes: CallFlowNode[];
  edges: CallFlowEdge[];
  stats: CallFlowStats;
}

/** Read coverage of one inbound-routing program (envelope metadata). */
export interface RoutingProgramStatus {
  title: string;
  /** "present" = has rows, "empty" = read but no rows, "missing" = not read. */
  status: "present" | "empty" | "missing";
}

/** Envelope metadata: which routing tables the read covered, and how many
 * answer points are actually programmed (a non-"no data" destination). */
export interface CallFlowCoverage {
  programs: Record<string, RoutingProgramStatus>;
  answer_points_programmed: number;
}

/** The callflow endpoint envelope the engine returns. The `graph` stays the
 * FROZEN v1.0.0 contract; everything that explains an empty/partial diagram
 * rides here on the envelope, never inside the graph. */
export interface CallFlowResult {
  ok: boolean;
  available: boolean;
  /** False when entry points exist but no onward routing could be drawn. */
  routing_complete?: boolean;
  reason?: string | null;
  coverage?: CallFlowCoverage | null;
  graph?: CallFlowGraph | null;
}

/* ---- layout-internal shapes (fields the layout engine adds in place) ---- */

export interface LaidNode extends CallFlowNode {
  x: number;
  y: number;
  layer: number;
  h: number;
  ord: number;
}

export interface LaidEdge extends CallFlowEdge {
  waypoints: string[];
  wp: Array<{ x: number; y: number }>;
  pi: number;
  pn: number;
  li: number;
  ln: number;
  t0: number;
  dupOf: LaidEdge | null;
}

export interface LayoutModel {
  nodes: LaidNode[];
  edges: LaidEdge[];
  byId: Map<string, LaidNode>;
  out: Map<string, LaidEdge[]>;
  inc: Map<string, LaidEdge[]>;
  crossings: number;
  width: number;
  height: number;
}

export interface LayoutOpts {
  hiddenNodeKinds?: Set<string>;
  hiddenEdgeKinds?: Set<string>;
  hiddenNodeIds?: Set<string>;
  mutedNodeIds?: Set<string>;
  focusId?: string | null;
  positions?: Map<string, { x: number; y: number }>;
  /** Per-node box height (group nodes get taller boxes for their port list). */
  nodeHeight?: (node: CallFlowNode) => number;
}
