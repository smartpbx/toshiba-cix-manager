/**
 * Node and connection taxonomy + colours.  Ported from callflow-map's kinds.js,
 * with the labels/colours of the FROZEN contract (callflow-port/contract/
 * callflow.ts §NODE_KINDS/EDGE_KINDS) so Switchroom speaks the same language as
 * the adapter and the Mitel port.
 *
 * Colours are a light-only palette by design (the diagram canvas is a white
 * board in both app themes, like every other config diagram tool).
 */
import type { NodeKind, EdgeKind } from "./types";

export const NODE_KINDS: Record<NodeKind, { label: string; color: string }> = {
  did:         { label: "DID",                  color: "#374151" },
  trunk_group: { label: "Trunk group",          color: "#334155" },
  line_group:  { label: "Line group (analog)",  color: "#0f766e" },
  ivr_menu:    { label: "Virtual receptionist", color: "#0284c7" },
  time_switch: { label: "Time / mode switch",   color: "#d97706" },
  ring_group:  { label: "Ring group",           color: "#7c3aed" },
  queue:       { label: "Queue",                color: "#7c3aed" },
  extension:   { label: "Extension",            color: "#059669" },
  attendant:   { label: "Attendant",            color: "#0891b2" },
  voicemail:   { label: "Voicemail",            color: "#e11d48" },
  fax:         { label: "Fax",                  color: "#6b7280" },
  conference:  { label: "Conference",           color: "#6b7280" },
  recording:   { label: "Greeting",             color: "#6b7280" },
  external:    { label: "External number",      color: "#9ca3af" },
  feature:     { label: "Feature code",         color: "#9ca3af" },
  hangup:      { label: "Hang up",              color: "#9ca3af" },
  unknown:     { label: "Unresolved",           color: "#dc2626" },
};

export const EDGE_KINDS: Record<EdgeKind, { label: string; color: string }> = {
  route:   { label: "Route",          color: "#9ca3af" },
  option:  { label: "IVR key",        color: "#0284c7" },
  member:  { label: "Group member",   color: "#9ca3af" },
  open:    { label: "Open hours",     color: "#059669" },
  closed:  { label: "Closed hours",   color: "#d97706" },
  always:  { label: "Always (24/7)",  color: "#4f46e5" },
  cf_on:   { label: "Active leg",     color: "#4f46e5" },
  cf_off:  { label: "Inactive leg",   color: "#9ca3af" },
  timeout: { label: "Timeout / exit", color: "#d97706" },
  fwd:     { label: "Call forward",   color: "#7c3aed" },
  ring_key:{ label: "Rings on CO line", color: "#0d9488" },
  vm:      { label: "Mailbox link",   color: "#e11d48" },
};

export const nodeKind = (k: string) =>
  NODE_KINDS[k as NodeKind] ?? NODE_KINDS.unknown;
export const edgeKind = (k: string) =>
  EDGE_KINDS[k as EdgeKind] ?? EDGE_KINDS.route;

/** "rings" adds nothing beside the colour + legend, so it stays hidden until selected.
 *  ring_key edges draw by default (they ARE the routing on key systems) but their
 *  repeated "rings" label is suppressed the same way — the teal colour + legend say it. */
export const QUIET_EDGES = new Set<string>(["member", "ring_key"]);

/** Shorter on canvas; the inspector still shows the full text. */
export const SHORT_LABEL: Record<string, string> = { "timeout / invalid": "timeout" };

/** An IVR key draws as a circled digit, not the words "press 3". */
export function keyBadge(label: string | undefined | null): string | null {
  const m = /^press\s+(\S+)$/.exec(String(label || "").trim());
  return m ? m[1] : null;
}

/** One mailbox edge per extension is noise, so this layer starts off. */
export const DEFAULT_HIDDEN_EDGES: EdgeKind[] = ["vm"];

/** Connection kinds that only ever touch one node kind (partial-legend logic). */
export const EDGE_KINDS_BY_NODE: Record<string, EdgeKind[]> = { voicemail: ["vm"] };
