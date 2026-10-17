/**
 * Dev / QA harness for the Call Flow renderer — NOT part of the shipped
 * webui.html (the main build only bundles index.html → main.tsx → App). It
 * mounts the ported CallFlowCanvas against the three frozen contract fixtures
 * (callflow-port/contract/fixtures) so the renderer can be validated (lays out
 * + draws without error) and screenshotted offline, with no backend.
 *
 * Pick a fixture with the URL hash: #a | #b | #c (default #b, the owner's
 * analog-line-group-with-ports case). Built via vite.demo.config.ts.
 */
import * as React from "react";
import { createRoot } from "react-dom/client";
import { CallFlowCanvas } from "./CallFlowCanvas";
import type { CallFlowCanvasHandle } from "./CallFlowCanvas";
import type { CallFlowGraph, LayoutModel } from "./types";
import a from "./__fixtures__/a_did_ivr.json";
import b from "./__fixtures__/b_analog_line_group.json";
import c from "./__fixtures__/c_day_night_vm_fallback.json";

const FIXTURES: Record<string, { title: string; graph: CallFlowGraph }> = {
  a: { title: "a — DID → auto-attendant (IVR keys, unresolved option)", graph: a as unknown as CallFlowGraph },
  b: { title: "b — analog line group with member ports (day/night)", graph: b as unknown as CallFlowGraph },
  c: { title: "c — trunk group day/night + no-answer → VM fallback", graph: c as unknown as CallFlowGraph },
};

function Demo() {
  const [key, setKey] = React.useState<string>(
    () => (location.hash.replace("#", "") in FIXTURES ? location.hash.replace("#", "") : "b"),
  );
  const [selected, setSelected] = React.useState<string | null>(null);
  const canvas = React.useRef<CallFlowCanvasHandle>(null);
  const [, setModel] = React.useState<LayoutModel | null>(null);
  const fx = FIXTURES[key];

  React.useEffect(() => {
    const onHash = () => {
      const k = location.hash.replace("#", "");
      if (k in FIXTURES) setKey(k);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", width: "100vw", fontFamily: "system-ui, sans-serif" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 14px", borderBottom: "1px solid #e5e7eb", background: "#f9fafb" }}>
        <strong style={{ fontSize: 14 }}>Call flow renderer — fixture</strong>
        {Object.keys(FIXTURES).map((k) => (
          <button key={k} onClick={() => { location.hash = k; setKey(k); }}
            style={{ padding: "4px 10px", borderRadius: 6, border: "1px solid #d1d5db", background: k === key ? "#0f766e" : "#fff", color: k === key ? "#fff" : "#111", cursor: "pointer" }}>
            {k}
          </button>
        ))}
        <span style={{ fontSize: 12, color: "#6b7280" }}>{fx.title}</span>
        <span style={{ marginLeft: "auto", fontSize: 12, color: "#6b7280" }}>
          {fx.graph.stats.nodes} nodes · {fx.graph.stats.edges} edges · {fx.graph.stats.unresolved} unresolved
        </span>
      </div>
      <div style={{ flex: 1, minHeight: 0, height: "calc(100vh - 47px)", width: "100vw" }}>
        <CallFlowCanvas
          ref={canvas}
          key={key}
          graph={fx.graph}
          selectedId={selected}
          onSelect={(id) => setSelected((cur) => (cur === id ? null : id))}
          onLaidOut={setModel}
        />
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<Demo />);
