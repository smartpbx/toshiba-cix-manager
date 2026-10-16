import { Globe, Plug } from "lucide-react";
import { cn } from "@/lib/utils";
import { useStore } from "@/store/useStore";

// DIRECT vs REMOTE must be unmistakable (ui.md §1.2): DIRECT = accent tint,
// REMOTE = violet tint. The dot is reachability.
export function ConnectionPill() {
  const { connState, identity, form, setView } = useStore((s) => ({
    connState: s.connState,
    identity: s.identity,
    form: s.form,
    setView: s.setView,
  }));

  const connected = connState === "ok" || connState === "reading";
  const dot =
    connState === "error"
      ? "bg-bad"
      : connState === "reading" || connState === "testing"
        ? "bg-warn"
        : connected
          ? "bg-ok"
          : "bg-fg-3";

  const remote = form.reach === "remote";

  return (
    <button
      onClick={() => setView("connect")}
      className="flex min-w-0 items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-surface-2"
      title="Connection details"
    >
      <span className={cn("h-2 w-2 shrink-0 rounded-full", dot)} />
      {connected && identity ? (
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate font-medium">{identity.software_id}</span>
          <span
            className={cn(
              "flex items-center gap-1 rounded px-1.5 py-0.5 text-2xs font-semibold",
              remote
                ? "bg-remote-tint text-remote"
                : "bg-accent-tint text-primary",
            )}
          >
            {remote ? <Globe className="h-3 w-3" /> : <Plug className="h-3 w-3" />}
            {remote ? "REMOTE" : "DIRECT"}
          </span>
          <span className="truncate font-mono text-xs text-fg-2 tnum">
            {form.ip}
          </span>
        </span>
      ) : (
        <span className="text-fg-2">Not connected</span>
      )}
    </button>
  );
}
