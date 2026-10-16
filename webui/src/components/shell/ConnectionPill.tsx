import { Globe, Plug } from "lucide-react";
import { cn } from "@/lib/utils";
import { useStore } from "@/store/useStore";

// Site · transport · live identity (DESIGN_PLAN 2.3). DIRECT = accent tint,
// REMOTE = violet. The dot is reachability / read state.
export function ConnectionPill() {
  const { progress, identity, form, coldStart, setConnectDrawerOpen } = useStore(
    (s) => ({
      progress: s.progress,
      identity: s.identity,
      form: s.form,
      coldStart: s.coldStart,
      setConnectDrawerOpen: s.setConnectDrawerOpen,
    }),
  );

  const dot =
    progress.status === "error"
      ? "bg-bad"
      : progress.status === "reading" || progress.status === "connecting"
        ? "bg-warn"
        : progress.status === "done" || progress.status === "cold"
          ? "bg-ok"
          : "bg-fg-3";

  const remote = form.reach === "remote";
  const swid = identity?.software_id ?? identity?.swid ?? null;
  const connected = progress.status !== "idle";

  return (
    <button
      onClick={() => setConnectDrawerOpen(true)}
      className="flex min-w-0 items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-surface-2"
      title="Connection details"
    >
      <span className={cn("h-2 w-2 shrink-0 rounded-full", dot)} />
      {connected ? (
        <span className="flex min-w-0 items-center gap-2">
          {form.site && <span className="truncate font-medium">{form.site}</span>}
          {swid && <span className="truncate text-fg-2">{swid}</span>}
          {!coldStart && (
            <span
              className={cn(
                "flex items-center gap-1 rounded px-1.5 py-0.5 text-2xs font-semibold",
                remote ? "bg-remote-tint text-remote" : "bg-accent-tint text-primary",
              )}
            >
              {remote ? <Globe className="h-3 w-3" /> : <Plug className="h-3 w-3" />}
              {remote ? "REMOTE" : "DIRECT"}
            </span>
          )}
          {coldStart && (
            <span className="rounded bg-surface-2 px-1.5 py-0.5 text-2xs text-fg-2">
              SNAPSHOT
            </span>
          )}
          {form.ip && (
            <span className="truncate font-mono text-xs text-fg-2 tnum">{form.ip}</span>
          )}
        </span>
      ) : (
        <span className="text-fg-2">Not connected</span>
      )}
    </button>
  );
}
