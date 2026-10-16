import * as React from "react";
import {
  Download,
  FileSearch,
  Pin,
  PinOff,
  RefreshCw,
  Tag,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/PageHeader";
import { DiffPane } from "@/components/backup/DiffPane";
import { api } from "@/lib/api";
import type { AnnotatedDiffResult, SnapshotHeader } from "@/lib/types";
import { useStore } from "@/store/useStore";

const AUTO_KINDS = new Set([
  "auto-pre-write",
  "auto-post-write",
  "compare-live",
  "scheduled",
  "snapshot",
]);

function kindBadge(kind: string): { label: string; variant: "secondary" | "ok" | "warn" | "outline" } {
  if (kind === "named") return { label: "named", variant: "ok" };
  if (kind === "imported") return { label: "imported", variant: "outline" };
  if (kind.startsWith("auto")) return { label: "auto", variant: "secondary" };
  if (kind === "scheduled") return { label: "sched", variant: "secondary" };
  if (kind === "compare-live") return { label: "compare", variant: "secondary" };
  return { label: kind, variant: "secondary" };
}

function fmt(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

export function BackupsView() {
  const { siteId, sessionId, enterFileMode, openHome } = useStore((s) => ({
    siteId: s.siteId(),
    sessionId: s.sessionId,
    enterFileMode: s.enterFileMode,
    openHome: s.openHome,
  }));

  const [snaps, setSnaps] = React.useState<SnapshotHeader[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);
  const [selA, setSelA] = React.useState<string | null>(null);
  const [selB, setSelB] = React.useState<string | null>(null);
  const [hideAuto, setHideAuto] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [diff, setDiff] = React.useState<AnnotatedDiffResult | null>(null);
  const [diffLoading, setDiffLoading] = React.useState(false);
  const [showRO, setShowRO] = React.useState(false);
  const [showVol, setShowVol] = React.useState(false);

  const reload = React.useCallback(async () => {
    if (!siteId) return;
    setLoading(true);
    setErr(null);
    try {
      const res = await api.siteSnapshots(siteId);
      setSnaps(res.ok ? res.snapshots : []);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [siteId]);

  React.useEffect(() => {
    void reload();
  }, [reload]);

  const runDiff = React.useCallback(async () => {
    if (!siteId || !selA || !selB || selA === selB) {
      setDiff(null);
      return;
    }
    setDiffLoading(true);
    try {
      const res = await api.diffReview({
        a: { site: siteId, snapshot: selA },
        b: { site: siteId, snapshot: selB },
        all: showRO,
        volatile: showVol,
      });
      setDiff(res);
    } catch (e) {
      setDiff({ ok: false, error: (e as Error).message });
    } finally {
      setDiffLoading(false);
    }
  }, [siteId, selA, selB, showRO, showVol]);

  React.useEffect(() => {
    void runDiff();
  }, [runDiff]);

  const visible = snaps.filter((s) => !(hideAuto && AUTO_KINDS.has(s.kind)));

  const take = async (name?: string) => {
    if (!siteId || !sessionId) return;
    setBusy(true);
    try {
      await api.takeSnapshot(siteId, { session: sessionId, scope: "all", name });
      await reload();
    } finally {
      setBusy(false);
    }
  };

  const compareLive = async () => {
    if (!siteId || !sessionId || !selA) return;
    setDiffLoading(true);
    try {
      const res = await api.compareLive(siteId, {
        snapshot: selA,
        session: sessionId,
        all: showRO,
        volatile: showVol,
      });
      setDiff(res);
      await reload();
    } catch (e) {
      setDiff({ ok: false, error: (e as Error).message });
    } finally {
      setDiffLoading(false);
    }
  };

  const patch = async (h: SnapshotHeader, body: Parameters<typeof api.patchSnapshot>[2]) => {
    if (!siteId) return;
    await api.patchSnapshot(siteId, h.sid, body);
    await reload();
  };

  const del = async (h: SnapshotHeader) => {
    if (!siteId) return;
    const res = await api.deleteSnapshot(siteId, h.sid);
    if (!res.ok && res.reason) {
      if (window.confirm(`This snapshot is ${res.reason}. Delete it anyway?`)) {
        await api.deleteSnapshot(siteId, h.sid, true);
      }
    }
    if (selA === h.sid) setSelA(null);
    if (selB === h.sid) setSelB(null);
    await reload();
  };

  const open = async (h: SnapshotHeader) => {
    if (!siteId) return;
    if (await enterFileMode(siteId, h)) openHome();
  };

  const exportSnap = (h: SnapshotHeader) => {
    if (!siteId) return;
    window.open(api.exportUrl(siteId, h.sid), "_blank");
  };

  const doExport = async (format: "markdown" | "csv" | "text" | "json") => {
    if (!siteId || !selA || !selB) return;
    const res = await fetch("/api/diff/review", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        a: { site: siteId, snapshot: selA },
        b: { site: siteId, snapshot: selB },
        all: showRO,
        volatile: showVol,
        export: format,
      }),
    });
    const text = await res.text();
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };

  if (!siteId) {
    return (
      <EmptyState message="Connect to a switch (or open a site) to see its backup history." />
    );
  }

  return (
    <div className="flex h-full min-h-0">
      {/* timeline (left) */}
      <aside className="flex w-[22rem] shrink-0 flex-col border-r border-border bg-surface">
        <div className="flex items-center gap-2 border-b border-border px-3 py-2">
          <span className="truncate text-sm font-semibold">Backups · {siteId}</span>
          <Button
            size="sm"
            variant="ghost"
            className="ml-auto"
            onClick={() => void reload()}
            title="Reload the timeline"
          >
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
          </Button>
        </div>
        <div className="flex items-center gap-2 border-b border-border px-3 py-1.5 text-xs">
          <Button
            size="sm"
            disabled={!sessionId || busy}
            onClick={() => void take()}
            title={sessionId ? "Take a snapshot now" : "Connect first"}
          >
            New snapshot
          </Button>
          <label className="ml-auto flex items-center gap-1 text-fg-2">
            <input type="checkbox" checked={hideAuto} onChange={(e) => setHideAuto(e.target.checked)} />
            hide auto
          </label>
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {err && <div className="p-3 text-xs text-bad">{err}</div>}
          {!loading && visible.length === 0 && (
            <div className="p-4 text-xs text-fg-3">No snapshots yet.</div>
          )}
          {visible.map((h) => {
            const kb = kindBadge(h.kind);
            const isA = selA === h.sid;
            const isB = selB === h.sid;
            return (
              <div
                key={h.sid}
                className="group border-b border-border/60 px-3 py-2 text-sm hover:bg-surface-2"
              >
                <div className="flex items-center gap-2">
                  <span className="text-fg-2">{fmt(h.saved_at)}</span>
                  <Badge variant={kb.variant}>{kb.label}</Badge>
                  {h.pinned && <Pin className="h-3 w-3 text-primary" />}
                  {h.dedupe_of && (
                    <span className="text-2xs text-fg-3" title="Unchanged — deduped">
                      unchanged
                    </span>
                  )}
                  <div className="ml-auto flex gap-1">
                    <button
                      onClick={() => setSelA(isA ? null : h.sid)}
                      className={
                        "rounded border px-1.5 text-2xs " +
                        (isA ? "border-primary bg-primary text-primary-foreground" : "border-border text-fg-2")
                      }
                      title="Compare: A (older)"
                    >
                      A
                    </button>
                    <button
                      onClick={() => setSelB(isB ? null : h.sid)}
                      className={
                        "rounded border px-1.5 text-2xs " +
                        (isB ? "border-primary bg-primary text-primary-foreground" : "border-border text-fg-2")
                      }
                      title="Compare: B (newer)"
                    >
                      B
                    </button>
                  </div>
                </div>
                {(h.name || h.label) && (
                  <div className="mt-0.5 truncate font-medium">{h.name || h.label}</div>
                )}
                <div className="mt-0.5 flex items-center gap-2 text-2xs text-fg-3">
                  <span>{h.counts?.rows ?? "?"} rows</span>
                  {h.swid && <span className="truncate">· {h.swid}</span>}
                </div>
                <div className="mt-1 hidden items-center gap-1 group-hover:flex">
                  <IconBtn title="Open in file mode" onClick={() => void open(h)}>
                    <FileSearch className="h-3.5 w-3.5" />
                  </IconBtn>
                  <IconBtn
                    title={h.pinned ? "Unpin" : "Pin (never pruned)"}
                    onClick={() => void patch(h, { pinned: !h.pinned })}
                  >
                    {h.pinned ? <PinOff className="h-3.5 w-3.5" /> : <Pin className="h-3.5 w-3.5" />}
                  </IconBtn>
                  <IconBtn
                    title="Name…"
                    onClick={() => {
                      const name = window.prompt("Name this snapshot", h.name || h.label || "");
                      if (name != null) void patch(h, { name });
                    }}
                  >
                    <Tag className="h-3.5 w-3.5" />
                  </IconBtn>
                  <IconBtn title="Export (redacted .cixbak)" onClick={() => exportSnap(h)}>
                    <Download className="h-3.5 w-3.5" />
                  </IconBtn>
                  <IconBtn title="Delete" onClick={() => void del(h)}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </IconBtn>
                </div>
              </div>
            );
          })}
        </div>
      </aside>

      {/* right pane: view / diff */}
      <section className="flex min-w-0 flex-1 flex-col">
        {selA && selB && selA !== selB ? (
          diff && diff.ok && diff.annotated ? (
            <DiffPane
              annotated={diff.annotated}
              showReadonly={showRO}
              showVolatile={showVol}
              onToggleReadonly={setShowRO}
              onToggleVolatile={setShowVol}
              onExport={doExport}
              loading={diffLoading}
            />
          ) : (
            <div className="p-6 text-sm text-fg-2">
              {diffLoading ? "Comparing…" : diff?.error ? `Diff failed: ${diff.error}` : "Select two snapshots."}
            </div>
          )
        ) : (
          <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center text-sm text-fg-2">
            <p>
              Pick <strong>A</strong> and <strong>B</strong> to diff two snapshots, or open one in
              file mode to browse it through the program pages.
            </p>
            {selA && (
              <Button
                variant="outline"
                size="sm"
                disabled={!sessionId || diffLoading}
                onClick={() => void compareLive()}
                title={sessionId ? "Read the switch now and diff A against it" : "Connect first"}
              >
                Compare A with live
              </Button>
            )}
            {diff && diff.ok && diff.annotated && (
              <div className="mt-4 w-full max-w-3xl text-left">
                <DiffPane
                  annotated={diff.annotated}
                  showReadonly={showRO}
                  showVolatile={showVol}
                  onToggleReadonly={setShowRO}
                  onToggleVolatile={setShowVol}
                  loading={diffLoading}
                />
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

function IconBtn({
  title,
  onClick,
  children,
}: {
  title: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      title={title}
      onClick={onClick}
      className="rounded border border-border p-1 text-fg-2 hover:bg-surface-2"
    >
      {children}
    </button>
  );
}
