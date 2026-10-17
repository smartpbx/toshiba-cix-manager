import * as React from "react";
import type { LucideIcon } from "lucide-react";
import { api } from "@/lib/api";
import { navIcon } from "@/components/shell/navIcons";
import type { SchemaProgram } from "@/lib/schema";
import type { SnapshotHeader } from "@/lib/types";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

// A "common job" card: a 34px accent tile + plain-English title + description +
// a mono program/area reference. Each opens the relevant program (or Backups).
interface Job {
  icon: string;
  title: string;
  desc: string;
  ref: string;
  onClick: () => void;
}

export function HomeView() {
  const {
    schema,
    identity,
    meta,
    readCount,
    rowCounts,
    programStatus,
    progress,
    form,
    coldStart,
    hasSnapshot,
    openProgram,
    openBackups,
    openCallFlow,
    setConnectDrawerOpen,
    siteId,
  } = useStore(
    useShallow((s) => ({
      schema: s.schema,
      identity: s.identity,
      meta: s.snapshotMeta,
      readCount: s.readKeys.size,
      rowCounts: s.rowCounts,
      programStatus: s.programStatus,
      progress: s.progress,
      form: s.form,
      coldStart: s.coldStart,
      hasSnapshot:
        s.progress.status === "done" || s.progress.status === "cold" || s.readKeys.size > 0,
      openProgram: s.openProgram,
      openBackups: s.openBackups,
      openCallFlow: s.openCallFlow,
      setConnectDrawerOpen: s.setConnectDrawerOpen,
      siteId: s.siteId(),
    })),
  );

  const byNumber = React.useMemo(() => {
    const m = new Map<string, SchemaProgram>();
    if (schema) {
      for (const p of Object.values(schema.programs)) {
        if (p.program_number) m.set(p.program_number, p);
      }
    }
    return m;
  }, [schema]);

  const count = (num: string) => {
    const p = byNumber.get(num);
    return p ? rowCounts[p.catalog_key] ?? 0 : 0;
  };
  const openNum = (num: string) => {
    const p = byNumber.get(num);
    if (p) openProgram(p.catalog_key, p.label);
  };

  const [snaps, setSnaps] = React.useState<SnapshotHeader[] | null>(null);
  React.useEffect(() => {
    let live = true;
    if (!siteId) {
      setSnaps([]);
      return;
    }
    void api
      .siteSnapshots(siteId)
      .then((r) => {
        if (live) setSnaps(r.ok ? r.snapshots ?? [] : []);
      })
      .catch(() => {
        if (live) setSnaps([]);
      });
    return () => {
      live = false;
    };
  }, [siteId]);

  const total = schema?.counts?.programs ?? 186;
  const failed = React.useMemo(
    () =>
      Object.values(programStatus).filter(
        (p) => p.outcome === "error" || p.outcome === "timeout" || p.outcome === "capped",
      ).length,
    [programStatus],
  );
  const readPct = total ? Math.min(100, Math.round((readCount / total) * 100)) : 0;

  const swid = identity?.software_id ?? identity?.swid ?? null;
  const siteName = (hasSnapshot && form.site) || meta?.site || form.site || "No system connected";
  const stations = count("200");
  const trunks = count("300");
  const subParts = ["Toshiba CIX"];
  if (swid) subParts.push(`software ${swid}`);
  if (stations) subParts.push(`${stations} stations`);
  if (trunks) subParts.push(`${trunks} trunks`);

  const connDot =
    progress.status === "error"
      ? "bg-bad"
      : progress.status === "reading" || progress.status === "connecting"
        ? "bg-warn"
        : progress.status === "done" || progress.status === "cold"
          ? "bg-ok"
          : "bg-fg-3";
  const connText = !hasSnapshot
    ? "Not connected"
    : `${coldStart ? "Snapshot" : form.reach === "remote" ? "Remote" : "Direct"} · ${
        progress.status === "error" ? "error" : coldStart ? "from file" : "SNMP ok"
      }`;

  const jobs: Job[] = [
    { icon: "user-pen", title: "Add or rename a phone", desc: "Change a name, type, or class of service.", ref: "Stations · 200", onClick: () => openNum("200") },
    { icon: "phone-forwarded", title: "Change where a line rings", desc: "Incoming routing for a trunk or DID.", ref: "Trunks · 300 / 309", onClick: () => openNum("300") },
    { icon: "route", title: "Map the call flow", desc: "Visual diagram of inbound routing: DIDs & line groups.", ref: "Call flow", onClick: openCallFlow },
    { icon: "moon", title: "Set day / night hours", desc: "When the system switches to night mode.", ref: "Day night · 106", onClick: () => openNum("106") },
    { icon: "zap", title: "Edit speed dials", desc: "System-wide and per-station numbers.", ref: "501 / 516", onClick: () => openNum("516") },
    { icon: "settings", title: "System settings", desc: "Clock, hold recall, music source.", ref: "System data · 105", onClick: () => openNum("105") },
    { icon: "git-compare", title: "Compare backups", desc: "See what changed between two snapshots.", ref: "Backups", onClick: openBackups },
  ];

  return (
    <div className="h-full overflow-auto">
      <div className="grid h-full grid-cols-1 gap-7 p-7 lg:grid-cols-[minmax(0,1fr)_320px]">
        {/* Left column */}
        <div className="flex min-w-0 flex-col gap-6">
          <div>
            <h1 className="text-[28px] font-semibold leading-tight tracking-[-0.015em]">{siteName}</h1>
            <div className="mt-1 text-fg-2">{subParts.join(" · ")}</div>
          </div>

          {/* Status strip */}
          <div className="grid grid-cols-1 overflow-hidden rounded-[12px] border border-border bg-surface sm:grid-cols-3">
            <div className="border-border px-[18px] py-4 sm:border-r">
              <div className="text-xs text-fg-3">Connection</div>
              <div className="mt-1 flex items-center gap-[7px] font-semibold">
                <span className={`h-2 w-2 rounded-full ${connDot}`} />
                {connText}
              </div>
            </div>
            <div className="border-border px-[18px] py-4 sm:border-r">
              <div className="text-xs text-fg-3">Snapshot</div>
              <div className="mt-1 truncate font-semibold">{meta?.read_at || (hasSnapshot ? "just now" : "—")}</div>
            </div>
            <div className="px-[18px] py-4">
              <div className="flex justify-between text-xs text-fg-3">
                <span>Programs read</span>
                <span className="tnum">
                  {readCount} / {total}
                </span>
              </div>
              <div className="mt-2.5 flex h-1.5 overflow-hidden rounded-full bg-surface-2">
                <div className="bg-primary" style={{ width: `${readPct}%` }} />
              </div>
              {failed > 0 ? (
                <button onClick={() => useStore.getState().openProblems()} className="mt-1.5 text-xs text-warn hover:underline">
                  {failed} didn&apos;t finish — review
                </button>
              ) : (
                <div className="mt-1.5 text-xs text-fg-3">{hasSnapshot ? "All read programs complete" : "Connect to read a snapshot"}</div>
              )}
            </div>
          </div>

          {/* Common jobs */}
          <div>
            <div className="mb-3 text-[15px] font-semibold">Common jobs</div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {jobs.map((j) => {
                const Icon: LucideIcon = navIcon(j.icon);
                return (
                  <button
                    key={j.title}
                    onClick={j.onClick}
                    className="flex flex-col items-start gap-2.5 rounded-[12px] border border-border bg-surface p-4 text-left hover:border-primary"
                  >
                    <span className="flex h-[34px] w-[34px] items-center justify-center rounded-[9px] bg-accent-tint text-primary">
                      <Icon className="h-[17px] w-[17px]" />
                    </span>
                    <span className="font-semibold">{j.title}</span>
                    <span className="text-[12.5px] leading-[1.45] text-fg-2">{j.desc}</span>
                    <span className="font-mono text-[11px] text-fg-3 tnum">{j.ref}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {!hasSnapshot && (
            <button
              onClick={() => setConnectDrawerOpen(true)}
              className="w-fit rounded-[9px] bg-primary px-3.5 py-2 text-[12.5px] font-medium text-primary-foreground hover:bg-accent-hover"
            >
              Connect to a CIX…
            </button>
          )}
        </div>

        {/* Right column — Snapshots */}
        <div className="flex flex-col gap-3">
          <div className="flex items-center">
            <span className="flex-1 text-[15px] font-semibold">Snapshots</span>
            <button
              onClick={openBackups}
              className="h-[30px] rounded-[8px] bg-primary px-3 text-[12.5px] font-medium text-primary-foreground hover:bg-accent-hover"
            >
              Back up now
            </button>
          </div>
          <div className="rounded-[12px] border border-border bg-surface px-4 py-1.5">
            {snaps === null ? (
              <div className="py-3 text-xs text-fg-3">Loading snapshots…</div>
            ) : snaps.length === 0 ? (
              <div className="py-3 text-xs text-fg-3">
                No snapshots yet. Back up now to capture the current configuration.
              </div>
            ) : (
              snaps.slice(0, 5).map((s) => (
                <div
                  key={s.sid}
                  className="grid grid-cols-[14px_minmax(0,1fr)] gap-2.5 border-b border-border py-2.5 last:border-b-0"
                >
                  <span
                    className={`mt-[5px] h-2 w-2 rounded-full ${s.pinned ? "bg-primary" : "bg-fg-3"}`}
                  />
                  <div className="min-w-0">
                    <div className="truncate font-medium">{s.name || s.label || s.kind}</div>
                    <div className="truncate text-xs text-fg-3">
                      {s.saved_at}
                      {s.note ? ` · ${s.note}` : s.tags && s.tags.length ? ` · ${s.tags.join(", ")}` : ""}
                    </div>
                  </div>
                </div>
              ))
            )}
            <button
              onClick={openBackups}
              className="w-full py-2.5 text-left text-[12.5px] font-medium text-primary hover:underline"
            >
              Compare two snapshots →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
