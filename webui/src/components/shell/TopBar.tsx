import * as React from "react";
import {
  Check,
  CircleHelp,
  CloudUpload,
  ListChecks,
  Loader2,
  Search,
  X,
} from "lucide-react";
import { ModeBadge } from "./ModeBadge";
import { UpdateButton } from "./Updates";
import type { UISchema } from "@/lib/schema";
import type { Tab } from "@/store/useStore";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";
import { cn } from "@/lib/utils";

// The breadcrumb for the active tab. eManager mode uses the program's verbatim
// menu_path (split on " - "); task mode uses the task group / item the program
// sits under (falling back to the menu_path), plus the record crumb a screen
// contributes (e.g. the selected station).
function crumbsFor(
  tab: Tab | undefined,
  schema: UISchema | null,
  navMode: "task" | "emanager",
  recordCrumb: string | null,
): string[] {
  if (!tab || tab.kind === "home") return [navMode === "task" ? "Overview" : "Home"];
  if (tab.kind === "backups") return ["Backups"];
  if (tab.kind === "problems") return ["Problems"];
  if (tab.kind === "help") return ["Help"];
  if (tab.kind === "vm") return ["Voice Mail", tab.title];
  if (tab.kind === "program" && tab.programKey && schema) {
    const prog = schema.programs[tab.programKey];
    let base: string[] = [];
    if (navMode === "task") {
      for (const g of schema.task_tree) {
        const it = g.items.find((i) => i.programs.includes(tab.programKey!));
        if (it) {
          base = [g.label, it.title].filter((x): x is string => !!x);
          break;
        }
      }
    }
    if (base.length === 0) {
      base = prog?.menu_path
        ? prog.menu_path.split(" - ").map((s) => s.trim()).filter(Boolean)
        : [prog?.label ?? tab.title];
    }
    return recordCrumb ? [...base, recordCrumb] : base;
  }
  return [tab.title];
}

// Save to cloud — only shown when the app was opened from Conduit (a deep-link
// bridge context is active). Generic label per the contract: it POSTs the
// backup the app already produces to the configured cloud endpoint (Conduit for
// our deployment). Shows a transient success / failure that auto-clears.
function SaveToCloudButton() {
  const { active, saving, result, saveToCloud, clearResult } = useStore(
    useShallow((s) => ({
      active: s.bridge.active,
      saving: s.bridgeSaving,
      result: s.bridgeSaveResult,
      saveToCloud: s.saveToCloud,
      clearResult: s.clearBridgeSaveResult,
    })),
  );

  React.useEffect(() => {
    if (!result) return;
    const t = setTimeout(clearResult, 6000);
    return () => clearTimeout(t);
  }, [result, clearResult]);

  if (!active) return null;

  return (
    <div className="flex items-center gap-1.5">
      {result && (
        <span
          className={cn(
            "flex items-center gap-1 text-xs",
            result.ok ? "text-ok" : "text-bad",
          )}
          title={result.text}
        >
          {result.ok ? <Check className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" />}
          <span className="max-w-[18ch] truncate">{result.text}</span>
        </span>
      )}
      <button
        onClick={() => void saveToCloud()}
        disabled={saving}
        className="flex h-8 items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 text-[13px] text-fg-2 hover:bg-surface-2 disabled:opacity-60"
        title="Save this backup to Conduit (the system that opened this app)"
      >
        {saving ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <CloudUpload className="h-4 w-4" />
        )}
        Save to cloud
      </button>
    </div>
  );
}

export function TopBar() {
  const { tabs, activeTabId, schema, navMode, recordCrumb, setPaletteOpen, openProblems, openHelp } =
    useStore(
      useShallow((s) => ({
        tabs: s.tabs,
        activeTabId: s.activeTabId,
        schema: s.schema,
        navMode: s.navMode,
        recordCrumb: s.recordCrumb,
        setPaletteOpen: s.setPaletteOpen,
        openProblems: s.openProblems,
        openHelp: s.openHelp,
      })),
    );
  const isMac =
    typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

  const tab = tabs.find((t) => t.id === activeTabId) ?? tabs[0];
  const crumbs = crumbsFor(tab, schema, navMode, recordCrumb);

  return (
    <header
      data-chrome="header"
      className="flex h-header shrink-0 items-center gap-3 border-b border-border px-7"
    >
      <nav
        aria-label="Breadcrumb"
        className="flex min-w-0 items-center gap-2 whitespace-nowrap text-[13.5px] text-fg-3"
      >
        {crumbs.map((c, i) => (
          <React.Fragment key={`${c}-${i}`}>
            {i > 0 && <span className="text-fg-3">/</span>}
            <span className={i === crumbs.length - 1 ? "truncate font-medium text-foreground" : "truncate"}>
              {c}
            </span>
          </React.Fragment>
        ))}
      </nav>

      <span className="flex-1" />

      <SaveToCloudButton />

      <button
        onClick={openProblems}
        className="flex h-8 w-8 items-center justify-center rounded-lg text-fg-2 hover:bg-surface-2"
        title="Problems (config linter)"
      >
        <ListChecks className="h-4 w-4" />
      </button>
      <button
        onClick={openHelp}
        className="flex h-8 w-8 items-center justify-center rounded-lg text-fg-2 hover:bg-surface-2"
        title="Coming from eManager?"
      >
        <CircleHelp className="h-4 w-4" />
      </button>
      <UpdateButton />

      <button
        onClick={() => setPaletteOpen(true)}
        className="flex h-[34px] w-[260px] max-w-[32vw] items-center gap-2 rounded-[9px] border border-border bg-surface px-3 text-fg-3 hover:border-line-strong"
        title="Search programs, people, DNs…"
      >
        <Search className="h-[15px] w-[15px]" />
        <span className="flex-1 text-left">Find a person, DN, setting…</span>
        <span className="font-mono text-[11px] tnum">{isMac ? "⌘K" : "⌃K"}</span>
      </button>

      <ModeBadge />
    </header>
  );
}
