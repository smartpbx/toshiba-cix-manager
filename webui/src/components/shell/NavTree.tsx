import * as React from "react";
import {
  ChevronDown,
  ChevronRight,
  ChevronsUpDown,
  History,
  ListTree,
  Route,
  Search,
  Settings2,
  Voicemail,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { MenuItem, TaskItem } from "@/lib/schema";
import { navIcon } from "./navIcons";
import { useStore, type VmScreen } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

// The Voice Mail root (VM Manager's menu bar as the second nav root —
// voicemail-map §4.3). Verbatim words, in order.
const VM_ITEMS: Array<{ screen: VmScreen; title: string }> = [
  { screen: "status", title: "Status" },
  { screen: "boxes", title: "Users · Box List" },
  { screen: "sysparams", title: "System Parameters" },
  { screen: "integration", title: "Telephone System Integration" },
  { screen: "backup", title: "Backup to JSON" },
  { screen: "reports", title: "Reports" },
];

function Logo() {
  return (
    <div className="flex items-center gap-2 px-1.5 pb-3.5">
      <svg viewBox="0 0 16 16" className="h-[18px] w-[18px] text-primary" aria-hidden>
        <rect x="1.5" y="1.5" width="13" height="13" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <path d="M5 8h6M8 5v6" stroke="currentColor" strokeWidth="1.5" />
      </svg>
      <span className="text-[15px] font-semibold">Switchroom</span>
    </div>
  );
}

// The site card — opens the existing ConnectDrawer. Line 1: status dot + site
// name + chevrons-up-down; line 2: "IP · transport" in mono.
function SiteCard() {
  const { progress, form, coldStart, setConnectDrawerOpen } = useStore(
    useShallow((s) => ({
      progress: s.progress,
      form: s.form,
      coldStart: s.coldStart,
      setConnectDrawerOpen: s.setConnectDrawerOpen,
    })),
  );
  const connected = progress.status !== "idle";
  const dot =
    progress.status === "error"
      ? "bg-bad"
      : progress.status === "reading" || progress.status === "connecting"
        ? "bg-warn"
        : progress.status === "done" || progress.status === "cold"
          ? "bg-ok"
          : "bg-fg-3";
  const transport = coldStart ? "snapshot" : form.reach === "remote" ? "remote" : "direct";
  const line2 = connected && form.ip ? `${form.ip} · ${transport}` : "Not connected";

  return (
    <button
      onClick={() => setConnectDrawerOpen(true)}
      className="mb-3.5 flex flex-col gap-[3px] rounded-[10px] bg-surface-2 px-3 py-2.5 text-left hover:bg-surface-3"
      title="Connection details"
    >
      <span className="flex items-center gap-[7px] font-semibold">
        <span className={cn("h-2 w-2 shrink-0 rounded-full", dot)} />
        <span className="min-w-0 flex-1 truncate">{connected ? form.site || "Connected" : "Connect…"}</span>
        <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-fg-3" />
      </span>
      <span className="truncate font-mono text-xs text-fg-2 tnum">{line2}</span>
    </button>
  );
}

// -------------------------------------------------------------------------
// Task-first tree (schema.task_tree). Every item opens its first program via
// the same openProgram() the eManager tree uses — tabs / pages / writes
// untouched. Home opens the Overview.
// -------------------------------------------------------------------------
function TaskTree() {
  const { schema, showProgramNumbers, activeProgramKey, activeTabId, openProgram, openHome } =
    useStore(
      useShallow((s) => ({
        schema: s.schema,
        showProgramNumbers: s.showProgramNumbers,
        activeTabId: s.activeTabId,
        activeProgramKey: (() => {
          const t = s.tabs.find((x) => x.id === s.activeTabId);
          return t?.programKey;
        })(),
        openProgram: s.openProgram,
        openHome: s.openHome,
      })),
    );
  if (!schema) return null;

  const onItem = (it: TaskItem) => {
    if (it.kind === "home") return openHome();
    const key0 = it.programs[0];
    if (key0) openProgram(key0, schema.programs[key0]?.label ?? it.title);
  };
  const isActive = (it: TaskItem) =>
    it.kind === "home" ? activeTabId === "home" : it.programs[0] === activeProgramKey;

  return (
    <div className="flex flex-1 flex-col gap-[1px] overflow-auto">
      {schema.task_tree.map((group, gi) => (
        <div key={group.label ?? `g${gi}`} className="mb-1.5 flex flex-col gap-[1px]">
          {group.label && (
            <div className="px-2.5 py-1 text-[11.5px] font-medium text-fg-3">{group.label}</div>
          )}
          {group.items.map((it) => {
            const Icon = navIcon(it.icon);
            const active = isActive(it);
            return (
              <button
                key={`${group.label}-${it.title}`}
                onClick={() => onItem(it)}
                className={cn(
                  "flex h-7 items-center gap-2.5 whitespace-nowrap rounded-[7px] px-2.5 text-left",
                  active
                    ? "bg-accent-tint font-medium text-primary"
                    : "text-fg-2 hover:bg-surface-2",
                )}
              >
                <Icon className="h-4 w-4 shrink-0 opacity-85" />
                <span className="min-w-0 flex-1 truncate">{it.title}</span>
                {showProgramNumbers && it.num && (
                  <span className="font-mono text-[11px] text-fg-3 tnum">{it.num}</span>
                )}
              </button>
            );
          })}
        </div>
      ))}
    </div>
  );
}

// -------------------------------------------------------------------------
// eManager tree — today's menu, verbatim: filter field, Home, area headers
// with counts + chevrons, items with row-count pills, greyed-unread, L0 tag,
// and the Voice Mail root under a top border.
// -------------------------------------------------------------------------
function EmanagerTree() {
  const {
    schema,
    openAreas,
    toggleArea,
    readKeys,
    rowCounts,
    openProgram,
    openHome,
    openVm,
    setPaletteOpen,
    vmStatus,
    activeTabId,
    tabs,
  } = useStore(
    useShallow((s) => ({
      schema: s.schema,
      openAreas: s.openAreas,
      toggleArea: s.toggleArea,
      readKeys: s.readKeys,
      rowCounts: s.rowCounts,
      openProgram: s.openProgram,
      openHome: s.openHome,
      openVm: s.openVm,
      setPaletteOpen: s.setPaletteOpen,
      vmStatus: s.vmStatus,
      activeTabId: s.activeTabId,
      tabs: s.tabs,
    })),
  );

  const activeProgramKey = React.useMemo(() => {
    const t = tabs.find((x) => x.id === activeTabId);
    return t?.programKey;
  }, [tabs, activeTabId]);

  if (!schema) return null;

  const itemRead = (item: MenuItem) => item.programs.some((p) => readKeys.has(p));
  const itemRows = (item: MenuItem) =>
    item.programs.reduce((n, p) => n + (rowCounts[p] ?? 0), 0);
  const programCount = schema.counts?.programs ?? 186;

  return (
    <div className="flex flex-1 flex-col gap-[1px] overflow-auto">
      <button
        onClick={() => setPaletteOpen(true)}
        className="mb-1.5 flex h-[30px] shrink-0 items-center gap-1.5 rounded-lg bg-surface-2 px-2.5 text-xs text-fg-3 hover:text-fg-2"
      >
        <Search className="h-3.5 w-3.5" />
        Filter {programCount} programs
      </button>

      <button
        onClick={openHome}
        className={cn(
          "flex h-7 shrink-0 items-center gap-2 rounded-[7px] px-2.5 text-left",
          activeTabId === "home" ? "bg-accent-tint font-medium text-primary" : "hover:bg-surface-2",
        )}
      >
        Home
      </button>

      {schema.menu_tree.map((area) => {
        const open = openAreas[area.area] ?? false;
        const anyRead = area.items.some(itemRead);
        return (
          <div key={area.area} className="shrink-0">
            <button
              onClick={() => toggleArea(area.area)}
              className="flex h-[26px] w-full items-center gap-1.5 rounded-[7px] px-2 text-[11px] font-semibold uppercase tracking-[0.04em] text-fg-2 hover:bg-surface-2"
            >
              {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              <span className={cn("flex-1 text-left", !anyRead && "text-fg-3")}>{area.area}</span>
              <span className="font-mono text-[11px] font-normal tracking-normal text-fg-3 tnum">
                {area.items.length}
              </span>
            </button>
            {open && (
              <div className="my-[1px] mb-1 flex flex-col gap-[1px]">
                {area.items.map((item) => {
                  const read = itemRead(item);
                  const rows = itemRows(item);
                  const key0 = item.programs[0];
                  const active = !!key0 && key0 === activeProgramKey;
                  return (
                    <button
                      key={item.menu_path}
                      disabled={!key0}
                      title={item.menu_path}
                      onClick={() => key0 && openProgram(key0, item.title)}
                      className={cn(
                        "flex h-[26px] items-center gap-1.5 rounded-[7px] pl-[25px] pr-2 text-left text-[12.5px]",
                        active
                          ? "bg-accent-tint text-primary"
                          : read
                            ? "hover:bg-surface-2"
                            : "text-fg-3 hover:bg-surface-2",
                      )}
                    >
                      <span className="min-w-0 flex-1 truncate">{item.title}</span>
                      {item.level0 && (
                        <span className="text-[10px] text-fg-3" title="Level-0 (advanced)">
                          L0
                        </span>
                      )}
                      {rows > 0 && (
                        <span className="rounded bg-surface-2 px-1.5 text-[10.5px] text-fg-2 tnum">
                          {rows}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}

      {/* Voice Mail — the second root (VM Manager's menu bar). */}
      <div className="mt-1.5 shrink-0 border-t border-border pt-1.5">
        <button
          onClick={() => toggleArea("__vm__")}
          className="flex h-[26px] w-full items-center gap-1.5 rounded-[7px] px-2 text-[11px] font-semibold uppercase tracking-[0.04em] text-fg-2 hover:bg-surface-2"
        >
          {openAreas["__vm__"] ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          <Voicemail className="h-3 w-3" />
          <span className="flex-1 text-left">Voice Mail</span>
          {vmStatus?.connected && (
            <span className="h-1.5 w-1.5 rounded-full bg-ok" title="Voicemail session connected" />
          )}
        </button>
        {(openAreas["__vm__"] ?? false) &&
          VM_ITEMS.map((item) => {
            const active = activeTabId === `vm:${item.screen}`;
            return (
              <button
                key={item.screen}
                onClick={() => openVm(item.screen, item.title.split(" · ").pop()!)}
                className={cn(
                  "flex h-[26px] w-full items-center gap-2 rounded-[7px] pl-[25px] pr-2 text-left text-[12.5px]",
                  active ? "bg-accent-tint text-primary" : "hover:bg-surface-2",
                )}
              >
                <span className="min-w-0 flex-1 truncate">{item.title}</span>
              </button>
            );
          })}
      </div>
    </div>
  );
}

export function NavTree() {
  const { schema, navMode, prefsOpen, setPrefsOpen, setNavMode, openBackups, openCallFlow } = useStore(
    useShallow((s) => ({
      schema: s.schema,
      navMode: s.navMode,
      prefsOpen: s.prefsOpen,
      setPrefsOpen: s.setPrefsOpen,
      setNavMode: s.setNavMode,
      openBackups: s.openBackups,
      openCallFlow: s.openCallFlow,
    })),
  );

  if (!schema) {
    return (
      <nav
        data-chrome="nav"
        className="flex w-nav shrink-0 flex-col border-r border-border bg-surface px-3 py-4 text-xs text-fg-3"
      >
        <Logo />
        Loading menu…
      </nav>
    );
  }

  const programCount = schema.counts?.programs ?? 186;

  return (
    <nav
      data-chrome="nav"
      className="flex w-nav shrink-0 flex-col overflow-hidden border-r border-border bg-surface px-3 py-4"
    >
      <Logo />
      <SiteCard />
      {navMode === "task" ? <TaskTree /> : <EmanagerTree />}

      <div className="flex flex-col gap-0.5 border-t border-border pt-2.5">
        <button
          onClick={() => setPrefsOpen(!prefsOpen)}
          className={cn(
            "flex h-8 items-center gap-2.5 whitespace-nowrap rounded-lg px-2.5 text-fg-2 hover:bg-surface-2",
            prefsOpen && "bg-surface-2",
          )}
        >
          <Settings2 className="h-4 w-4" />
          <span className="flex-1 text-left">Preferences</span>
          <span className="rounded-[10px] bg-surface-2 px-[7px] py-0.5 text-[11px] text-fg-2">
            {navMode === "task" ? "Task menu" : "eManager menu"}
          </span>
        </button>
        <button
          onClick={openCallFlow}
          className="flex h-8 items-center gap-2.5 rounded-lg px-2.5 text-fg-2 hover:bg-surface-2"
        >
          <Route className="h-4 w-4" />
          <span className="flex-1 text-left">Call flow</span>
        </button>
        <button
          onClick={openBackups}
          className="flex h-8 items-center gap-2.5 rounded-lg px-2.5 text-fg-2 hover:bg-surface-2"
        >
          <History className="h-4 w-4" />
          <span className="flex-1 text-left">Backups &amp; diff</span>
        </button>
        {navMode === "task" && (
          <button
            onClick={() => setNavMode("emanager")}
            className="flex h-8 items-center gap-2.5 rounded-lg px-2.5 text-[12.5px] text-fg-3 hover:bg-surface-2 hover:text-fg-2"
            title="Switch to the full eManager menu tree"
          >
            <ListTree className="h-4 w-4" />
            <span className="flex-1 text-left">All {programCount} programs · eManager</span>
          </button>
        )}
      </div>
    </nav>
  );
}
