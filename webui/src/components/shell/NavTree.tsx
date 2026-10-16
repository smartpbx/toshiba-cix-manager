import * as React from "react";
import { ChevronDown, ChevronRight, Voicemail } from "lucide-react";
import { cn } from "@/lib/utils";
import type { MenuItem } from "@/lib/schema";
import { useStore, type VmScreen } from "@/store/useStore";

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

// The eManager menu tree, verbatim and in order (DESIGN_PLAN 3.2). Each menu
// item opens a tab for its (first) program; an item whose programs returned no
// data in the snapshot is greyed ("greys programs not yet read"). Home sits at
// the top, as in the design.
export function NavTree() {
  const {
    schema,
    openAreas,
    toggleArea,
    setArea,
    readKeys,
    rowCounts,
    openProgram,
    openHome,
    openVm,
    vmStatus,
    activeTabId,
    tabs,
  } = useStore((s) => ({
    schema: s.schema,
    openAreas: s.openAreas,
    toggleArea: s.toggleArea,
    setArea: s.setArea,
    readKeys: s.readKeys,
    rowCounts: s.rowCounts,
    openProgram: s.openProgram,
    openHome: s.openHome,
    openVm: s.openVm,
    vmStatus: s.vmStatus,
    activeTabId: s.activeTabId,
    tabs: s.tabs,
  }));

  const activeProgramKey = React.useMemo(() => {
    const t = tabs.find((x) => x.id === activeTabId);
    return t?.programKey;
  }, [tabs, activeTabId]);

  // Open the first area by default, and any area holding the active program.
  React.useEffect(() => {
    if (!schema) return;
    setArea(schema.menu_tree[0]?.area ?? "", true);
  }, [schema, setArea]);

  if (!schema) {
    return (
      <nav className="w-[var(--nav-w)] shrink-0 border-r border-border bg-surface p-3 text-xs text-fg-3">
        Loading menu…
      </nav>
    );
  }

  const itemRead = (item: MenuItem) => item.programs.some((p) => readKeys.has(p));
  const itemRows = (item: MenuItem) =>
    item.programs.reduce((n, p) => n + (rowCounts[p] ?? 0), 0);

  return (
    <nav className="flex w-[var(--nav-w)] shrink-0 flex-col overflow-auto border-r border-border bg-surface py-2">
      <button
        onClick={openHome}
        className={cn(
          "mx-2 mb-1 flex items-center gap-2 rounded-md px-2 py-1.5 text-sm",
          activeTabId === "home"
            ? "bg-accent-tint font-medium text-primary"
            : "hover:bg-surface-2",
        )}
      >
        Home
      </button>

      {schema.menu_tree.map((area) => {
        const open = openAreas[area.area] ?? false;
        const anyRead = area.items.some(itemRead);
        return (
          <div key={area.area} className="px-2">
            <button
              onClick={() => toggleArea(area.area)}
              className="flex w-full items-center gap-1 rounded-md px-1.5 py-1 text-2xs font-semibold uppercase tracking-wide text-fg-2 hover:bg-surface-2"
            >
              {open ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
              <span className={cn(!anyRead && "text-fg-3")}>{area.area}</span>
            </button>
            {open &&
              area.items.map((item) => {
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
                      "flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-sm",
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
                      <span className="rounded bg-surface-2 px-1.5 text-2xs text-fg-2 tnum">
                        {rows}
                      </span>
                    )}
                  </button>
                );
              })}
          </div>
        );
      })}

      {/* Voice Mail — the second root (VM Manager's menu bar). */}
      <div className="mt-2 border-t border-border px-2 pt-2">
        <button
          onClick={() => toggleArea("__vm__")}
          className="flex w-full items-center gap-1 rounded-md px-1.5 py-1 text-2xs font-semibold uppercase tracking-wide text-fg-2 hover:bg-surface-2"
        >
          {openAreas["__vm__"] ? (
            <ChevronDown className="h-3 w-3" />
          ) : (
            <ChevronRight className="h-3 w-3" />
          )}
          <Voicemail className="h-3 w-3" />
          <span>Voice Mail</span>
          {vmStatus?.connected && (
            <span
              className="ml-auto h-1.5 w-1.5 rounded-full bg-ok"
              title="Voicemail session connected"
            />
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
                  "flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-sm",
                  active ? "bg-accent-tint text-primary" : "hover:bg-surface-2",
                )}
              >
                <span className="min-w-0 flex-1 truncate">{item.title}</span>
              </button>
            );
          })}
      </div>
    </nav>
  );
}
