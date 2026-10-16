import { Home, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

// The tabbed workspace (DESIGN_PLAN 3.1): each open program is a tab; Home is
// pinned and never closes. Middle-click or the × closes a program tab.
export function TabStrip() {
  const { tabs, activeTabId, setActiveTab, closeTab } = useStore(
    useShallow((s) => ({
      tabs: s.tabs,
      activeTabId: s.activeTabId,
      setActiveTab: s.setActiveTab,
      closeTab: s.closeTab,
    })),
  );

  return (
    <div data-chrome="tabs" className="flex h-9 shrink-0 items-stretch gap-1 overflow-x-auto border-b border-border bg-surface px-2">
      {tabs.map((tab) => {
        const active = tab.id === activeTabId;
        return (
          <div
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            onMouseDown={(e) => {
              if (e.button === 1 && tab.kind !== "home") {
                e.preventDefault();
                closeTab(tab.id);
              }
            }}
            className={cn(
              "group flex cursor-pointer items-center gap-1.5 self-end rounded-t-md border border-b-0 px-3 py-1.5 text-xs",
              active
                ? "border-border bg-background font-medium text-foreground"
                : "border-transparent text-fg-2 hover:bg-surface-2",
            )}
          >
            {tab.kind === "home" && <Home className="h-3.5 w-3.5" />}
            <span className="max-w-[180px] truncate">{tab.title}</span>
            {tab.kind !== "home" && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(tab.id);
                }}
                className="ml-1 rounded p-0.5 text-fg-3 opacity-0 hover:bg-surface-3 hover:text-fg group-hover:opacity-100"
                aria-label={`Close ${tab.title}`}
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}
