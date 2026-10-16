import {
  Boxes,
  Cpu,
  Download,
  Hash,
  Home,
  LayoutGrid,
  Network,
  Plug,
  Save,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { useStore, type ViewId } from "@/store/useStore";

interface NavItem {
  id: ViewId;
  label: string;
  icon: LucideIcon;
  needsDoc?: boolean;
  needsBackup?: boolean;
}

const ITEMS: NavItem[] = [
  { id: "connect", label: "Connect", icon: Plug },
  { id: "overview", label: "Overview", icon: Home, needsDoc: true },
  { id: "stations", label: "Stations", icon: LayoutGrid, needsDoc: true },
  { id: "equipment", label: "Equipment", icon: Boxes, needsDoc: true },
  { id: "system", label: "System", icon: Cpu, needsDoc: true },
  { id: "network", label: "Network / FTP", icon: Network, needsDoc: true },
  { id: "programs", label: "Programs", icon: Hash, needsBackup: true },
  { id: "backup", label: "Backup & Diff", icon: Save },
  { id: "export", label: "Export", icon: Download, needsDoc: true },
];

export function NavRail() {
  const { view, setView, doc, backupA, stationCount } = useStore((s) => ({
    view: s.view,
    setView: s.setView,
    doc: s.doc,
    backupA: s.backupA,
    stationCount: s.doc?.stations?.length ?? 0,
  }));

  return (
    <nav className="flex w-[240px] shrink-0 flex-col gap-0.5 border-r border-border bg-surface p-2">
      <div className="px-2 py-1 text-2xs font-semibold uppercase tracking-wide text-fg-3">
        Site
      </div>
      {ITEMS.map((item) => {
        const disabled =
          (item.needsDoc && !doc) || (item.needsBackup && !backupA);
        const active = view === item.id;
        const Icon = item.icon;
        return (
          <button
            key={item.id}
            disabled={disabled}
            onClick={() => setView(item.id)}
            className={cn(
              "flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors",
              active
                ? "bg-accent-tint font-medium text-primary"
                : "text-foreground hover:bg-surface-2",
              disabled && "cursor-not-allowed opacity-40 hover:bg-transparent",
            )}
          >
            <Icon className="h-4 w-4 shrink-0" />
            <span className="flex-1 text-left">{item.label}</span>
            {item.id === "stations" && stationCount > 0 && (
              <span className="rounded bg-surface-2 px-1.5 text-2xs text-fg-2 tnum">
                {stationCount}
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
}
