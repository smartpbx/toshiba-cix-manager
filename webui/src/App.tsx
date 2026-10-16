import * as React from "react";
import { TopBar } from "@/components/shell/TopBar";
import { NavRail } from "@/components/shell/NavRail";
import { StatusBar } from "@/components/shell/StatusBar";
import { CommandPalette } from "@/components/shell/CommandPalette";
import { EmptyState } from "@/components/PageHeader";
import { ConnectView } from "@/views/ConnectView";
import { OverviewView } from "@/views/OverviewView";
import { StationsView } from "@/views/StationsView";
import { EquipmentView } from "@/views/EquipmentView";
import { SystemView } from "@/views/SystemView";
import { NetworkView } from "@/views/NetworkView";
import { ProgramsView } from "@/views/ProgramsView";
import { BackupDiffView } from "@/views/BackupDiffView";
import { ExportView } from "@/views/ExportView";
import { api } from "@/lib/api";
import { useStore } from "@/store/useStore";

function useTheme() {
  const theme = useStore((s) => s.theme);
  React.useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
  }, [theme]);
}

function useBoot() {
  const { setRuntime, setCatalog } = useStore((s) => ({
    setRuntime: s.setRuntime,
    setCatalog: s.setCatalog,
  }));
  React.useEffect(() => {
    api
      .health()
      .then((h) => h?.ok && setRuntime({ version: h.version, writesEnabled: h.writes_enabled }))
      .catch(() => {});
    api
      .catalog()
      .then((c) => c?.ok && setCatalog(c))
      .catch(() => {});
  }, [setRuntime, setCatalog]);
}

function ActiveView() {
  const { view, hasDoc } = useStore((s) => ({
    view: s.view,
    hasDoc: !!s.doc,
  }));

  switch (view) {
    case "connect":
      return <ConnectView />;
    case "overview":
      return hasDoc ? <OverviewView /> : <EmptyState message="Read a CIX first (Connect)." />;
    case "stations":
      return hasDoc ? <StationsView /> : <EmptyState message="Read a CIX first (Connect)." />;
    case "equipment":
      return hasDoc ? <EquipmentView /> : <EmptyState message="Read a CIX first (Connect)." />;
    case "system":
      return hasDoc ? <SystemView /> : <EmptyState message="Read a CIX first (Connect)." />;
    case "network":
      return hasDoc ? <NetworkView /> : <EmptyState message="Read a CIX first (Connect)." />;
    case "programs":
      return <ProgramsView />;
    case "backup":
      return <BackupDiffView />;
    case "export":
      return hasDoc ? <ExportView /> : <EmptyState message="Read a CIX first (Connect)." />;
    default:
      return <ConnectView />;
  }
}

export default function App() {
  useTheme();
  useBoot();
  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden">
      <TopBar />
      <div className="flex min-h-0 flex-1">
        <NavRail />
        <main className="min-w-0 flex-1 overflow-hidden bg-background">
          <ActiveView />
        </main>
      </div>
      <StatusBar />
      <CommandPalette />
    </div>
  );
}
