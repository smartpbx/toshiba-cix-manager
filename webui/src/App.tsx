import * as React from "react";
import { TopBar } from "@/components/shell/TopBar";
import { NavTree } from "@/components/shell/NavTree";
import { TabStrip } from "@/components/shell/TabStrip";
import { StatusBar } from "@/components/shell/StatusBar";
import { CommandPalette } from "@/components/shell/CommandPalette";
import { ConnectDrawer } from "@/components/shell/ConnectDrawer";
import { EmptyState } from "@/components/PageHeader";
import { HomeView } from "@/views/HomeView";
import { ProgramPage } from "@/views/ProgramPage";
import { BackupsView } from "@/views/BackupsView";
import { FileModeBanner } from "@/components/backup/FileModeBanner";
import { useEventStream } from "@/lib/sse";
import { useStore } from "@/store/useStore";

function useTheme() {
  const theme = useStore((s) => s.theme);
  React.useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
  }, [theme]);
}

function Workspace() {
  const { tabs, activeTabId, schemaError } = useStore((s) => ({
    tabs: s.tabs,
    activeTabId: s.activeTabId,
    schemaError: s.schemaError,
  }));
  const tab = tabs.find((t) => t.id === activeTabId) ?? tabs[0];

  if (schemaError) {
    return <EmptyState message={`Could not load the UI schema: ${schemaError}`} />;
  }
  if (!tab || tab.kind === "home") return <HomeView />;
  if (tab.kind === "backups") return <BackupsView />;
  if (tab.kind === "program" && tab.programKey) {
    // key forces a fresh mount per program so per-page state resets cleanly
    return <ProgramPage key={tab.programKey} programKey={tab.programKey} />;
  }
  return <HomeView />;
}

export default function App() {
  useTheme();
  useEventStream();
  const loadSchema = useStore((s) => s.loadSchema);
  React.useEffect(() => {
    void loadSchema();
  }, [loadSchema]);

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden">
      <TopBar />
      <div className="flex min-h-0 flex-1">
        <NavTree />
        <main className="flex min-w-0 flex-1 flex-col overflow-hidden bg-background">
          <TabStrip />
          <FileModeBanner />
          <div className="min-h-0 flex-1 overflow-hidden">
            <Workspace />
          </div>
        </main>
      </div>
      <StatusBar />
      <CommandPalette />
      <ConnectDrawer />
    </div>
  );
}
