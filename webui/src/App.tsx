import * as React from "react";
import { TopBar } from "@/components/shell/TopBar";
import { NavTree } from "@/components/shell/NavTree";
import { TabStrip } from "@/components/shell/TabStrip";
import { StatusBar } from "@/components/shell/StatusBar";
import { CommandPalette } from "@/components/shell/CommandPalette";
import { ConnectDrawer } from "@/components/shell/ConnectDrawer";
import { UpdatesDialog, UpdateToast } from "@/components/shell/Updates";
import { EmptyState } from "@/components/PageHeader";
import { HomeView } from "@/views/HomeView";
import { ProgramPage } from "@/views/ProgramPage";
import { BackupsView } from "@/views/BackupsView";
import { VoiceMailView } from "@/views/VoiceMailView";
import { ProblemsView } from "@/views/ProblemsView";
import { CallFlowView } from "@/views/CallFlowView";
import { HelpView } from "@/views/HelpView";
import { FileModeBanner } from "@/components/backup/FileModeBanner";
import { PreferencesPopover } from "@/components/shell/PreferencesPopover";
import { PendingRail } from "@/components/write/PendingRail";
import { ReviewWriteDialog } from "@/components/write/ReviewWriteDialog";
import { useEventStream } from "@/lib/sse";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

function useTheme() {
  const theme = useStore((s) => s.theme);
  React.useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
  }, [theme]);
}

function Workspace() {
  const { tabs, activeTabId, schemaError } = useStore(
    useShallow((s) => ({
      tabs: s.tabs,
      activeTabId: s.activeTabId,
      schemaError: s.schemaError,
    })),
  );
  const tab = tabs.find((t) => t.id === activeTabId) ?? tabs[0];

  if (schemaError) {
    return <EmptyState message={`Could not load the UI schema: ${schemaError}`} />;
  }
  if (!tab || tab.kind === "home") return <HomeView />;
  if (tab.kind === "backups") return <BackupsView />;
  if (tab.kind === "problems") return <ProblemsView />;
  if (tab.kind === "callflow") return <CallFlowView />;
  if (tab.kind === "help") return <HelpView />;
  if (tab.kind === "vm" && tab.vmScreen) {
    return <VoiceMailView key={tab.vmScreen} screen={tab.vmScreen} />;
  }
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
  const checkUpdate = useStore((s) => s.checkUpdate);
  const initBridge = useStore((s) => s.initBridge);
  React.useEffect(() => {
    void loadSchema();
  }, [loadSchema]);
  // Manager bridge: re-establish the Save-to-cloud target after a reload and
  // act on a deep link that launched the app (cold start — it may have arrived
  // before the SSE stream was subscribed, so poll once here too).
  React.useEffect(() => {
    void initBridge();
  }, [initBridge]);
  // One-time, non-blocking "is there a newer release?" check on launch. It
  // degrades silently offline (store swallows the error) and never blocks the
  // UI from mounting — it only surfaces the dismissible UpdateToast if newer.
  React.useEffect(() => {
    void checkUpdate();
  }, [checkUpdate]);

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden">
      <div className="flex min-h-0 flex-1">
        <NavTree />
        <main className="flex min-w-0 flex-1 flex-col overflow-hidden bg-background">
          <TopBar />
          <TabStrip />
          <FileModeBanner />
          <div className="min-h-0 flex-1 overflow-hidden">
            <Workspace />
          </div>
        </main>
        <PendingRail />
      </div>
      <StatusBar />
      <CommandPalette />
      <ConnectDrawer />
      <ReviewWriteDialog />
      <UpdatesDialog />
      <UpdateToast />
      <PreferencesPopover />
    </div>
  );
}
