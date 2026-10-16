import { History, Search } from "lucide-react";
import { ConnectionPill } from "./ConnectionPill";
import { ModeBadge } from "./ModeBadge";
import { ThemeToggle } from "./ThemeToggle";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

function Logo() {
  return (
    <div className="flex items-center gap-2 pl-1 pr-2">
      <svg viewBox="0 0 16 16" className="h-4 w-4 text-primary" aria-hidden>
        <rect
          x="1.5"
          y="1.5"
          width="13"
          height="13"
          rx="2"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        />
        <path d="M5 8h6M8 5v6" stroke="currentColor" strokeWidth="1.5" />
      </svg>
      <span className="text-sm font-semibold">Switchroom</span>
    </div>
  );
}

export function TopBar() {
  const { setPaletteOpen, openBackups } = useStore(
    useShallow((s) => ({
      setPaletteOpen: s.setPaletteOpen,
      openBackups: s.openBackups,
    })),
  );
  const isMac =
    typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
  return (
    <header className="flex h-topbar shrink-0 items-center gap-2 border-b border-border bg-surface px-2">
      <Logo />
      <div className="mx-1 h-5 w-px bg-border" />
      <ConnectionPill />
      <div className="mx-1 flex-1" />
      <button
        onClick={() => setPaletteOpen(true)}
        className="flex h-8 w-64 max-w-[40vw] items-center gap-2 rounded-md border border-border bg-surface-2 px-2.5 text-sm text-fg-2 hover:border-line-strong"
        title="Command palette"
      >
        <Search className="h-4 w-4" />
        <span className="flex-1 text-left">Search programs, DNs…</span>
        <kbd className="rounded bg-surface px-1 py-0.5 text-2xs text-fg-3">
          {isMac ? "⌘K" : "Ctrl K"}
        </kbd>
      </button>
      <button
        onClick={openBackups}
        className="flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 text-sm text-fg-2 hover:border-line-strong"
        title="Backups & Diff"
      >
        <History className="h-4 w-4" />
        <span className="hidden sm:inline">Backups</span>
      </button>
      <ModeBadge />
      <ThemeToggle />
    </header>
  );
}
