import * as React from "react";
import { Monitor, Moon, Sun, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { useStore, type NavMode } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

type Theme = "system" | "light" | "dark";

const THEME_OPTS: Array<{ value: Theme; label: string; Icon: typeof Sun }> = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "System", Icon: Monitor },
];

const MODE_CARDS: Array<{ value: NavMode; title: string; desc: string }> = [
  {
    value: "task",
    title: "Task-based",
    desc: "Grouped by job: People & phones, Lines, Call routing, System. Plain-English names, with program numbers next to them.",
  },
  {
    value: "emanager",
    title: "eManager (verbatim)",
    desc: "The original eManager menu tree, with the same names, order and program numbers. Good for techs who know it by heart.",
  },
];

// Preferences — opened from the sidebar footer, anchored to the right of the
// sidebar and bottom-aligned. Applies immediately (no Save); Esc or clicking
// outside closes it. Per-laptop, persisted via the store (switchroom.prefs).
export function PreferencesPopover() {
  const {
    prefsOpen,
    setPrefsOpen,
    theme,
    setTheme,
    navMode,
    setNavMode,
    showProgramNumbers,
    setShowProgramNumbers,
  } = useStore(
    useShallow((s) => ({
      prefsOpen: s.prefsOpen,
      setPrefsOpen: s.setPrefsOpen,
      theme: s.theme,
      setTheme: s.setTheme,
      navMode: s.navMode,
      setNavMode: s.setNavMode,
      showProgramNumbers: s.showProgramNumbers,
      setShowProgramNumbers: s.setShowProgramNumbers,
    })),
  );

  React.useEffect(() => {
    if (!prefsOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPrefsOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [prefsOpen, setPrefsOpen]);

  if (!prefsOpen) return null;

  return (
    <>
      {/* click-outside catcher */}
      <div className="fixed inset-0 z-40" onClick={() => setPrefsOpen(false)} aria-hidden />
      <div
        role="dialog"
        aria-label="Preferences"
        className="fixed z-50 flex w-[400px] flex-col gap-3.5 rounded-[14px] border border-line-strong bg-surface p-[18px] shadow-[0_18px_48px_rgba(0,0,0,0.22)]"
        style={{ left: 252, bottom: "calc(var(--statusbar-h) + 12px)" }}
      >
        <div className="flex items-center">
          <span className="flex-1 text-[15px] font-semibold">Preferences</span>
          <button
            onClick={() => setPrefsOpen(false)}
            className="flex h-7 w-7 items-center justify-center rounded-[7px] text-fg-3 hover:bg-surface-2"
            aria-label="Close preferences"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Appearance */}
        <div className="flex items-center gap-3 border-b border-border pb-3.5">
          <span className="flex-1">
            <span className="block font-semibold">Appearance</span>
            <span className="block text-xs text-fg-3">System uses your laptop&apos;s setting</span>
          </span>
          <span className="inline-flex rounded-[9px] bg-surface-2 p-[3px] text-[12.5px]">
            {THEME_OPTS.map((o) => {
              const on = theme === o.value;
              return (
                <button
                  key={o.value}
                  onClick={() => setTheme(o.value)}
                  className={cn(
                    "flex items-center gap-1.5 rounded-[7px] px-2.5 py-[5px]",
                    on
                      ? "bg-surface font-medium text-foreground shadow-[0_1px_2px_rgba(0,0,0,0.12)]"
                      : "text-fg-3 hover:text-fg-2",
                  )}
                >
                  <o.Icon className="h-[13px] w-[13px]" />
                  {o.label}
                </button>
              );
            })}
          </span>
        </div>

        {/* Navigation menu */}
        <div>
          <div className="font-semibold">Navigation menu</div>
          <div className="mb-2.5 text-[12.5px] text-fg-2">
            Search, tabs and every program page stay the same either way.
          </div>
          <div className="flex flex-col gap-2">
            {MODE_CARDS.map((m) => {
              const on = navMode === m.value;
              return (
                <button
                  key={m.value}
                  onClick={() => setNavMode(m.value)}
                  className={cn(
                    "flex items-start gap-3 rounded-[10px] p-[12px_14px] text-left",
                    on ? "border-[1.5px] border-primary bg-accent-tint" : "border border-border",
                  )}
                >
                  <span
                    className={cn(
                      "mt-[1px] h-4 w-4 shrink-0 rounded-full",
                      on
                        ? "border-[5px] border-primary"
                        : "border-[1.5px] border-line-strong",
                    )}
                  />
                  <span className="flex-1">
                    <span className="block font-semibold">{m.title}</span>
                    <span className="mt-0.5 block text-[12.5px] leading-[1.45] text-fg-2">
                      {m.desc}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Show program numbers */}
        <button
          onClick={() => setShowProgramNumbers(!showProgramNumbers)}
          className="flex items-center gap-3 border-t border-border pt-3 text-left"
        >
          <span className="flex-1">
            <span className="block font-medium">Show program numbers in the menu</span>
            <span className="block text-xs text-fg-3">Task menu only. Example: Stations · 200</span>
          </span>
          <span
            className={cn(
              "flex h-5 w-9 shrink-0 rounded-[10px] p-0.5 transition-colors",
              showProgramNumbers ? "justify-end bg-primary" : "justify-start bg-line-strong",
            )}
          >
            <span className="h-4 w-4 rounded-full bg-white shadow-[0_1px_2px_rgba(0,0,0,0.2)]" />
          </span>
        </button>

        <div className="text-[11.5px] text-fg-3">
          Saved on this laptop, so each tech keeps their own choice.
        </div>
      </div>
    </>
  );
}
