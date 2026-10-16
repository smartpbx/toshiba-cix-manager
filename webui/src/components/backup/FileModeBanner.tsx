import { FileClock, X } from "lucide-react";
import { useStore } from "@/store/useStore";

// The persistent amber "you are viewing a file, not the live switch" banner
// (backups.md §3 / DESIGN_PLAN 7.3). Shown across the workspace whenever a
// snapshot is open in file mode; the program pages render read-only underneath.
export function FileModeBanner() {
  const { fileMode, exitFileMode, openBackups } = useStore((s) => ({
    fileMode: s.fileMode,
    exitFileMode: s.exitFileMode,
    openBackups: s.openBackups,
  }));
  if (!fileMode) return null;
  const when = fileMode.savedAt ? new Date(fileMode.savedAt).toLocaleString() : "";
  return (
    <div className="flex items-center gap-2 border-b border-warn/40 bg-warn-tint px-3 py-1.5 text-xs text-warn">
      <FileClock className="h-4 w-4 shrink-0" />
      <span className="truncate">
        Viewing snapshot <strong>“{fileMode.label}”</strong>
        {when && <> · {when}</>}
        {fileMode.swid && <> · {fileMode.swid}</>} · <strong>not live</strong>
      </span>
      <div className="ml-auto flex items-center gap-1">
        <button
          onClick={openBackups}
          className="rounded px-2 py-0.5 font-medium hover:bg-warn/15"
          title="Back to the Backups timeline"
        >
          Compare…
        </button>
        <button
          onClick={exitFileMode}
          className="flex items-center gap-1 rounded px-2 py-0.5 font-medium hover:bg-warn/15"
          title="Leave file mode"
        >
          <X className="h-3.5 w-3.5" /> Open live
        </button>
      </div>
    </div>
  );
}
