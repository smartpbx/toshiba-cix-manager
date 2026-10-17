import { Lock, PencilLine, PlayCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useStore } from "@/store/useStore";

// The write-gate state machine is always visible (DESIGN_PLAN 5.5):
// read-only ("Viewing only") → ARMED (amber) → SIMULATE (violet). The live
// WRITING / VERIFIED / MISMATCH transitions are shown inside the Review & Write
// dialog's log. Read-only is the redesign's "Viewing only" header pill.
export function ModeBadge() {
  const mode = useStore((s) => s.mode.mode);
  const sessionId = useStore((s) => s.sessionId);

  if (!sessionId || mode === "disarmed") {
    return (
      <span className="flex h-[30px] items-center gap-1.5 rounded-[15px] bg-surface-2 px-3 text-xs text-fg-2">
        <Lock className="h-[13px] w-[13px]" />
        Viewing only
      </span>
    );
  }
  if (mode === "simulate") {
    return (
      <Badge variant="remote" className="h-[30px] gap-1.5 rounded-[15px] px-3 text-xs">
        <PlayCircle className="h-[13px] w-[13px]" />
        SIMULATE
      </Badge>
    );
  }
  return (
    <Badge variant="warn" className="h-[30px] gap-1.5 rounded-[15px] px-3 text-xs">
      <PencilLine className="h-[13px] w-[13px]" />
      ARMED
    </Badge>
  );
}
