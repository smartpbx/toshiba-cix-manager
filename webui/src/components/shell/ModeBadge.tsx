import { Lock, PencilLine, PlayCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useStore } from "@/store/useStore";

// The write-gate state machine is always visible (DESIGN_PLAN 5.5):
// READ-ONLY → ARMED (amber) → SIMULATE (blue). The live WRITING / VERIFIED /
// MISMATCH transitions are shown inside the Review & Write dialog's log.
export function ModeBadge() {
  const mode = useStore((s) => s.mode.mode);
  const sessionId = useStore((s) => s.sessionId);

  if (!sessionId || mode === "disarmed") {
    return (
      <Badge variant="outline" className="gap-1 px-2 py-1 text-fg-2">
        <Lock className="h-3 w-3" />
        READ-ONLY
      </Badge>
    );
  }
  if (mode === "simulate") {
    return (
      <Badge variant="remote" className="gap-1 px-2 py-1">
        <PlayCircle className="h-3 w-3" />
        SIMULATE
      </Badge>
    );
  }
  return (
    <Badge variant="warn" className="gap-1 px-2 py-1">
      <PencilLine className="h-3 w-3" />
      ARMED
    </Badge>
  );
}
