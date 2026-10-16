import { Lock, Unlock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useStore } from "@/store/useStore";

// The write-gate state machine is always visible (ui.md §1.3). This first cut
// is read-only: the engine's writes are stubbed/confirm-gated, so the badge
// reports READ-ONLY or WRITES: CONFIRM-GATED and never claims ARMED.
export function ModeBadge() {
  const writesEnabled = useStore((s) => s.writesEnabled);
  if (writesEnabled) {
    return (
      <Badge variant="warn" className="gap-1 px-2 py-1">
        <Unlock className="h-3 w-3" />
        WRITES: CONFIRM-GATED
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="gap-1 px-2 py-1 text-fg-2">
      <Lock className="h-3 w-3" />
      READ-ONLY
    </Badge>
  );
}
