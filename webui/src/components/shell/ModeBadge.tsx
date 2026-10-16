import { Lock } from "lucide-react";
import { Badge } from "@/components/ui/badge";

// The write-gate state machine is always visible (DESIGN_PLAN 5.5). This is the
// read-only browse release: the badge is always READ-ONLY. ARMED / WRITING /
// VERIFIED arrive with the write path (P2).
export function ModeBadge() {
  return (
    <Badge variant="outline" className="gap-1 px-2 py-1 text-fg-2">
      <Lock className="h-3 w-3" />
      READ-ONLY
    </Badge>
  );
}
