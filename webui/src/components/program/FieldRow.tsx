import { cn } from "@/lib/utils";
import type { SchemaField } from "@/lib/schema";
import type { Cell } from "@/lib/types";
import { FieldControl } from "./FieldControl";
import { HelpPopover } from "./HelpPopover";

// One field row in a Form / record pane (DESIGN_PLAN 3.3):
//   [05] Class of Service   [ control ]   ?help
// display-number badge, native label, read-only control, help popover. A
// read-only field is italic + an `ro` tag (DESIGN_PLAN 3.4).
export function FieldRow({ field, cell }: { field: SchemaField; cell?: Cell }) {
  const ro = field.access !== "rw";
  return (
    <div className="flex items-start gap-2 py-1">
      <span className="field-badge mt-0.5" title={`field ${field.display_no}`}>
        {field.display_no}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span
            className={cn("text-xs text-fg-2", ro && "italic")}
            title={field.name}
          >
            {field.title}
          </span>
          {ro && (
            <span className="rounded bg-surface-2 px-1 text-[10px] uppercase text-fg-3">
              ro
            </span>
          )}
          {field.is_secret && (
            <span className="rounded bg-warn-tint px-1 text-[10px] uppercase text-warn">
              secret
            </span>
          )}
        </div>
        <div className="mt-0.5">
          <FieldControl field={field} cell={cell} />
        </div>
      </div>
      <HelpPopover field={field} cell={cell} />
    </div>
  );
}
