import * as React from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { SchemaField, SchemaProgram } from "@/lib/schema";
import type { Cell, Row } from "@/lib/types";
import { FieldRow } from "./FieldRow";

// A record rendered as a grouped, read-only form: the primary fields
// (DESIGN_PLAN 3.3) first, the rest under a collapsible "Advanced (N)".
// Hidden and key fields are not shown as editable rows (the key is the row's
// identity, shown in the header).
export function RecordForm({
  program,
  row,
}: {
  program: SchemaProgram;
  row?: Row;
}) {
  const [showAdvanced, setShowAdvanced] = React.useState(false);

  const cellByName = React.useMemo(() => {
    const m: Record<string, Cell> = {};
    for (const c of row?.cells ?? []) m[c.field_name] = c;
    return m;
  }, [row]);

  const visible = program.fields.filter((f) => f.control !== "hidden");
  const primarySet = new Set(program.primary_fields ?? []);
  const primary: SchemaField[] = [];
  const advanced: SchemaField[] = [];
  for (const f of visible) {
    if (primarySet.has(f.name)) primary.push(f);
    else advanced.push(f);
  }
  // Fields flagged primary keep the schema's primary order; everything else
  // falls to Advanced. If nothing is flagged primary, show the first few up top.
  if (primary.length === 0) {
    primary.push(...advanced.splice(0, Math.min(6, advanced.length)));
  }

  return (
    <div className="divide-y divide-border/60">
      {program.danger && (
        <div className="mb-1 flex items-center gap-2 border-l-2 border-bad bg-bad-tint px-2 py-1 text-xs text-bad">
          Danger program — changes here are high-impact.
        </div>
      )}
      {primary.map((f) => (
        <FieldRow key={f.name} field={f} cell={cellByName[f.name]} />
      ))}
      {advanced.length > 0 && (
        <div className="pt-1">
          <button
            type="button"
            onClick={() => setShowAdvanced((s) => !s)}
            className="flex items-center gap-1 py-1 text-xs font-medium text-fg-2 hover:text-foreground"
          >
            {showAdvanced ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
            Advanced ({advanced.length})
          </button>
          {showAdvanced &&
            advanced.map((f) => (
              <FieldRow key={f.name} field={f} cell={cellByName[f.name]} />
            ))}
        </div>
      )}
    </div>
  );
}
