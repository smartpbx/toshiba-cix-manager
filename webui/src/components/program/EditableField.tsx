import * as React from "react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { SchemaField } from "@/lib/schema";

// The editable counterpart of FieldControl (DESIGN_PLAN 3.4). Editing stages a
// change — it NEVER writes — so these are plain controlled inputs bound to the
// draft value. An enum is a native <select> of its captions (value = raw); all
// other fields are a text input (every field is written as its literal string,
// the only data wire type the capture proved).
export function EditableField({
  field,
  value,
  invalid,
  onChange,
}: {
  field: SchemaField;
  value: string;
  invalid?: boolean;
  onChange: (next: string) => void;
}) {
  const enumEntries = React.useMemo(
    () => (field.enum_values ? Object.entries(field.enum_values) : null),
    [field.enum_values],
  );

  if (enumEntries && enumEntries.length > 0) {
    return (
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={cn(
          "h-ctl w-full rounded-md border border-input bg-surface px-2 py-1 text-sm text-foreground",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          invalid && "border-bad ring-1 ring-bad",
        )}
      >
        {/* keep the current raw value selectable even if not in the map */}
        {!field.enum_values?.[value] && value !== "" && (
          <option value={value}>{value}</option>
        )}
        {enumEntries.map(([raw, caption]) => (
          <option key={raw} value={raw}>
            {caption} ({raw})
          </option>
        ))}
      </select>
    );
  }

  const numeric = field.control === "number" || field.syntax === "INTEGER";
  return (
    <Input
      value={value}
      inputMode={numeric ? "numeric" : undefined}
      onChange={(e) => onChange(e.target.value)}
      className={cn(
        (field.control === "port" ||
          field.control === "ipaddress" ||
          field.control === "time") &&
          "font-mono",
        invalid && "border-bad ring-1 ring-bad",
      )}
    />
  );
}
