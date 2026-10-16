import * as React from "react";
import { ChevronDown, Eye, EyeOff } from "lucide-react";
import { cn } from "@/lib/utils";
import { enumCaption, type SchemaField } from "@/lib/schema";
import type { Cell } from "@/lib/types";

// Read-only value rendering, honouring the `.tbl` control (DESIGN_PLAN 3.4).
// P1 is browse: every control shows the value but takes no input. Binary enums
// are a two-label segmented control (never a switch), enums show their caption,
// passwords mask with a reveal, dial strings / ports / OIDs are monospace.

function Empty() {
  return <span className="text-fg-3">—</span>;
}

function Segmented({ field, cell }: { field: SchemaField; cell?: Cell }) {
  const bp = field.binary_pair;
  if (!bp) return <EnumValue field={field} cell={cell} />;
  const raw = cell?.raw_value;
  const sides = [bp.on, bp.off];
  return (
    <div
      className="inline-flex overflow-hidden rounded-md border border-border"
      title={raw == null ? undefined : `raw ${String(raw)}`}
    >
      {sides.map((side) => {
        const active = raw != null && Number(raw) === side.raw;
        return (
          <span
            key={side.raw}
            className={cn(
              "px-2 py-0.5 text-2xs font-medium",
              active
                ? "bg-accent-tint text-primary"
                : "bg-surface text-fg-3",
            )}
          >
            {side.label}
          </span>
        );
      })}
    </div>
  );
}

function EnumValue({ field, cell }: { field: SchemaField; cell?: Cell }) {
  if (cell?.raw_value == null || cell.display_value === "") return <Empty />;
  const caption = enumCaption(field, cell.raw_value, cell.display_value);
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-2 py-0.5 text-sm"
      title={`raw ${String(cell.raw_value)}`}
    >
      {caption}
      <ChevronDown className="h-3 w-3 text-fg-3" />
    </span>
  );
}

function Password({ cell }: { cell?: Cell }) {
  const [show, setShow] = React.useState(false);
  const val = cell?.display_value ?? "";
  if (!val) return <Empty />;
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="font-mono tnum">{show ? val : "•".repeat(Math.min(val.length, 10))}</span>
      <button
        type="button"
        onClick={() => setShow((s) => !s)}
        className="text-fg-3 hover:text-fg-2"
        aria-label={show ? "Hide" : "Reveal"}
      >
        {show ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
      </button>
    </span>
  );
}

export function FieldControl({ field, cell }: { field: SchemaField; cell?: Cell }) {
  switch (field.control) {
    case "segmented":
      return <Segmented field={field} cell={cell} />;
    case "select":
    case "radio":
      return <EnumValue field={field} cell={cell} />;
    case "password":
      return <Password cell={cell} />;
    case "port":
    case "ipaddress":
    case "time":
      return cell?.display_value ? (
        <span className="font-mono tnum text-sm">{cell.display_value}</span>
      ) : (
        <Empty />
      );
    default:
      return cell?.display_value ? (
        <span className="text-sm">{cell.display_value}</span>
      ) : (
        <Empty />
      );
  }
}
