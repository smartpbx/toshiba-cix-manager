import * as React from "react";
import { HelpCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { SchemaField } from "@/lib/schema";
import type { Cell } from "@/lib/types";

// The `?` popover (DESIGN_PLAN 3.3): the honest field facts the schema holds —
// native title, OID, raw value, syntax, access, range and enum options. No
// fabricated "Possible values" prose (the catalog does not carry help text).
export function HelpPopover({ field, cell }: { field: SchemaField; cell?: Cell }) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const rows: Array<[string, React.ReactNode]> = [
    ["Field", field.name],
    ["OID", <span className="font-mono text-2xs">{field.oid}</span>],
    ["Syntax", field.syntax],
    ["Access", field.access === "rw" ? "read / write" : "read-only"],
  ];
  if (field.len) rows.push(["Range / length", field.len]);
  if (cell) {
    rows.push([
      "Raw value",
      <span className="font-mono tnum">{String(cell.raw_value ?? "")}</span>,
    ]);
  }

  return (
    <div ref={ref} className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "inline-flex h-5 w-5 items-center justify-center rounded text-fg-3 hover:bg-surface-2 hover:text-fg-2",
          open && "bg-surface-2 text-fg",
        )}
        aria-label={`Help for ${field.title}`}
      >
        <HelpCircle className="h-3.5 w-3.5" />
      </button>
      {open && (
        <div className="absolute right-0 top-6 z-50 w-72 rounded-md border border-line-strong bg-surface p-3 text-xs shadow-lg">
          <div className="mb-2 font-semibold text-foreground">{field.title}</div>
          <dl className="space-y-1">
            {rows.map(([k, v], i) => (
              <div key={i} className="flex gap-2">
                <dt className="w-24 shrink-0 text-fg-3">{k}</dt>
                <dd className="min-w-0 break-words text-fg-2">{v}</dd>
              </div>
            ))}
          </dl>
          {field.enum_values && (
            <div className="mt-2 border-t border-border pt-2">
              <div className="mb-1 text-fg-3">Values</div>
              <ul className="space-y-0.5">
                {Object.entries(field.enum_values).map(([raw, cap]) => (
                  <li key={raw} className="flex gap-2">
                    <span className="field-badge">{raw}</span>
                    <span className="text-fg-2">{cap}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
