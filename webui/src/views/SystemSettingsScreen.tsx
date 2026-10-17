import * as React from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { enumCaption, type SchemaField, type SchemaProgram } from "@/lib/schema";
import type { Cell, ProgramView, Row } from "@/lib/types";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { RecordForm } from "@/components/program/RecordForm";
import { useStore } from "@/store/useStore";

const ADVANCED = "Advanced";

function cellMap(row: Row | undefined): Record<string, Cell> {
  const m: Record<string, Cell> = {};
  for (const c of row?.cells ?? []) m[c.field_name] = c;
  return m;
}
function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

// System settings (105) — the redesign's single-record form page: a "contents"
// rail of the groups, then grouped cards of label / description / control. The
// controls are read-only presentations of the current values (the app is
// "Viewing only" until armed); "Edit…" opens the existing RecordForm stage →
// Review & Write flow, so the write path is untouched.
export function SystemSettingsScreen({
  program,
  view,
}: {
  program: SchemaProgram;
  view: ProgramView;
}) {
  const sessionId = useStore((s) => s.sessionId);
  const [active, setActive] = React.useState<string | null>(null);
  const [editOpen, setEditOpen] = React.useState(false);

  const row = view.rows[0];
  const cells = React.useMemo(() => cellMap(row), [row]);

  // Group visible fields in first-appearance order; ungrouped -> "Advanced".
  const groups = React.useMemo(() => {
    const order: string[] = [];
    const byGroup = new Map<string, SchemaField[]>();
    for (const f of program.fields) {
      if (f.control === "hidden") continue;
      const g = f.group || ADVANCED;
      if (!byGroup.has(g)) {
        byGroup.set(g, []);
        if (g !== ADVANCED) order.push(g);
      }
      byGroup.get(g)!.push(f);
    }
    if (byGroup.has(ADVANCED)) order.push(ADVANCED);
    return order.map((name) => ({
      name,
      heading: name === ADVANCED ? `Advanced (${byGroup.get(name)!.length})` : name,
      fields: byGroup.get(name)!,
    }));
  }, [program.fields]);

  React.useEffect(() => {
    if (!active && groups.length) setActive(groups[0].name);
  }, [groups, active]);

  const scrollTo = (name: string) => {
    setActive(name);
    const el = document.getElementById(`grp-${slug(name)}`);
    el?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const renderControl = (f: SchemaField) => {
    const cell = cells[f.name];
    if (f.is_binary_pair && f.binary_pair) {
      const onActive = cell != null && cell.raw_value === f.binary_pair.on.raw;
      const offActive = cell != null && cell.raw_value === f.binary_pair.off.raw;
      return (
        <span className="inline-flex rounded-[9px] bg-surface-2 p-[3px] text-[12.5px]">
          <span className={cn("rounded-[7px] px-3 py-1", onActive ? "bg-surface font-medium text-foreground shadow-[0_1px_2px_rgba(0,0,0,0.12)]" : "text-fg-3")}>
            {f.binary_pair.on.label}
          </span>
          <span className={cn("rounded-[7px] px-3 py-1", offActive ? "bg-surface font-medium text-foreground shadow-[0_1px_2px_rgba(0,0,0,0.12)]" : "text-fg-3")}>
            {f.binary_pair.off.label}
          </span>
        </span>
      );
    }
    if (f.is_enum || f.enum_values) {
      const val = enumCaption(f, cell?.raw_value, cell?.display_value) || "—";
      return (
        <span className="inline-flex h-8 min-w-[170px] items-center justify-between gap-2 rounded-[8px] border border-border px-3 text-sm">
          <span className="truncate">{val}</span>
          <ChevronDown className="h-[13px] w-[13px] shrink-0 text-fg-3" />
        </span>
      );
    }
    const val = cell?.display_value ?? "";
    return (
      <span className="inline-flex h-8 min-w-[170px] items-center rounded-[8px] border border-border px-3 text-sm">
        <span className="truncate">{val || "—"}</span>
      </span>
    );
  };

  return (
    <div className="flex h-full min-h-0">
      {/* Contents rail */}
      <div className="hidden w-[200px] shrink-0 flex-col gap-0.5 py-7 pl-7 md:flex">
        <div className="mb-2 text-xs text-fg-3">On this page</div>
        {groups.map((g) => (
          <button
            key={g.name}
            onClick={() => scrollTo(g.name)}
            className={cn(
              "rounded-[7px] px-2.5 py-1.5 text-left text-sm",
              active === g.name ? "bg-accent-tint font-medium text-primary" : "text-fg-2 hover:bg-surface-2",
            )}
          >
            {g.name === ADVANCED ? "Advanced" : g.name}
          </button>
        ))}
      </div>

      {/* Body */}
      <div className="min-w-0 flex-1 overflow-auto px-6 py-6 md:px-10">
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-[24px] font-semibold">System settings</h1>
            <div className="mb-[22px] mt-1 text-fg-2">
              Basic behaviour for the whole system. In eManager this is{" "}
              <span className="font-mono text-xs">105 System Data</span>.
            </div>
          </div>
          {sessionId && (
            <button
              onClick={() => setEditOpen(true)}
              className="h-8 shrink-0 rounded-[8px] border border-border bg-surface px-3 text-sm font-medium hover:bg-surface-2"
            >
              Edit…
            </button>
          )}
        </div>

        {groups.map((g) => (
          <div key={g.name} id={`grp-${slug(g.name)}`} className="mb-[22px] max-w-[720px] scroll-mt-4">
            <div className="mb-2 text-[15px] font-semibold">{g.heading}</div>
            <div className="rounded-[12px] border border-border bg-surface">
              {g.fields.map((f, i) => (
                <div
                  key={f.name}
                  className={cn(
                    "flex items-center gap-4 px-4 py-3",
                    i < g.fields.length - 1 && "border-b border-border",
                  )}
                >
                  <div className="min-w-0 flex-1">
                    <div className="font-medium">{f.title}</div>
                    <div className="mt-0.5 text-xs text-fg-3">
                      {f.desc ? `${f.desc} ` : ""}
                      <span className="font-mono text-[10.5px]">· field {f.display_no}</span>
                    </div>
                  </div>
                  <div className="shrink-0">{renderControl(f)}</div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      <Dialog open={editOpen} onOpenChange={setEditOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit system settings</DialogTitle>
          </DialogHeader>
          <div className="max-h-[70vh] overflow-auto">
            <RecordForm program={program} row={row} />
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
