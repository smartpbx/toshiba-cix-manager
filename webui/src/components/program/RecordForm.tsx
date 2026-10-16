import * as React from "react";
import { ChevronDown, ChevronRight, Pencil, Plus, X } from "lucide-react";
import type { SchemaField, SchemaProgram } from "@/lib/schema";
import type { Cell, Row } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { FieldRow } from "./FieldRow";
import { FieldControl } from "./FieldControl";
import { EditableField } from "./EditableField";
import { HelpPopover } from "./HelpPopover";
import { useStore } from "@/store/useStore";

// A record rendered as a grouped form (DESIGN_PLAN 3.3): primary fields first,
// the rest under "Advanced (N)". Read-only by default; when there is a live
// session the "Edit" button turns writable fields into inputs. Staging a change
// NEVER writes — it drops the edit into the pending tray (DESIGN_PLAN §9 layer
// 2); the one write is the Review & Write dialog.

function isWritable(program: SchemaProgram, f: SchemaField): boolean {
  if (program.never_write) return false;
  if (program.program_number === "116") return false; // hard exclusion (layer 7)
  return (
    f.writable && !f.key && f.control !== "hidden" && f.control !== "action"
  );
}

// The value we edit (and compare for no-ops): an enum edits by raw value, every
// other field by its literal display string — matching how it goes on the wire.
function editValue(f: SchemaField, cell?: Cell): string {
  if (f.enum_values && cell?.raw_value != null) return String(cell.raw_value);
  return cell?.display_value ?? "";
}

function EditableFieldRow({
  field,
  value,
  onChange,
}: {
  field: SchemaField;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex items-start gap-2 py-1">
      <span className="field-badge mt-1.5" title={`field ${field.display_no}`}>
        {field.display_no}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-fg-2" title={field.name}>
            {field.title}
          </span>
          {field.is_secret && (
            <span className="rounded bg-warn-tint px-1 text-[10px] uppercase text-warn">
              secret
            </span>
          )}
        </div>
        <div className="mt-0.5">
          <EditableField field={field} value={value} onChange={onChange} />
        </div>
      </div>
      <HelpPopover field={field} cell={undefined} />
    </div>
  );
}

export function RecordForm({
  program,
  row,
}: {
  program: SchemaProgram;
  row?: Row;
}) {
  const [showAdvanced, setShowAdvanced] = React.useState(false);
  const [editing, setEditing] = React.useState(false);
  const [draft, setDraft] = React.useState<Record<string, string>>({});

  const sessionId = useStore((s) => s.sessionId);
  const stageRowChanges = useStore((s) => s.stageRowChanges);

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
  if (primary.length === 0) {
    primary.push(...advanced.splice(0, Math.min(6, advanced.length)));
  }

  const anyWritable = visible.some((f) => isWritable(program, f));
  const canEdit = !!sessionId && !!row && anyWritable;

  const originals = React.useMemo(() => {
    const o: Record<string, string> = {};
    for (const f of visible) {
      if (isWritable(program, f)) o[f.name] = editValue(f, cellByName[f.name]);
    }
    return o;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [program, cellByName]);

  function startEdit() {
    setDraft({ ...originals });
    setEditing(true);
  }
  function cancelEdit() {
    setEditing(false);
    setDraft({});
  }
  async function stage() {
    if (!row) return;
    const changes: Record<string, string> = {};
    for (const [field, value] of Object.entries(draft)) {
      if (value !== (originals[field] ?? "")) changes[field] = value;
    }
    if (Object.keys(changes).length > 0) {
      await stageRowChanges(program.catalog_key, row.index, changes, originals);
    }
    cancelEdit();
  }

  const dirtyCount = Object.entries(draft).filter(
    ([f, v]) => v !== (originals[f] ?? ""),
  ).length;

  const renderField = (f: SchemaField) => {
    if (editing && isWritable(program, f)) {
      return (
        <EditableFieldRow
          key={f.name}
          field={f}
          value={draft[f.name] ?? ""}
          onChange={(v) => setDraft((d) => ({ ...d, [f.name]: v }))}
        />
      );
    }
    if (!editing) return <FieldRow key={f.name} field={f} cell={cellByName[f.name]} />;
    // editing but read-only field: show its value, muted
    return (
      <div key={f.name} className="flex items-start gap-2 py-1 opacity-70">
        <span className="field-badge mt-0.5">{f.display_no}</span>
        <div className="min-w-0 flex-1">
          <div className="text-xs italic text-fg-3" title={f.name}>
            {f.title}
          </div>
          <div className="mt-0.5">
            <FieldControl field={f} cell={cellByName[f.name]} />
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="divide-y divide-border/60">
      <div className="flex items-center justify-between gap-2 pb-1">
        {program.danger ? (
          <div className="flex items-center gap-2 border-l-2 border-bad bg-bad-tint px-2 py-1 text-xs text-bad">
            Danger program — changes here are high-impact.
          </div>
        ) : (
          <span />
        )}
        {canEdit &&
          (editing ? (
            <div className="flex items-center gap-1.5">
              <Button size="sm" variant="ghost" onClick={cancelEdit}>
                <X className="h-3.5 w-3.5" /> Cancel
              </Button>
              <Button size="sm" onClick={stage} disabled={dirtyCount === 0}>
                <Plus className="h-3.5 w-3.5" />
                Stage {dirtyCount > 0 ? dirtyCount : ""}
              </Button>
            </div>
          ) : (
            <Button size="sm" variant="outline" onClick={startEdit}>
              <Pencil className="h-3.5 w-3.5" /> Edit
            </Button>
          ))}
      </div>
      {primary.map(renderField)}
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
          {showAdvanced && advanced.map(renderField)}
        </div>
      )}
    </div>
  );
}
