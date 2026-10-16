import * as React from "react";
import { Hash, Phone, Tag } from "lucide-react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import type { SchemaField } from "@/lib/schema";
import { useStore } from "@/store/useStore";

interface FieldHit {
  programKey: string;
  programLabel: string;
  field: SchemaField;
}

// The command palette (DESIGN_PLAN 3.5): one input, sectioned results. Jump by
// program number, menu/program name, field title, or a DN/box/value held in the
// snapshot. Filtering is ours (shouldFilter=false) so a numeric query ranks a
// program number first and a value search can scan the working copy.
export function CommandPalette() {
  const {
    open,
    setPaletteOpen,
    schema,
    programViews,
    openProgram,
  } = useStore((s) => ({
    open: s.paletteOpen,
    setPaletteOpen: s.setPaletteOpen,
    schema: s.schema,
    programViews: s.programViews,
    openProgram: s.openProgram,
  }));
  const [query, setQuery] = React.useState("");

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen(!open);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, setPaletteOpen]);

  const fieldIndex = React.useMemo<FieldHit[]>(() => {
    if (!schema) return [];
    const out: FieldHit[] = [];
    for (const prog of Object.values(schema.programs)) {
      for (const field of prog.fields) {
        if (field.control === "hidden") continue;
        out.push({ programKey: prog.catalog_key, programLabel: prog.label, field });
      }
    }
    return out;
  }, [schema]);

  const q = query.trim().toLowerCase();

  const programHits = React.useMemo(() => {
    if (!schema || !q) return [];
    const hits = Object.values(schema.programs).filter((p) => {
      return (
        (p.program_number && p.program_number.toLowerCase().startsWith(q)) ||
        p.label.toLowerCase().includes(q) ||
        p.program_name.toLowerCase().includes(q) ||
        p.menu_path.toLowerCase().includes(q)
      );
    });
    hits.sort((a, b) => {
      const an = a.program_number === q ? 0 : a.program_number?.startsWith(q) ? 1 : 2;
      const bn = b.program_number === q ? 0 : b.program_number?.startsWith(q) ? 1 : 2;
      return an - bn;
    });
    return hits.slice(0, 7);
  }, [schema, q]);

  const fieldHits = React.useMemo(() => {
    if (q.length < 2) return [];
    return fieldIndex
      .filter((h) => h.field.title.toLowerCase().includes(q))
      .slice(0, 7);
  }, [fieldIndex, q]);

  // DN / value jump: scan the working copy's rows for a key or value match.
  const valueHits = React.useMemo(() => {
    if (q.length < 2) return [];
    const out: Array<{ programKey: string; label: string; rowKey: string }> = [];
    for (const pv of Object.values(programViews)) {
      for (const row of pv.rows) {
        const hitKey = (row.key || row.index).toLowerCase().includes(q);
        const hitVal =
          !hitKey &&
          row.cells.some((c) => (c.display_value ?? "").toLowerCase().includes(q));
        if (hitKey || hitVal) {
          out.push({ programKey: pv.catalog_key, label: pv.label, rowKey: row.key || row.index });
          if (out.length >= 8) return out;
        }
      }
    }
    return out;
  }, [programViews, q]);

  const go = (key: string, title: string) => {
    openProgram(key, title);
    setPaletteOpen(false);
    setQuery("");
  };

  return (
    <CommandDialog open={open} onOpenChange={setPaletteOpen} shouldFilter={false}>
      <CommandInput
        placeholder="Jump to a program number, menu, field, or DN…"
        value={query}
        onValueChange={setQuery}
      />
      <CommandList>
        {q && <CommandEmpty>No matches.</CommandEmpty>}
        {valueHits.length > 0 && (
          <CommandGroup heading="In the snapshot">
            {valueHits.map((h, i) => (
              <CommandItem
                key={`v-${h.programKey}-${h.rowKey}-${i}`}
                value={`v-${i}`}
                onSelect={() => go(h.programKey, h.label)}
              >
                <Phone className="h-4 w-4 text-fg-3" />
                <span className="font-mono tnum">{h.rowKey}</span>
                <span className="ml-auto text-2xs text-fg-3">{h.label}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {programHits.length > 0 && (
          <CommandGroup heading="Programs">
            {programHits.map((p) => (
              <CommandItem
                key={p.catalog_key}
                value={`p-${p.catalog_key}`}
                onSelect={() => go(p.catalog_key, p.label)}
              >
                <Hash className="h-4 w-4 text-fg-3" />
                {p.program_number && <span className="field-badge">{p.program_number}</span>}
                <span className="truncate">{p.program_name}</span>
                <span className="ml-auto truncate text-2xs text-fg-3">{p.menu_area}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {fieldHits.length > 0 && (
          <CommandGroup heading="Fields">
            {fieldHits.map((h, i) => (
              <CommandItem
                key={`f-${h.programKey}-${h.field.name}-${i}`}
                value={`f-${i}`}
                onSelect={() => go(h.programKey, h.programLabel)}
              >
                <Tag className="h-4 w-4 text-fg-3" />
                <span className="truncate">{h.field.title}</span>
                <span className="ml-auto truncate text-2xs text-fg-3">{h.programLabel}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
      </CommandList>
    </CommandDialog>
  );
}
