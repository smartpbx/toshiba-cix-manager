import { PageHeader } from "@/components/PageHeader";
import { RecordGrid } from "@/components/RecordGrid";
import { useStore } from "@/store/useStore";

export function EquipmentView() {
  const doc = useStore((s) => s.doc)!;
  const rows = doc.equipment ?? [];
  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Equipment"
        subtitle="Maintenance › Hardware Info and Control"
        actions={<div className="text-xs text-fg-2 tnum">{rows.length} rows</div>}
      />
      <div className="min-h-0 flex-1 p-4">
        <RecordGrid
          rows={rows}
          rowKey={(r, i) => `eq-${i}-${render(r.index)}`}
          preferredFirst="index"
          emptyLabel="No equipment rows in this snapshot."
        />
      </div>
    </div>
  );
}

function render(v: unknown): string {
  if (Array.isArray(v)) return v.join(".");
  return String(v ?? "");
}
