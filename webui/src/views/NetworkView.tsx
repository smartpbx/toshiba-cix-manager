import { PageHeader } from "@/components/PageHeader";
import { RecordGrid } from "@/components/RecordGrid";
import { useStore } from "@/store/useStore";

export function NetworkView() {
  const doc = useStore((s) => s.doc)!;
  const rows = doc.network_access ?? [];
  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Network / FTP"
        subtitle="Maintenance › CIX Processor IP Address (916) · SD-card FTP"
        actions={<div className="text-xs text-fg-2 tnum">{rows.length} rows</div>}
      />
      <div className="min-h-0 flex-1 p-4">
        <RecordGrid
          rows={rows}
          rowKey={(r, i) => `net-${i}-${String(r.index ?? "")}`}
          preferredFirst="index"
          emptyLabel="No network / FTP rows in this snapshot."
        />
      </div>
    </div>
  );
}
