import { PageHeader } from "@/components/PageHeader";
import { Card, CardContent } from "@/components/ui/card";
import { humanizeFieldName } from "@/lib/normalize";
import { useStore } from "@/store/useStore";

function KVSection({ title, data }: { title: string; data: Record<string, unknown> }) {
  const entries = Object.entries(data).filter(([, v]) => v !== null && v !== undefined);
  if (entries.length === 0) return null;
  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-2 text-2xs font-semibold uppercase tracking-wide text-fg-2">
          {title}
        </div>
        <div className="grid grid-cols-1 gap-x-8 gap-y-1 sm:grid-cols-2">
          {entries.map(([k, v]) => (
            <div
              key={k}
              className="flex items-baseline justify-between gap-3 border-b border-border/60 py-1 last:border-0"
            >
              <span className="truncate text-fg-2">{humanizeFieldName(k)}</span>
              <span className="shrink-0 font-mono text-sm tnum">{String(v)}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export function SystemView() {
  const doc = useStore((s) => s.doc)!;
  const sys = doc.system || {};
  const { status = {}, numbering_config = {}, ...scalars } = sys as Record<string, unknown> & {
    status?: Record<string, unknown>;
    numbering_config?: Record<string, unknown>;
  };

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="System" subtitle="System Data (105) · Voice Mail Data (579)" />
      <div className="flex-1 space-y-4 overflow-auto p-4">
        <KVSection title="Identity & system scalars" data={scalars} />
        <KVSection title="Voice mail / numbering config (579)" data={numbering_config} />
        <KVSection title="Status / other scalars" data={status} />
      </div>
    </div>
  );
}
