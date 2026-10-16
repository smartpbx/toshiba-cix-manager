import { AlertTriangle } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useStore } from "@/store/useStore";

function Fact({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <div className="text-2xs font-semibold uppercase tracking-wide text-fg-3">{label}</div>
      <div className={mono ? "font-mono text-sm tnum" : "text-sm"}>{value ?? "—"}</div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="flex flex-col gap-1 p-4">
        <div className="text-2xl font-semibold tnum">{value ?? 0}</div>
        <div className="text-xs text-fg-2">{label}</div>
      </CardContent>
    </Card>
  );
}

export function OverviewView() {
  const doc = useStore((s) => s.doc)!;
  const sys = doc.system;
  const stats = doc.stats || {};
  const findings = doc.security_findings || [];

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Overview"
        subtitle="Connected Equipment Details"
      />
      <div className="flex-1 space-y-4 overflow-auto p-4">
        {findings.length > 0 && (
          <div className="space-y-2">
            {findings.map((f) => (
              <div
                key={f.code}
                className="flex items-start gap-2 rounded-md border border-bad/40 bg-bad-tint px-3 py-2 text-sm text-bad"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div>
                  <span className="font-semibold uppercase">{f.severity}</span> — {f.detail}
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Stations" value={stats.stations} />
          <Stat label="Equipment rows" value={stats.equipment_rows} />
          <Stat label="Network / FTP rows" value={stats.network_access_rows} />
          <Stat label="OIDs read" value={doc.device?.oids_read} />
        </div>

        <Card>
          <CardContent className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-3">
            <Fact label="Software id" value={sys.software_id as string} mono />
            <Fact label="Chassis MAC" value={sys.chassis_mac as string} mono />
            <Fact label="Address" value={doc.device?.ip} mono />
            <Fact label="SNMP port" value={doc.device?.port} mono />
            <Fact label="Scope" value={doc.device?.scope} />
            <Fact
              label="Walk"
              value={doc.device?.walk_error ? <Badge variant="warn">partial</Badge> : <Badge variant="ok">complete</Badge>}
            />
          </CardContent>
        </Card>

        {sys.numbering_config && Object.keys(sys.numbering_config).length > 0 && (
          <Card>
            <CardContent className="p-4">
              <div className="mb-2 text-2xs font-semibold uppercase tracking-wide text-fg-2">
                Voice mail integration (579/580)
              </div>
              <div className="grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-3">
                {Object.entries(sys.numbering_config).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2 text-sm">
                    <span className="truncate text-fg-2">{k}</span>
                    <span className="font-mono tnum">{String(v)}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
