import * as React from "react";
import { LayoutGrid, Phone, PhoneCall, Search, Settings, Timer } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import type { SchemaProgram } from "@/lib/schema";
import { useStore } from "@/store/useStore";

function Fact({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 rounded-md border border-border bg-surface px-3 py-2">
      <span className="text-2xs uppercase tracking-wide text-fg-3">{label}</span>
      <span className="truncate text-sm font-medium">{value ?? "—"}</span>
    </div>
  );
}

export function HomeView() {
  const {
    schema,
    identity,
    meta,
    readCount,
    rowCounts,
    hasSnapshot,
    openProgram,
    setPaletteOpen,
    setConnectDrawerOpen,
  } = useStore((s) => ({
    schema: s.schema,
    identity: s.identity,
    meta: s.snapshotMeta,
    readCount: s.readKeys.size,
    rowCounts: s.rowCounts,
    hasSnapshot: s.progress.status === "done" || s.progress.status === "cold" ||
      s.readKeys.size > 0,
    openProgram: s.openProgram,
    setPaletteOpen: s.setPaletteOpen,
    setConnectDrawerOpen: s.setConnectDrawerOpen,
  }));

  const byNumber = React.useMemo(() => {
    const m = new Map<string, SchemaProgram>();
    if (schema) {
      for (const p of Object.values(schema.programs)) {
        if (p.program_number) m.set(p.program_number, p);
      }
    }
    return m;
  }, [schema]);

  const count = (num: string) => {
    const p = byNumber.get(num);
    return p ? (rowCounts[p.catalog_key] ?? 0) : 0;
  };

  const tasks: Array<{ icon: LucideIcon; label: string; onClick: () => void }> = [];
  tasks.push({ icon: Search, label: "Find a user / DN", onClick: () => setPaletteOpen(true) });
  const addJump = (num: string, icon: LucideIcon, label: string) => {
    const p = byNumber.get(num);
    if (p) tasks.push({ icon, label, onClick: () => openProgram(p.catalog_key, p.label) });
  };
  addJump("200", Phone, "Stations");
  addJump("300", PhoneCall, "Trunks");
  addJump("103", Settings, "Class of Service");
  addJump("105", LayoutGrid, "System Data");
  addJump("104", Timer, "System Timers");

  const swid = identity?.software_id ?? identity?.swid ?? null;

  return (
    <div className="flex h-full flex-col overflow-auto">
      <PageHeader
        title="Home"
        subtitle="Connected Equipment Details"
      />
      <div className="space-y-5 p-4">
        {!hasSnapshot && (
          <Card className="flex flex-col items-start gap-2 p-5">
            <div className="text-sm font-semibold">No snapshot yet</div>
            <p className="max-w-md text-sm text-fg-2">
              Connect to a CIX over SNMP to read a snapshot, then browse every
              program with eManager&apos;s own names. Browsing reads the local
              snapshot — only Connect and Refresh touch the device.
            </p>
            <Button onClick={() => setConnectDrawerOpen(true)}>Connect…</Button>
          </Card>
        )}

        <div>
          <div className="mb-2 text-2xs font-semibold uppercase tracking-wide text-fg-3">
            What do you want to do?
          </div>
          <div className="flex flex-wrap gap-2">
            {tasks.map((t) => (
              <Button key={t.label} variant="outline" size="sm" onClick={t.onClick}>
                <t.icon className="h-4 w-4" />
                {t.label}
              </Button>
            ))}
          </div>
        </div>

        {hasSnapshot && (
          <div>
            <div className="mb-2 text-2xs font-semibold uppercase tracking-wide text-fg-3">
              Equipment
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
              <Fact label="Software id" value={swid} />
              <Fact label="Chassis MAC" value={identity?.chassis_mac} />
              <Fact label="Source" value={meta?.source_ip} />
              <Fact label="Site" value={meta?.site} />
              <Fact label="Stations (200)" value={count("200") || "—"} />
              <Fact label="Trunks (300)" value={count("300") || "—"} />
              <Fact label="Programs read" value={readCount} />
              <Fact label="OIDs read" value={meta?.oids_read} />
              <Fact label="Catalog" value={meta?.catalog_version} />
              <Fact label="Snapshot" value={meta?.read_at} />
            </div>
            {meta?.walk_error && (
              <p className="mt-2 text-xs text-warn">
                Partial read: {meta.walk_error}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
