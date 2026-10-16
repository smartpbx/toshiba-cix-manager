import * as React from "react";
import { Loader2 } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, downloadText } from "@/lib/api";
import type { BackupDoc } from "@/lib/types";
import { useStore } from "@/store/useStore";

function label(b: BackupDoc | null): string {
  if (!b) return "empty";
  const m = b.meta || {};
  return `${m.swid ?? "CIX"} · ${m.programs_count ?? Object.keys(b.programs ?? {}).length} prg · ${m.rows_count ?? "?"} rows`;
}

export function BackupDiffView() {
  const { backupA, backupB, setBackupA, setBackupB, form } = useStore((s) => ({
    backupA: s.backupA,
    backupB: s.backupB,
    setBackupA: s.setBackupA,
    setBackupB: s.setBackupB,
    form: s.form,
  }));
  const [busy, setBusy] = React.useState("");
  const [out, setOut] = React.useState("");
  const [err, setErr] = React.useState<string | null>(null);

  const body = () => ({
    ip: form.ip.trim(),
    community: form.community.trim() || "communityName",
    port: form.port || 161,
  });

  const read = async (slot: "A" | "B") => {
    if (!form.ip.trim()) {
      setErr("Set a CIX address on the Connect page first.");
      return;
    }
    setBusy(slot);
    setErr(null);
    try {
      const res = await api.catalogBackup(body());
      if (res.ok && res.backup) {
        if (slot === "A") setBackupA(res.backup);
        else setBackupB(res.backup);
        setOut(res.report || "");
      } else {
        setErr(res.error || "Catalog read failed.");
      }
    } catch (e) {
      setErr(`Request failed: ${(e as Error).message}`);
    } finally {
      setBusy("");
    }
  };

  const diff = async () => {
    if (!backupA || !backupB) return;
    setBusy("diff");
    setErr(null);
    try {
      const res = await api.diff({ a: backupA, b: backupB });
      if (res.ok) setOut(res.report || "(no differences)");
      else setErr(res.error || "Diff failed.");
    } catch (e) {
      setErr(`Request failed: ${(e as Error).message}`);
    } finally {
      setBusy("");
    }
  };

  const slotCard = (slot: "A" | "B", b: BackupDoc | null) => (
    <Card>
      <CardContent className="flex flex-col gap-2 p-4">
        <div className="flex items-center gap-2">
          <Badge variant={b ? "ok" : "secondary"}>Slot {slot}</Badge>
          <span className="truncate text-sm text-fg-2">{label(b)}</span>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => read(slot)} disabled={!!busy}>
            {busy === slot && <Loader2 className="h-4 w-4 animate-spin" />}
            Read into {slot}
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={!b}
            onClick={() =>
              b && downloadText(`cix-backup-${slot}.json`, JSON.stringify(b, null, 2))
            }
          >
            Download JSON
          </Button>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Backup & Diff"
        subtitle="Catalog-driven read · compare two snapshots (programming as source code)"
        actions={
          <Button size="sm" variant="secondary" onClick={diff} disabled={!backupA || !backupB || !!busy}>
            {busy === "diff" && <Loader2 className="h-4 w-4 animate-spin" />}
            Diff A → B
          </Button>
        }
      />
      <div className="flex-1 space-y-4 overflow-auto p-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {slotCard("A", backupA)}
          {slotCard("B", backupB)}
        </div>
        {err && (
          <div className="rounded-md border border-bad/40 bg-bad-tint px-3 py-2 text-sm text-bad">
            {err}
          </div>
        )}
        {out && (
          <pre className="max-h-[50vh] overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-xs tnum whitespace-pre">
            {out}
          </pre>
        )}
      </div>
    </div>
  );
}
