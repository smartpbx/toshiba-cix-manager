import * as React from "react";
import { FileArchive, FileJson, FileText, Loader2 } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardTitle } from "@/components/ui/card";
import { api, downloadBlob, downloadText } from "@/lib/api";
import { useStore } from "@/store/useStore";

export function ExportView() {
  const { doc, report } = useStore((s) => ({ doc: s.doc, report: s.report }));
  const [busy, setBusy] = React.useState(false);

  const stamp = new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
  const base = `cix-${(doc?.device?.ip || "read").replace(/[^\w.-]/g, "_")}-${stamp}`;

  const zip = async () => {
    if (!doc) return;
    setBusy(true);
    try {
      const blob = await api.backupZip(doc);
      downloadBlob(`${base}-backup.zip`, blob);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Export" subtitle="Keep this read as a file" />
      <div className="grid flex-1 grid-cols-1 content-start gap-3 overflow-auto p-4 sm:grid-cols-3">
        <Card>
          <CardContent className="flex flex-col gap-3 p-4">
            <FileJson className="h-5 w-5 text-primary" />
            <CardTitle className="text-base">Programming JSON</CardTitle>
            <CardDescription>
              The full structured read — re-openable in this tool.
            </CardDescription>
            <Button
              variant="outline"
              onClick={() => doc && downloadText(`${base}.json`, JSON.stringify(doc, null, 2))}
            >
              Download .json
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex flex-col gap-3 p-4">
            <FileText className="h-5 w-5 text-primary" />
            <CardTitle className="text-base">Text report</CardTitle>
            <CardDescription>Human-readable report for a ticket.</CardDescription>
            <Button
              variant="outline"
              disabled={!report}
              onClick={() => downloadText(`${base}-report.txt`, report, "text/plain")}
            >
              Download .txt
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex flex-col gap-3 p-4">
            <FileArchive className="h-5 w-5 text-primary" />
            <CardTitle className="text-base">Backup .zip</CardTitle>
            <CardDescription>
              programming.json + report + raw OID walk (engine-built).
            </CardDescription>
            <Button variant="outline" onClick={zip} disabled={busy}>
              {busy && <Loader2 className="h-4 w-4 animate-spin" />}
              Download .zip
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
