import * as React from "react";
import {
  AlertTriangle,
  Download,
  Loader2,
  Plug,
  RefreshCw,
  Unplug,
  X,
} from "lucide-react";
import { PageHeader, EmptyState } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { DataGrid, type GridColumn } from "@/components/DataGrid";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import type {
  VmBoxRow,
  VmBoxDetail,
  VmDiff,
  VmEditorField,
  VmPbxDb,
  VmReport,
  VmReportTemplate,
  VmSysParams,
} from "@/lib/types";
import { useStore, type VmScreen } from "@/store/useStore";

// --------------------------------------------------------------------------
// Dispatcher — one of the VM screens, gated on a live session
// --------------------------------------------------------------------------
export function VoiceMailView({ screen }: { screen: VmScreen }) {
  const { vmStatus, refreshVmStatus } = useStore((s) => ({
    vmStatus: s.vmStatus,
    refreshVmStatus: s.refreshVmStatus,
  }));

  React.useEffect(() => {
    void refreshVmStatus();
  }, [refreshVmStatus]);

  if (!vmStatus?.connected) return <VmConnectPanel />;

  switch (screen) {
    case "status":
      return <VmStatusView />;
    case "boxes":
      return <VmBoxListView />;
    case "sysparams":
      return <VmSysParamsView />;
    case "integration":
      return <VmIntegrationView />;
    case "backup":
      return <VmBackupView />;
    case "reports":
      return <VmReportsView />;
    default:
      return <VmStatusView />;
  }
}

// --------------------------------------------------------------------------
// Connect (VM Manager's Connection List / Login) — the offline demo too
// --------------------------------------------------------------------------
function VmConnectPanel() {
  const { vmConnect, vmBusy } = useStore((s) => ({
    vmConnect: s.vmConnect,
    vmBusy: s.vmBusy,
  }));
  const [kind, setKind] = React.useState<"fake" | "serial" | "tcp">("fake");
  const [port, setPort] = React.useState("/dev/ttyUSB0");
  const [host, setHost] = React.useState("");
  const [tcpPort, setTcpPort] = React.useState("2001");
  const [password, setPassword] = React.useState("Stratagy");
  const [err, setErr] = React.useState<string | null>(null);

  const connect = async () => {
    setErr(null);
    const spec: Record<string, unknown> = { transport: kind, password };
    if (kind === "serial") spec.port = port;
    if (kind === "tcp") {
      spec.host = host;
      spec.port = Number(tcpPort) || 2001;
    }
    const error = await vmConnect(spec);
    if (error) setErr(error);
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Voice Mail" subtitle="Stratagy LVMU — Connection List · Login" />
      <div className="flex min-h-0 flex-1 items-start justify-center overflow-auto p-6">
        <div className="w-full max-w-lg rounded-md border border-border bg-surface p-4">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <Plug className="h-4 w-4 text-fg-2" /> Connect to the voicemail
          </div>
          <div className="space-y-3 text-sm">
            <div>
              <div className="mb-1 text-xs font-medium text-fg-2">Connect using</div>
              <div className="flex flex-wrap gap-2">
                {([
                  ["fake", "Replay capture (offline demo)"],
                  ["serial", "Serial (COM / tty)"],
                  ["tcp", "TCP bridge (RSM Pi)"],
                ] as const).map(([k, label]) => (
                  <button
                    key={k}
                    onClick={() => setKind(k)}
                    className={cn(
                      "rounded-md border px-2.5 py-1 text-xs",
                      kind === k
                        ? "border-primary bg-accent-tint text-primary"
                        : "border-border text-fg-2 hover:bg-surface-2",
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {kind === "serial" && (
              <Labeled label="Port">
                <Input value={port} onChange={(e) => setPort(e.target.value)} className="font-mono" />
              </Labeled>
            )}
            {kind === "tcp" && (
              <div className="flex gap-2">
                <Labeled label="Host (overlay IP)">
                  <Input value={host} onChange={(e) => setHost(e.target.value)} className="font-mono" />
                </Labeled>
                <Labeled label="Port">
                  <Input value={tcpPort} onChange={(e) => setTcpPort(e.target.value)} className="w-24 font-mono" />
                </Labeled>
              </div>
            )}
            <Labeled label="Password">
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="font-mono"
              />
            </Labeled>

            {kind === "fake" && (
              <p className="rounded bg-surface-2 px-2 py-1.5 text-xs text-fg-2">
                Replays a built-in, PII-free card image frame-for-frame — the
                offline twin of the serial line. No hardware needed.
              </p>
            )}
            {err && (
              <div className="rounded border border-bad/40 bg-bad-tint px-2 py-1.5 text-xs text-bad">
                {err}
              </div>
            )}
            <div className="flex justify-end">
              <Button onClick={() => void connect()} disabled={vmBusy}>
                {vmBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plug className="h-4 w-4" />}
                Connect
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Labeled({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block flex-1">
      <div className="mb-1 text-xs font-medium text-fg-2">{label}</div>
      {children}
    </label>
  );
}

// A header with a Disconnect + Refresh action, shared by the connected screens.
function VmHeader({
  title,
  subtitle,
  onRefresh,
  busy,
  extra,
}: {
  title: string;
  subtitle?: string;
  onRefresh?: () => void;
  busy?: boolean;
  extra?: React.ReactNode;
}) {
  const vmDisconnect = useStore((s) => s.vmDisconnect);
  return (
    <PageHeader
      title={title}
      subtitle={subtitle}
      actions={
        <>
          {extra}
          {onRefresh && (
            <Button variant="outline" size="sm" onClick={onRefresh} disabled={busy}
              title="Re-read from the card">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              Refresh
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={() => void vmDisconnect()}
            title="Close the voicemail session">
            <Unplug className="h-4 w-4" /> Disconnect
          </Button>
        </>
      }
    />
  );
}

// --------------------------------------------------------------------------
// Status (Admin › Port Status)
// --------------------------------------------------------------------------
function VmStatusView() {
  const { vmStatus, refreshVmStatus } = useStore((s) => ({
    vmStatus: s.vmStatus,
    refreshVmStatus: s.refreshVmStatus,
  }));
  if (!vmStatus) return <EmptyState message="No status." />;
  const rows: Array<[string, React.ReactNode]> = [
    ["Firmware", vmStatus.firmware || "—"],
    ["Admin box", vmStatus.admin_box || "—"],
    ["Log name", vmStatus.log_name || "—"],
    ["Transport", `${vmStatus.transport} · ${vmStatus.port}`],
    ["Next shutdown", vmStatus.shutdown || "—"],
    ["Trace frames", String(vmStatus.trace_frames)],
    ["Writes", vmStatus.writes_enabled ? "enabled" : "read-only"],
  ];
  return (
    <div className="flex h-full min-h-0 flex-col">
      <VmHeader title="Status" subtitle="Admin › Port Status" onRefresh={() => void refreshVmStatus()} />
      <div className="min-h-0 flex-1 overflow-auto p-4">
        <div className="max-w-xl rounded-md border border-border bg-surface">
          {rows.map(([k, v]) => (
            <div key={k} className="flex items-center gap-3 border-b border-border/60 px-3 py-2 text-sm last:border-0">
              <span className="w-36 shrink-0 text-fg-2">{k}</span>
              <span className="min-w-0 flex-1 font-mono">{v}</span>
            </div>
          ))}
        </div>
        <p className="mt-3 max-w-xl text-xs text-fg-3">
          Per-port rows (last call, call count) are not shown: the Port Status
          opcode is not yet attributed. This panel shows only what the confirmed
          session opcodes return, never a blank guess.
        </p>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------
// Users › Box List (+ read-only User Editor drawer with status dots)
// --------------------------------------------------------------------------
function VmBoxListView() {
  const [boxes, setBoxes] = React.useState<VmBoxRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [filter, setFilter] = React.useState("");
  const [selected, setSelected] = React.useState<string | null>(null);

  const load = React.useCallback(async (refresh = false) => {
    setLoading(true);
    try {
      const res = await api.vm.boxes(refresh);
      if (res.ok) setBoxes(res.boxes);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const rows = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return boxes;
    return boxes.filter(
      (b) => b.box.includes(q) || b.name.toLowerCase().includes(q),
    );
  }, [boxes, filter]);

  const columns: GridColumn<VmBoxRow>[] = [
    { key: "box", header: "User ID", width: 110, sticky: true, mono: true,
      cell: (b) => (
        <span className={cn(b.reserved && "text-fg-3")}>
          {b.box}
          {b.reserved && <span className="ml-1 text-2xs">(reserved)</span>}
        </span>
      ) },
    { key: "name", header: "Name", width: 220, cell: (b) => (
      <span className={cn(b.reserved && "text-fg-3")}>{b.name}</span>
    ) },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col">
      <VmHeader title="Users · Box List" subtitle="User ID | Comment | Extension | Name | Messages"
        onRefresh={() => void load(true)} busy={loading} />
      <div className="flex items-center gap-3 px-4 py-2">
        <Input placeholder="Filter box / name…" value={filter}
          onChange={(e) => setFilter(e.target.value)} className="max-w-xs" />
        <span className="text-xs text-fg-2 tnum">{rows.length} / {boxes.length} boxes</span>
      </div>
      <div className="flex min-h-0 flex-1 gap-3 px-4 pb-4">
        <div className="min-w-0 flex-1">
          <DataGrid columns={columns} rows={rows} rowKey={(b) => b.box}
            selectedKey={selected ?? undefined}
            onRowClick={(b) => setSelected(b.box)}
            emptyLabel={loading ? "Reading directory…" : "No boxes."} />
        </div>
        {selected && (
          <VmUserEditor box={selected} onClose={() => setSelected(null)} />
        )}
      </div>
    </div>
  );
}

const DOT: Record<string, string> = {
  green: "bg-ok",
  amber: "bg-warn",
  grey: "bg-fg-3",
};

function VmUserEditor({ box, onClose }: { box: string; onClose: () => void }) {
  const [detail, setDetail] = React.useState<VmBoxDetail | null>(null);
  const [tab, setTab] = React.useState("Header");
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    let live = true;
    setLoading(true);
    setDetail(null);
    api.vm
      .box(box)
      .then((res) => {
        if (live && res.ok) {
          setDetail(res);
          setTab(res.editor.tabs[0]?.tab ?? "Header");
        }
      })
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [box]);

  const tabs = detail?.editor.tabs ?? [];
  const current = tabs.find((t) => t.tab === tab) ?? tabs[0];
  const values = detail?.editor.values ?? {};
  const mb = detail?.mailbox;

  return (
    <div className="flex w-[420px] shrink-0 flex-col overflow-hidden rounded-md border border-border bg-surface">
      <div className="flex items-center gap-2 border-b border-border bg-surface-2 px-3 py-2">
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-semibold">
            Box {box}{mb?.name ? ` · ${mb.name}` : ""}
          </div>
          <div className="truncate text-2xs text-fg-3">
            {detail?.reserved ? "reserved box · " : ""}read-only (writes disabled)
          </div>
        </div>
        <button onClick={onClose} className="text-fg-3 hover:text-fg-2" aria-label="Close">
          <X className="h-4 w-4" />
        </button>
      </div>
      {loading || !current ? (
        <div className="flex flex-1 items-center justify-center gap-2 text-sm text-fg-2">
          <Loader2 className="h-4 w-4 animate-spin" /> Reading box {box}…
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-1 border-b border-border px-2 py-1.5">
            {tabs.map((t) => (
              <button key={t.tab} onClick={() => setTab(t.tab)}
                className={cn(
                  "rounded px-2 py-0.5 text-xs",
                  t.tab === tab ? "bg-accent-tint text-primary" : "text-fg-2 hover:bg-surface-2",
                )}>
                {t.tab}
              </button>
            ))}
          </div>
          <div className="min-h-0 flex-1 overflow-auto px-3 py-2">
            {current.fields.map((f) => (
              <VmFieldRow key={f.name} field={f} value={values[f.name]} />
            ))}
            {current.fields.length === 0 && (
              <div className="py-4 text-xs text-fg-3">No fields on this tab.</div>
            )}
          </div>
          {mb?.unproven?.length ? (
            <div className="border-t border-border bg-surface-2 px-3 py-2 text-2xs text-fg-3">
              {mb.unproven.map((u, i) => (
                <div key={i} className="flex gap-1">
                  <span>•</span>
                  <span>{u}</span>
                </div>
              ))}
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

function VmFieldRow({ field, value }: { field: VmEditorField; value: unknown }) {
  const readable = field.status === "confirmed";
  const shown =
    value === undefined || value === null || value === ""
      ? readable
        ? "—"
        : field.status === "inferred"
          ? "(write offset unverified — read-only)"
          : "(not yet readable)"
      : field.type === "secret"
        ? "••••"
        : String(value);
  return (
    <div className="flex items-start gap-2 border-b border-border/50 py-1.5 text-sm">
      <span className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", DOT[field.dot])}
        title={`status: ${field.status}`} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1">
          <span className="font-medium">{field.label}</span>
          {field.lock && <span className="text-2xs text-fg-3" title="lockable field">🔒</span>}
        </div>
        {field.tooltip && <div className="text-2xs text-fg-3">{field.tooltip}</div>}
      </div>
      <span className={cn("max-w-[45%] truncate text-right font-mono",
        readable ? "text-foreground" : "text-fg-3")}>
        {shown}
      </span>
    </div>
  );
}

// --------------------------------------------------------------------------
// Configuration › Stratagy System Parameters
// --------------------------------------------------------------------------
function VmSysParamsView() {
  const [sp, setSp] = React.useState<VmSysParams | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [filter, setFilter] = React.useState("");

  const load = React.useCallback(async (refresh = false) => {
    setLoading(true);
    try {
      const res = await api.vm.sysparams(refresh);
      if (res.ok) setSp(res.sysparams);
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => {
    void load();
  }, [load]);

  const params = React.useMemo(() => {
    const q = filter.trim().toLowerCase();
    const list = sp?.params ?? [];
    if (!q) return list;
    return list.filter(
      (p) => p.name.toLowerCase().includes(q) || p.value.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q),
    );
  }, [sp, filter]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <VmHeader title="Stratagy System Parameters"
        subtitle="Parameter Names | Values | Parameter Descriptions (read-only)"
        onRefresh={() => void load(true)} busy={loading} />
      <div className="min-h-0 flex-1 overflow-auto p-4">
        {sp?.findings?.map((f, i) => (
          <div key={i} className="mb-2 flex items-center gap-2 rounded border border-warn/40 bg-warn-tint px-2 py-1.5 text-xs text-warn">
            <AlertTriangle className="h-3.5 w-3.5" /> {f.message}
          </div>
        ))}
        <div className="mb-2 flex items-center gap-2">
          <Input placeholder="Filter parameter…" value={filter}
            onChange={(e) => setFilter(e.target.value)} className="max-w-xs" />
          {sp?.help_status === "partial" && (
            <span className="text-2xs text-fg-3">help: partial (Install.dhp subset)</span>
          )}
        </div>
        <div className="overflow-hidden rounded-md border border-border">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-surface-2 text-left text-2xs uppercase tracking-wide text-fg-2">
                <th className="px-3 py-1.5 font-semibold">Parameter</th>
                <th className="px-3 py-1.5 font-semibold">Value</th>
                <th className="px-3 py-1.5 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              {params.map((p) => (
                <tr key={p.name} className={cn("border-t border-border/60", !p.enabled && "opacity-55")}>
                  <td className="px-3 py-1.5 align-top font-mono">
                    {p.name}
                    {!p.enabled && <span className="ml-1 text-2xs text-fg-3">(default/off)</span>}
                  </td>
                  <td className="px-3 py-1.5 align-top font-mono">
                    {p.value || "—"}
                    {p.decoded && <div className="text-2xs text-fg-3">{p.decoded}</div>}
                  </td>
                  <td className="px-3 py-1.5 align-top text-fg-2">
                    {p.description || <span className="text-fg-3">—</span>}
                    {p.default && <span className="ml-1 text-2xs text-fg-3">(default {p.default})</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-fg-3">
          Read-only: the INSTALL.CFG file-write opcode is not yet captured.
        </p>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------
// Configuration › Telephone System Integration (+ compare with default)
// --------------------------------------------------------------------------
function VmIntegrationView() {
  const [pbx, setPbx] = React.useState<VmPbxDb | null>(null);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.vm.pbxdb(true);
      if (res.ok) setPbx(res.pbxdb);
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => {
    void load();
  }, [load]);

  const cmp = pbx?.compare;
  return (
    <div className="flex h-full min-h-0 flex-col">
      <VmHeader title="Telephone System Integration"
        subtitle={pbx ? `${pbx.pbx_name || pbx.model} · Dial Codes + Integration Patterns` : "Dial Codes + Integration Patterns"}
        onRefresh={() => void load()} busy={loading} />
      <div className="min-h-0 flex-1 overflow-auto p-4">
        {cmp && (
          <div className="mb-3 rounded-md border border-border bg-surface p-3">
            <div className="mb-1 text-sm font-semibold">Compare with Toshiba default</div>
            {!cmp.available ? (
              <div className="text-xs text-fg-3">{cmp.reason}</div>
            ) : cmp.clean ? (
              <div className="text-xs text-ok">Matches the bundled {cmp.model} default.</div>
            ) : (
              <div className="space-y-1 text-xs">
                {cmp.dial_codes.map((c, i) => (
                  <div key={i} className="font-mono">
                    <Badge variant={c.kind === "changed" ? "warn" : "secondary"}>{c.kind}</Badge>{" "}
                    {c.code}: <span className="text-fg-3">default {c.default ?? "—"}</span> → {c.live ?? "—"}
                  </div>
                ))}
                {cmp.integration.map((c, i) => (
                  <div key={`i${i}`} className="font-mono">
                    <Badge variant="secondary">{c.kind}</Badge> integration {c.pattern}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="mb-2 text-sm font-semibold">Dial Codes</div>
        <div className="mb-4 overflow-hidden rounded-md border border-border">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-surface-2 text-left text-2xs uppercase tracking-wide text-fg-2">
                <th className="px-3 py-1.5 font-semibold">Code</th>
                <th className="px-3 py-1.5 font-semibold">Value</th>
                <th className="px-3 py-1.5 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              {(pbx?.dial_codes ?? []).map((d) => (
                <tr key={d.code} className="border-t border-border/60">
                  <td className="px-3 py-1.5 font-mono">{d.code}</td>
                  <td className="px-3 py-1.5 font-mono">{d.value || "—"}</td>
                  <td className="px-3 py-1.5 text-fg-2">{d.label}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="mb-2 text-sm font-semibold">Integration Patterns</div>
        <div className="overflow-hidden rounded-md border border-border">
          <table className="w-full border-collapse text-sm">
            <tbody>
              {(pbx?.integration ?? []).map((p, i) => (
                <tr key={i} className="border-t border-border/60 first:border-0">
                  <td className="px-3 py-1.5 font-mono">{p.pattern}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-fg-3">
          Legend: A/B/N/D/S lead the pattern type; x = ID digits, r = ring/MWI,
          b = busy, c = CO line, s = sub-type, i = inband. Read-only.
        </p>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------
// Tools › Backup to JSON (+ mailbox-level diff of two in-session backups)
// --------------------------------------------------------------------------
type VmBackupDoc = Record<string, unknown> & {
  meta?: { box_count?: number; taken_at?: string; firmware?: string };
};

function VmBackupView() {
  const [a, setA] = React.useState<VmBackupDoc | null>(null);
  const [b, setB] = React.useState<VmBackupDoc | null>(null);
  const [diff, setDiff] = React.useState<VmDiff | null>(null);
  const [busy, setBusy] = React.useState(false);

  const take = async (slot: "a" | "b") => {
    setBusy(true);
    try {
      const res = await api.vm.backupJson();
      if (res.ok) (slot === "a" ? setA : setB)(res.backup as VmBackupDoc);
    } finally {
      setBusy(false);
    }
  };

  const download = async () => {
    setBusy(true);
    try {
      const res = await api.vm.backupJson();
      if (!res.ok) return;
      const blob = new Blob([JSON.stringify(res.backup, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "voicemail-backup.json";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } finally {
      setBusy(false);
    }
  };

  const compare = async () => {
    if (!a || !b) return;
    setBusy(true);
    try {
      const res = await api.vm.diff(a, b);
      if (res.ok) setDiff(res.diff);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <VmHeader title="Backup to JSON" subtitle="Every box + sysparams + dial codes — no call interruption"
        extra={
          <Button size="sm" onClick={() => void download()} disabled={busy}>
            <Download className="h-4 w-4" /> Download backup
          </Button>
        } />
      <div className="min-h-0 flex-1 overflow-auto p-4">
        <p className="mb-3 max-w-2xl text-sm text-fg-2">
          Reads every mailbox, the system parameters and the dial-code /
          integration table over confirmed opcodes <strong>without halting call
          processing</strong> — unlike the native Backup Utility (disabled here
          until its serialization is captured). Take two and compare them per
          mailbox.
        </p>
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void take("a")} disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null} Capture A
          </Button>
          <BackupChip label="A" doc={a} />
          <Button variant="outline" size="sm" onClick={() => void take("b")} disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null} Capture B
          </Button>
          <BackupChip label="B" doc={b} />
          <Button size="sm" onClick={() => void compare()} disabled={busy || !a || !b}>
            Compare A → B
          </Button>
        </div>
        {diff && <VmDiffPane diff={diff} />}
      </div>
    </div>
  );
}

function BackupChip({ label, doc }: { label: string; doc: VmBackupDoc | null }) {
  if (!doc) return <span className="text-2xs text-fg-3">{label}: —</span>;
  return (
    <span className="text-2xs text-fg-2">
      {label}: {doc.meta?.box_count ?? "?"} boxes
    </span>
  );
}

function VmDiffPane({ diff }: { diff: VmDiff }) {
  const boxIds = Object.keys(diff.boxes);
  return (
    <div className="rounded-md border border-border bg-surface p-3 text-sm">
      <div className="mb-2 flex flex-wrap gap-3 text-xs text-fg-2">
        <span>+{diff.summary.boxes_added} added</span>
        <span>−{diff.summary.boxes_removed} removed</span>
        <span>{diff.summary.boxes_changed} changed</span>
        <span>{diff.summary.sysparams_changed} sysparam changes</span>
      </div>
      {boxIds.length === 0 && diff.summary.sysparams_changed === 0 ? (
        <div className="text-xs text-ok">No differences.</div>
      ) : (
        boxIds.map((box) => {
          const bd = diff.boxes[box];
          return (
            <div key={box} className="border-t border-border/60 py-2">
              <div className="font-mono text-xs font-semibold">Box {box}</div>
              {bd.changes.map((c, i) => (
                <div key={i} className="ml-3 text-xs">
                  {c.field}: <span className="text-fg-3">{String(c.old)}</span> → {String(c.new)}
                </div>
              ))}
              {Object.entries(bd.raw).map(([seg, r]) => (
                <div key={seg} className="ml-3 text-2xs text-fg-3">
                  {seg.replace("_hex", "")}: record changed, {r.bytes_differ} bytes differ
                  {r.offsets.length ? ` at offsets ${r.offsets.join(", ")}` : ""}
                </div>
              ))}
            </div>
          );
        })
      )}
    </div>
  );
}

// --------------------------------------------------------------------------
// Reports (client-side, over the read model)
// --------------------------------------------------------------------------
function VmReportsView() {
  const [templates, setTemplates] = React.useState<VmReportTemplate[]>([]);
  const [tid, setTid] = React.useState("directory");
  const [report, setReport] = React.useState<VmReport | null>(null);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    api.vm.reportTemplates().then((r) => {
      if (r.ok) setTemplates(r.templates);
    });
  }, []);

  const run = React.useCallback(async () => {
    setBusy(true);
    try {
      const res = await api.vm.runReport(tid);
      if (res.ok) setReport(res.report);
    } finally {
      setBusy(false);
    }
  }, [tid]);

  const downloadCsv = () => {
    if (!report) return;
    const head = report.columns.map((c) => c.label).join(",");
    const lines = report.rows.map((r) => r.map((v) => `"${v.replace(/"/g, '""')}"`).join(","));
    const blob = new Blob([[head, ...lines].join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `vm-report-${tid}.csv`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <VmHeader title="Reports" subtitle="Client-side over the read model — instant" />
      <div className="flex items-center gap-2 px-4 py-2">
        <select value={tid} onChange={(e) => setTid(e.target.value)}
          className="h-ctl rounded-md border border-border bg-surface px-2 text-sm">
          {templates.map((t) => (
            <option key={t.id} value={t.id}>{t.name}</option>
          ))}
        </select>
        <Button size="sm" onClick={() => void run()} disabled={busy}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null} Run report
        </Button>
        {report && (
          <Button size="sm" variant="outline" onClick={downloadCsv}>
            <Download className="h-4 w-4" /> CSV
          </Button>
        )}
        {report && <span className="text-xs text-fg-2 tnum">{report.row_count} rows</span>}
      </div>
      <div className="min-h-0 flex-1 overflow-auto px-4 pb-4">
        {report ? (
          <div className="overflow-hidden rounded-md border border-border">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="bg-surface-2 text-left text-2xs uppercase tracking-wide text-fg-2">
                  {report.columns.map((c) => (
                    <th key={c.name} className="px-3 py-1.5 font-semibold">{c.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.rows.map((row, i) => (
                  <tr key={i} className="border-t border-border/60">
                    {row.map((v, j) => (
                      <td key={j} className="px-3 py-1.5 font-mono">{v}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="Pick a template and Run report." />
        )}
      </div>
    </div>
  );
}
