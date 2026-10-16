import * as React from "react";
import { Globe, Loader2, Plug, Radar } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import type { DiscoverCandidate } from "@/lib/types";
import { useStore } from "@/store/useStore";

type Msg = { kind: "info" | "ok" | "err"; text: string } | null;

export function ConnectView() {
  const {
    form,
    setForm,
    setConnState,
    setIdentity,
    setDoc,
    setView,
  } = useStore((s) => ({
    form: s.form,
    setForm: s.setForm,
    setConnState: s.setConnState,
    setIdentity: s.setIdentity,
    setDoc: s.setDoc,
    setView: s.setView,
  }));

  const [msg, setMsg] = React.useState<Msg>(null);
  const [busy, setBusy] = React.useState<"" | "test" | "read" | "discover">("");
  const [candidates, setCandidates] = React.useState<DiscoverCandidate[]>([]);

  const needIp = () => {
    if (!form.ip.trim()) {
      setMsg({ kind: "err", text: "Enter the CIX IP address first." });
      return false;
    }
    return true;
  };

  const body = () => ({
    ip: form.ip.trim(),
    community: form.community.trim() || "communityName",
    port: form.port || 161,
  });

  const test = async () => {
    if (!needIp()) return;
    setBusy("test");
    setConnState("testing");
    setMsg({ kind: "info", text: `Testing SNMP to ${form.ip}…` });
    try {
      const res = await api.connect(body());
      if (res.ok) {
        setConnState("ok");
        setIdentity({ software_id: res.software_id, chassis_mac: res.chassis_mac });
        setMsg({
          kind: "ok",
          text: `Connected. Software id: ${res.software_id}${res.chassis_mac ? ` · MAC ${res.chassis_mac}` : ""}`,
        });
      } else {
        setConnState("error");
        setMsg({ kind: "err", text: res.error || "No CIX answered." });
      }
    } catch (e) {
      setConnState("error");
      setMsg({ kind: "err", text: `Request failed: ${(e as Error).message}` });
    } finally {
      setBusy("");
    }
  };

  const read = async () => {
    if (!needIp()) return;
    setBusy("read");
    setConnState("reading");
    setMsg({
      kind: "info",
      text: `Reading ${form.ip}${form.scope === "all" ? " (full MIB — this can take a few minutes)" : ""}…`,
    });
    try {
      const timeout = form.reach === "remote" ? 5 : 3;
      const retries = form.reach === "remote" ? 2 : 1;
      const res = await api.read({ ...body(), scope: form.scope, timeout, retries });
      if (res.ok && res.doc) {
        setDoc(res.doc, res.report);
        setConnState("ok");
        setIdentity({
          software_id: res.doc.system.software_id,
          chassis_mac: res.doc.system.chassis_mac,
        });
        setMsg({ kind: "ok", text: `Read ${res.doc.stations.length} stations. Opening Overview…` });
        setView("overview");
      } else {
        setConnState("error");
        setMsg({ kind: "err", text: res.error || "Read failed." });
      }
    } catch (e) {
      setConnState("error");
      setMsg({ kind: "err", text: `Request failed: ${(e as Error).message}` });
    } finally {
      setBusy("");
    }
  };

  const discover = async () => {
    setBusy("discover");
    setMsg({ kind: "info", text: "Scanning the local network (ARP + ping sweep)…" });
    try {
      const res = await api.discover();
      const cands = res.candidates || [];
      setCandidates(cands);
      setMsg(
        cands.length
          ? { kind: "ok", text: `Found ${cands.length} candidate(s).` }
          : { kind: "info", text: "No candidates found. Enter the IP manually, or try the .253 convention." },
      );
    } catch (e) {
      setMsg({ kind: "err", text: `Request failed: ${(e as Error).message}` });
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="mx-auto max-w-2xl p-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Connect to a CIX</CardTitle>
          <CardDescription>
            It is just SNMP to an IP — direct on the voice LAN, or remote over an
            RSM NAT VIP / tunnel. Reads are read-only (GET/GETNEXT).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-5">
          {/* Reach */}
          <div className="flex flex-col gap-1.5">
            <Label>Reach via</Label>
            <div className="flex gap-2">
              {(["direct", "remote"] as const).map((r) => (
                <button
                  key={r}
                  onClick={() => setForm({ reach: r })}
                  className={cn(
                    "flex flex-1 items-center gap-2 rounded-md border px-3 py-2 text-sm",
                    form.reach === r
                      ? r === "remote"
                        ? "border-remote bg-remote-tint text-remote"
                        : "border-primary bg-accent-tint text-primary"
                      : "border-border hover:bg-surface-2",
                  )}
                >
                  {r === "remote" ? <Globe className="h-4 w-4" /> : <Plug className="h-4 w-4" />}
                  {r === "remote" ? "Remote (overlay / RSM)" : "Direct (voice LAN)"}
                </button>
              ))}
            </div>
          </div>

          {/* SNMP */}
          <div className="grid grid-cols-[1fr_auto_auto] gap-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ip">PBX address</Label>
              <Input
                id="ip"
                placeholder="192.168.254.253"
                value={form.ip}
                onChange={(e) => setForm({ ip: e.target.value })}
                className="font-mono tnum"
              />
            </div>
            <div className="flex w-28 flex-col gap-1.5">
              <Label htmlFor="community">Community</Label>
              <Input
                id="community"
                value={form.community}
                onChange={(e) => setForm({ community: e.target.value })}
                className="font-mono"
              />
            </div>
            <div className="flex w-20 flex-col gap-1.5">
              <Label htmlFor="port">Port</Label>
              <Input
                id="port"
                type="number"
                value={form.port}
                onChange={(e) => setForm({ port: parseInt(e.target.value, 10) || 161 })}
                className="font-mono tnum"
              />
            </div>
          </div>

          {/* Scope */}
          <div className="flex flex-col gap-1.5">
            <Label>Read scope on connect</Label>
            <Select
              value={form.scope}
              onValueChange={(v) => setForm({ scope: v as "core" | "all" })}
            >
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="core">Core — stations, system, network (fast)</SelectItem>
                <SelectItem value="all">All — full catalog (slower)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {msg && (
            <div
              className={cn(
                "rounded-md border px-3 py-2 text-sm",
                msg.kind === "ok" && "border-ok/40 bg-ok-tint text-ok",
                msg.kind === "err" && "border-bad/40 bg-bad-tint text-bad",
                msg.kind === "info" && "border-border bg-surface-2 text-fg-2",
              )}
            >
              {busy && <Loader2 className="mr-2 inline h-4 w-4 animate-spin" />}
              {msg.text}
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={test} disabled={!!busy}>
              Test
            </Button>
            <Button onClick={read} disabled={!!busy}>
              {busy === "read" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plug className="h-4 w-4" />}
              Read CIX
            </Button>
            <Button variant="ghost" onClick={discover} disabled={!!busy}>
              <Radar className="h-4 w-4" />
              Auto-discover
            </Button>
          </div>

          {candidates.length > 0 && (
            <div className="rounded-md border border-border">
              <div className="border-b border-border bg-surface-2 px-3 py-1.5 text-2xs font-semibold uppercase tracking-wide text-fg-2">
                Discovered on the LAN
              </div>
              {candidates.map((c) => (
                <div
                  key={c.ip}
                  className="flex items-center gap-3 border-b border-border px-3 py-1.5 text-sm last:border-0"
                >
                  <span className="font-mono tnum">{c.ip}</span>
                  <span className="font-mono text-xs text-fg-2">{c.mac}</span>
                  <span className="flex-1 truncate text-fg-2">{c.software_id}</span>
                  <Button size="sm" variant="secondary" onClick={() => setForm({ ip: c.ip })}>
                    Use
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
