import { Globe, Loader2, Plug } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

// Connect (DESIGN_PLAN 5.1): reach direct or over the overlay, SNMP address /
// community / port, an optional site label, then start the snapshot. Also
// "Open last snapshot" for cold start — browse with the device off.
export function ConnectDrawer() {
  const { open, setOpen, form, setForm, connect, openColdSnapshot, progress } =
    useStore(
      useShallow((s) => ({
        open: s.connectDrawerOpen,
        setOpen: s.setConnectDrawerOpen,
        form: s.form,
        setForm: s.setForm,
        connect: s.connect,
        openColdSnapshot: s.openColdSnapshot,
        progress: s.progress,
      })),
    );

  const busy = progress.status === "connecting";

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Connect to a CIX</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label className="mb-1 block text-xs text-fg-2">Reach via</Label>
            <div className="flex gap-2">
              {(["direct", "remote"] as const).map((r) => (
                <button
                  key={r}
                  onClick={() => setForm({ reach: r })}
                  className={cn(
                    "flex flex-1 items-center justify-center gap-1.5 rounded-md border px-3 py-1.5 text-sm",
                    form.reach === r
                      ? r === "remote"
                        ? "border-remote bg-remote-tint text-remote"
                        : "border-primary bg-accent-tint text-primary"
                      : "border-border text-fg-2 hover:bg-surface-2",
                  )}
                >
                  {r === "remote" ? <Globe className="h-4 w-4" /> : <Plug className="h-4 w-4" />}
                  {r === "remote" ? "Remote (overlay / RSM)" : "Direct (voice LAN)"}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-[1fr_auto] gap-3">
            <div>
              <Label className="mb-1 block text-xs text-fg-2">PBX address (SNMP)</Label>
              <Input
                value={form.ip}
                placeholder="192.168.254.253"
                onChange={(e) => setForm({ ip: e.target.value })}
                className="font-mono"
              />
            </div>
            <div className="w-24">
              <Label className="mb-1 block text-xs text-fg-2">Port</Label>
              <Input
                type="number"
                value={form.port}
                onChange={(e) => setForm({ port: Number(e.target.value) || 161 })}
                className="font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="mb-1 block text-xs text-fg-2">Community</Label>
              <Input
                value={form.community}
                onChange={(e) => setForm({ community: e.target.value })}
                className="font-mono"
              />
            </div>
            <div>
              <Label className="mb-1 block text-xs text-fg-2">Site label</Label>
              <Input
                value={form.site}
                placeholder="104670 Toner Farms"
                onChange={(e) => setForm({ site: e.target.value })}
              />
            </div>
          </div>

          {progress.status === "error" && (
            <p className="text-sm text-bad">{progress.message}</p>
          )}

          <div className="flex items-center gap-2 pt-1">
            <Button onClick={() => connect()} disabled={busy || !form.ip.trim()}>
              {busy && <Loader2 className="h-4 w-4 animate-spin" />}
              Connect &amp; snapshot
            </Button>
            <Button
              variant="outline"
              onClick={() => openColdSnapshot()}
              disabled={!form.site_id}
              title={
                form.site_id
                  ? "Browse the last saved snapshot with the device off"
                  : "Connect once to a site to enable cold start"
              }
            >
              Open last snapshot
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
