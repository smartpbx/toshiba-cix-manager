import * as React from "react";
import {
  Check,
  Globe,
  Loader2,
  Pencil,
  Plug,
  Plus,
  Server,
  Trash2,
  X,
} from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import type { Site } from "@/lib/types";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

// When a site was last connected, in a short relative-ish form. Never throws on
// a missing / malformed timestamp — a saved site may predate the field.
function fmtLastConnected(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const diff = Date.now() - d.getTime();
  const day = 86_400_000;
  if (diff < day && diff >= 0) return "today";
  if (diff < 2 * day && diff >= 0) return "yesterday";
  return d.toLocaleDateString(undefined, { month: "short", day: "2-digit" });
}

function siteSubtitle(site: Site): string {
  const pbx = site.pbx ?? {};
  const host = pbx.host ?? "";
  const port = pbx.port && pbx.port !== 161 ? `:${pbx.port}` : "";
  return host ? `${host}${port}` : "no address";
}

// One saved-site card: click the body to reconnect in one click; rename inline;
// delete with a two-step confirm so a stray click can't lose a site.
function SiteCard({
  site,
  busy,
  onConnect,
  onRename,
  onDelete,
}: {
  site: Site;
  busy: boolean;
  onConnect: (site: Site) => void;
  onRename: (id: string, name: string) => void;
  onDelete: (id: string) => void;
}) {
  const [editing, setEditing] = React.useState(false);
  const [draft, setDraft] = React.useState(site.name);
  const [confirmDelete, setConfirmDelete] = React.useState(false);

  const swid = site.pbx?.identity?.software_id ?? site.pbx?.identity?.swid ?? "";
  const remote = site.pbx?.via === "overlay";
  const last = fmtLastConnected(site.last_connected);

  const saveRename = () => {
    const name = draft.trim();
    if (name && name !== site.name) onRename(site.id, name);
    setEditing(false);
  };

  if (editing) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-border bg-surface px-3 py-2">
        <Input
          autoFocus
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") saveRename();
            if (e.key === "Escape") {
              setDraft(site.name);
              setEditing(false);
            }
          }}
          className="h-8"
        />
        <Button size="icon" variant="ghost" onClick={saveRename} title="Save name">
          <Check className="h-4 w-4" />
        </Button>
        <Button
          size="icon"
          variant="ghost"
          onClick={() => {
            setDraft(site.name);
            setEditing(false);
          }}
          title="Cancel"
        >
          <X className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-1 rounded-md border border-border bg-surface hover:bg-surface-2">
      <button
        type="button"
        disabled={busy}
        onClick={() => onConnect(site)}
        className="flex min-w-0 flex-1 items-center gap-3 px-3 py-2 text-left disabled:opacity-60"
        title="Reconnect to this site"
      >
        <span
          className={cn(
            "flex h-8 w-8 shrink-0 items-center justify-center rounded-md",
            remote ? "bg-remote-tint text-remote" : "bg-accent-tint text-primary",
          )}
        >
          {remote ? <Globe className="h-4 w-4" /> : <Server className="h-4 w-4" />}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium">{site.name}</span>
          <span className="block truncate font-mono text-xs text-fg-2">
            {siteSubtitle(site)}
            {swid ? ` · ${swid}` : ""}
          </span>
        </span>
        {last && <span className="shrink-0 text-xs text-fg-3">{last}</span>}
      </button>
      <div className="flex shrink-0 items-center gap-0.5 pr-1.5">
        {confirmDelete ? (
          <>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => onDelete(site.id)}
              title="Confirm delete"
            >
              Delete?
            </Button>
            <Button
              size="icon"
              variant="ghost"
              onClick={() => setConfirmDelete(false)}
              title="Keep"
            >
              <X className="h-4 w-4" />
            </Button>
          </>
        ) : (
          <>
            <Button
              size="icon"
              variant="ghost"
              onClick={() => setEditing(true)}
              title="Rename site"
            >
              <Pencil className="h-4 w-4" />
            </Button>
            <Button
              size="icon"
              variant="ghost"
              onClick={() => setConfirmDelete(true)}
              title="Delete site"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

// Connect (DESIGN_PLAN 5.1): open on the tech's saved sites as one-click
// reconnect cards, then a form to reach a new CIX direct or over the overlay
// (SNMP address / community / port, an optional site label). A successful
// connect persists the system server-side, so the card list fills itself; this
// drawer also covers explicit add / rename / delete. "Open last snapshot" cold-
// starts from the last saved snapshot so a tech can browse with the device off.
export function ConnectDrawer() {
  const {
    open,
    setOpen,
    form,
    setForm,
    connect,
    openColdSnapshot,
    progress,
    sites,
    loadSites,
    connectToSite,
    addSite,
    renameSite,
    deleteSite,
  } = useStore(
    useShallow((s) => ({
      open: s.connectDrawerOpen,
      setOpen: s.setConnectDrawerOpen,
      form: s.form,
      setForm: s.setForm,
      connect: s.connect,
      openColdSnapshot: s.openColdSnapshot,
      progress: s.progress,
      sites: s.sites,
      loadSites: s.loadSites,
      connectToSite: s.connectToSite,
      addSite: s.addSite,
      renameSite: s.renameSite,
      deleteSite: s.deleteSite,
    })),
  );

  const busy = progress.status === "connecting";

  // Refresh the saved-site list each time the drawer opens.
  React.useEffect(() => {
    if (open) void loadSites();
  }, [open, loadSites]);

  const canSave = !!form.ip.trim();

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Connect to a CIX</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          {sites.length > 0 && (
            <div>
              <Label className="mb-1.5 block text-xs text-fg-2">
                Saved sites ({sites.length})
              </Label>
              <div className="max-h-56 space-y-1.5 overflow-y-auto">
                {sites.map((site) => (
                  <SiteCard
                    key={site.id}
                    site={site}
                    busy={busy}
                    onConnect={connectToSite}
                    onRename={renameSite}
                    onDelete={deleteSite}
                  />
                ))}
              </div>
            </div>
          )}

          <div className="border-t border-border pt-3">
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
            <Button onClick={() => connect()} disabled={busy || !canSave}>
              {busy && <Loader2 className="h-4 w-4 animate-spin" />}
              Connect &amp; snapshot
            </Button>
            <Button
              variant="outline"
              onClick={() =>
                addSite({
                  name: form.site || form.ip.trim(),
                  pbx: {
                    host: form.ip.trim(),
                    port: form.port || 161,
                    community: form.community.trim() || "communityName",
                    via: form.reach === "remote" ? "overlay" : "direct",
                  },
                })
              }
              disabled={!canSave}
              title="Save these details as a site without connecting"
            >
              <Plus className="h-4 w-4" />
              Save site
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
