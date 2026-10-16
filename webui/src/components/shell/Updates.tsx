// Self-updater UI (DESIGN_PLAN self-update leg; backend: toshiba_cix/update.py).
//
// The React rebuild dropped every /api/update trigger the vanilla UI had; this
// restores them:
//   • UpdateButton — a visible TopBar control that opens the dialog and shows a
//     dot when a newer release exists.
//   • UpdatesDialog — current-vs-latest, release notes, and a confirm-gated
//     Install that calls POST /api/update {confirm:true} with progress + a
//     "restart to finish" prompt. Handles already-current and check failures.
//   • UpdateToast — a one-time, dismissible "update available" notice from the
//     non-blocking on-launch check (wired in App.tsx).
//
// All state lives in the store's update slice; the on-launch check degrades
// silently when offline (api.checkUpdate swallows network errors to {ok:false}
// / null), so startup is never blocked.
import {
  ArrowUpCircle,
  CheckCircle2,
  Download,
  ExternalLink,
  Loader2,
  RefreshCw,
  X,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useStore } from "@/store/useStore";
import { useShallow } from "zustand/react/shallow";

// The TopBar entry point: an icon button with a dot when an update is waiting.
export function UpdateButton() {
  const { info, setDialogOpen, checkUpdate } = useStore(
    useShallow((s) => ({
      info: s.updateInfo,
      setDialogOpen: s.setUpdateDialogOpen,
      checkUpdate: s.checkUpdate,
    })),
  );
  const newer = !!(info?.ok && info?.newer);
  return (
    <button
      onClick={() => {
        setDialogOpen(true);
        // Re-check on open unless we already have a current reading.
        if (!info) void checkUpdate();
      }}
      className="relative flex h-8 w-8 items-center justify-center rounded-md border border-border bg-surface-2 text-fg-2 hover:border-line-strong"
      title={
        newer
          ? `Update available — v${info?.latest}`
          : "Check for updates"
      }
      aria-label="Check for updates"
    >
      <Download className="h-4 w-4" />
      {newer && (
        <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-primary ring-2 ring-surface" />
      )}
    </button>
  );
}

function ReleaseNotesLink({ href }: { href?: string | null }) {
  if (!href) return null;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 text-primary hover:underline"
    >
      Release notes <ExternalLink className="h-3.5 w-3.5" />
    </a>
  );
}

// The dialog body, driven entirely by the store's update slice.
function UpdatesBody() {
  const {
    info,
    checking,
    applying,
    result,
    checkUpdate,
    applyUpdate,
  } = useStore(
    useShallow((s) => ({
      info: s.updateInfo,
      checking: s.updateChecking,
      applying: s.updateApplying,
      result: s.updateResult,
      checkUpdate: s.checkUpdate,
      applyUpdate: s.applyUpdate,
    })),
  );

  // Nothing fetched yet.
  if (!info) {
    return checking ? (
      <div className="flex items-center gap-2 text-sm text-fg-2">
        <Loader2 className="h-4 w-4 animate-spin" /> Checking for updates…
      </div>
    ) : (
      <div className="space-y-3">
        <p className="text-sm text-fg-2">Couldn't reach the update service.</p>
        <Button variant="outline" size="sm" onClick={() => void checkUpdate()}>
          <RefreshCw className="h-4 w-4" /> Try again
        </Button>
      </div>
    );
  }

  // The check itself failed (offline, GitHub rate-limited, …).
  if (!info.ok) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-fg-2">
          Couldn't check for updates
          {info.error ? <span className="text-fg-3"> — {info.error}</span> : null}
        </p>
        <Button variant="outline" size="sm" onClick={() => void checkUpdate()}>
          <RefreshCw className="h-4 w-4" /> Try again
        </Button>
      </div>
    );
  }

  // Up to date.
  if (!info.newer) {
    return (
      <div className="flex items-start gap-2 rounded-md bg-ok-tint p-3 text-sm">
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" />
        <span className="text-fg">
          You're on the latest — <strong>v{info.current}</strong>.
        </span>
      </div>
    );
  }

  // A newer version exists.
  const installer = info.install_method === "installer";
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 rounded-md bg-surface-2 p-3 text-sm">
        <ArrowUpCircle className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
        <div className="space-y-0.5">
          <div className="text-fg">
            Version <strong>{info.latest}</strong> is available.
          </div>
          <div className="text-fg-3 tnum">You have v{info.current}.</div>
          <div className="pt-1">
            <ReleaseNotesLink href={info.html_url} />
          </div>
        </div>
      </div>

      {result ? (
        <div
          className={
            "rounded-md p-3 text-sm " +
            (result.ok ? "bg-ok-tint text-fg" : "bg-bad-tint text-fg")
          }
        >
          <div>{result.message || result.error || "Update finished."}</div>
          {result.ok && result.needs_restart && (
            <div className="pt-1 font-medium">
              Restart Switchroom to finish.
            </div>
          )}
        </div>
      ) : info.can_apply ? (
        <div className="space-y-2">
          <Button
            onClick={() => void applyUpdate()}
            disabled={applying}
            className="w-full"
          >
            {applying ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Downloading v
                {info.latest}…
              </>
            ) : (
              <>
                <Download className="h-4 w-4" /> Install update
              </>
            )}
          </Button>
          <p className="text-2xs text-fg-3">
            {installer
              ? "Downloads the installer and opens it — you'll confirm in your system installer, then reopen Switchroom."
              : "Replaces this app in place and prompts you to restart."}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-sm text-fg-2">
            {info.plan_reason ||
              "This build updates outside the app — get the new release from GitHub."}
          </p>
          {info.html_url && (
            <Button variant="outline" size="sm" asChild className="w-full">
              <a href={info.html_url} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-4 w-4" /> Download from GitHub
              </a>
            </Button>
          )}
        </div>
      )}

      <div className="flex justify-end">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void checkUpdate()}
          disabled={checking || applying}
        >
          <RefreshCw className={"h-4 w-4 " + (checking ? "animate-spin" : "")} />
          Check again
        </Button>
      </div>
    </div>
  );
}

// Controlled dialog — opened from the TopBar button or the launch toast.
export function UpdatesDialog() {
  const { open, setOpen } = useStore(
    useShallow((s) => ({
      open: s.updateDialogOpen,
      setOpen: s.setUpdateDialogOpen,
    })),
  );
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Software update</DialogTitle>
          <DialogDescription>
            Switchroom checks GitHub Releases. Updates are optional and only
            install when you choose.
          </DialogDescription>
        </DialogHeader>
        <UpdatesBody />
      </DialogContent>
    </Dialog>
  );
}

// A one-time, non-blocking toast from the on-launch check. Dismissible, and it
// never reappears once dismissed for the session.
export function UpdateToast() {
  const { info, dismissed, dialogOpen, setDialogOpen, dismiss } = useStore(
    useShallow((s) => ({
      info: s.updateInfo,
      dismissed: s.updateToastDismissed,
      dialogOpen: s.updateDialogOpen,
      setDialogOpen: s.setUpdateDialogOpen,
      dismiss: s.dismissUpdateToast,
    })),
  );
  if (!info?.ok || !info.newer || dismissed || dialogOpen) return null;
  return (
    <div className="fixed bottom-4 right-4 z-40 w-80 max-w-[calc(100vw-2rem)] rounded-lg border border-border bg-surface p-3 shadow-lg">
      <div className="flex items-start gap-2">
        <ArrowUpCircle className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-fg">Update available</div>
          <div className="text-2xs text-fg-3 tnum">
            v{info.latest} — you have v{info.current}.
          </div>
          <div className="mt-2 flex gap-2">
            <Button
              size="sm"
              onClick={() => {
                dismiss();
                setDialogOpen(true);
              }}
            >
              View
            </Button>
            <Button variant="ghost" size="sm" onClick={() => dismiss()}>
              Later
            </Button>
          </div>
        </div>
        <button
          onClick={() => dismiss()}
          className="rounded-sm text-fg-3 hover:text-fg"
          aria-label="Dismiss"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
