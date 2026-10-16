import * as React from "react";
import { AlertTriangle, CheckCircle2, Loader2, Lock, PlayCircle } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import { useStore } from "@/store/useStore";
import type { OpLog, ReviewResult, ReviewRow } from "@/lib/types";

// The one modal (DESIGN_PLAN 5.5). It is the ONLY place `applyChangeset` is
// called (a backend test greps the UI to enforce this). Simulate produces the
// plan + three-way review + op-log with no socket opened; a live write is gated
// on armed mode + confirm + the typed site name, and never happens by default.

function Cell({ value, muted }: { value: string | null; muted?: boolean }) {
  return (
    <span className={cn("block truncate", muted && "text-fg-3")}>
      {value == null || value === "" ? "—" : value}
    </span>
  );
}

function ReviewRowView({ row }: { row: ReviewRow }) {
  return (
    <tr
      className={cn(
        "border-t border-border/60",
        row.excluded && "opacity-55",
      )}
    >
      <td className="px-2 py-1">
        <div className="flex items-center gap-1">
          {row.display_no && <span className="field-badge">{row.display_no}</span>}
          <span className="truncate" title={row.field}>
            {row.label}
          </span>
        </div>
      </td>
      <td className="px-2 py-1 text-fg-3">
        <Cell value={row.base} muted />
      </td>
      <td className="px-2 py-1">
        <span className={cn(row.conflict && "text-warn font-medium")}>
          <Cell value={row.live} />
        </span>
      </td>
      <td className="px-2 py-1 font-medium">
        <Cell value={row.excluded ? row.live : row.proposed} />
      </td>
      <td className="px-2 py-1 text-2xs">
        <span className="font-mono">{row.native_wire}</span>{" "}
        {row.wire_proven ? (
          <span className="text-ok" title="wire type proven on the wire">
            ✓
          </span>
        ) : (
          <span className="text-warn" title="catalog-derived — not seen on the wire">
            ⚠
          </span>
        )}
      </td>
      <td className="px-2 py-1 text-2xs text-fg-3">
        {row.excluded
          ? row.exclude_reason || "excluded"
          : row.blast.note || (row.blast.affects ? `${row.blast.affects}` : "")}
      </td>
    </tr>
  );
}

export function ReviewWriteDialog() {
  const reviewOpen = useStore((s) => s.reviewOpen);
  const sessionId = useStore((s) => s.sessionId);
  const modeName = useStore((s) => s.mode.mode);
  const closeReview = useStore((s) => s.closeReview);
  const setMode = useStore((s) => s.setMode);
  const refreshPending = useStore((s) => s.refreshPending);

  const [review, setReview] = React.useState<ReviewResult | null>(null);
  const [oplog, setOplog] = React.useState<OpLog | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [typed, setTyped] = React.useState("");
  const [result, setResult] = React.useState<{ ok: boolean; message: string } | null>(null);

  React.useEffect(() => {
    if (!reviewOpen || !sessionId) return;
    let cancelled = false;
    setLoading(true);
    setResult(null);
    setOplog(null);
    api
      .reviewChangeset(sessionId, { simulate: true })
      .then((res) => {
        if (!cancelled && res.ok) setReview(res.review);
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [reviewOpen, sessionId]);

  const errorCount = review?.validation?.error_count ?? 0;
  const needsName = review?.needs_typed_name ?? false;
  const armed = modeName === "armed";

  async function doSimulate() {
    if (!sessionId) return;
    setBusy(true);
    try {
      const res = await api.applyChangeset(sessionId, { mode: "simulate" });
      if (res.ok) {
        if (res.review) setReview(res.review);
        if (res.oplog) setOplog(res.oplog);
        setResult({ ok: true, message: `Simulated — ${res.oplog?.would_send ?? 0} SET(s) prepared, nothing sent.` });
      } else {
        setResult({ ok: false, message: res.error ?? "Simulate failed." });
      }
    } catch (e) {
      setResult({ ok: false, message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  async function doWrite() {
    if (!sessionId) return;
    setBusy(true);
    try {
      const res = await api.applyChangeset(sessionId, {
        mode: "live",
        confirm: true,
        site_name_typed: typed,
      });
      if (res.ok) {
        setResult({ ok: true, message: "Write sent and verified." });
        await refreshPending();
      } else {
        setResult({ ok: false, message: res.error ?? "Write refused." });
        if (res.review) setReview(res.review);
      }
    } catch (e) {
      setResult({ ok: false, message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  // The write button is enabled only when armed, error-free, and (if the tier
  // needs it) the typed name is non-empty.
  const canWrite =
    !busy && errorCount === 0 && armed && (!needsName || typed.trim().length > 0);

  return (
    <Dialog
      open={reviewOpen}
      onOpenChange={(o) => {
        if (!o) closeReview();
      }}
    >
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            Review &amp; write
            {review && (
              <Badge variant={review.tier >= 3 ? "bad" : review.tier === 2 ? "warn" : "secondary"}>
                Tier {review.tier}
              </Badge>
            )}
            <Badge variant={armed ? "warn" : "secondary"} className="gap-1">
              <Lock className="h-3 w-3" />
              {modeName.toUpperCase()}
            </Badge>
          </DialogTitle>
          <DialogDescription>
            {review?.summary.affects_line ??
              "Every change is shown base → live → proposed before anything is sent."}
            {review?.tier_reasons?.length
              ? ` (${review.tier_reasons.join(", ")})`
              : ""}
          </DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="flex items-center justify-center gap-2 py-8 text-sm text-fg-2">
            <Loader2 className="h-4 w-4 animate-spin" /> Building the review…
          </div>
        ) : !review || review.rows.length === 0 ? (
          <div className="py-8 text-center text-sm text-fg-2">Nothing staged.</div>
        ) : (
          <div className="max-h-[46vh] overflow-auto rounded-md border border-border">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-surface-2 text-left text-2xs uppercase text-fg-3">
                <tr>
                  <th className="px-2 py-1 font-medium">Field</th>
                  <th className="px-2 py-1 font-medium">Base</th>
                  <th className="px-2 py-1 font-medium">Live now</th>
                  <th className="px-2 py-1 font-medium">Proposed</th>
                  <th className="px-2 py-1 font-medium">Wire</th>
                  <th className="px-2 py-1 font-medium">Note</th>
                </tr>
              </thead>
              <tbody>
                {review.rows.map((r, i) => (
                  <ReviewRowView key={`${r.field}:${i}`} row={r} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {review && errorCount > 0 && (
          <div className="flex items-start gap-1.5 rounded-md border-l-2 border-bad bg-bad-tint px-2 py-1.5 text-xs text-bad">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div>
              {review.validation.errors.map((f, i) => (
                <div key={i}>
                  <span className="font-medium">{f.field}</span>: {f.message}
                </div>
              ))}
            </div>
          </div>
        )}

        {oplog && (
          <div className="rounded-md border border-border bg-surface-2 p-2 text-2xs">
            <div className="mb-1 font-medium text-fg-2">
              Simulate — {oplog.would_send} SET(s), no socket opened. Batch SET PDU:
            </div>
            <code className="block break-all font-mono text-fg-3">
              {oplog.batch_set_pdu_hex}
            </code>
            {oplog.commit_value_tlv_hex && (
              <div className="mt-1 text-fg-3">
                + apply/commit SET value TLV{" "}
                <code className="font-mono">{oplog.commit_value_tlv_hex}</code>{" "}
                (persistence across reboot unproven)
              </div>
            )}
          </div>
        )}

        {result && (
          <div
            className={cn(
              "flex items-center gap-1.5 rounded-md px-2 py-1.5 text-xs",
              result.ok ? "bg-ok-tint text-ok" : "bg-bad-tint text-bad",
            )}
          >
            {result.ok ? (
              <CheckCircle2 className="h-3.5 w-3.5" />
            ) : (
              <AlertTriangle className="h-3.5 w-3.5" />
            )}
            {result.message}
          </div>
        )}

        <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
          {needsName && (
            <Input
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder="Type the site name to confirm"
              className="h-ctl max-w-[220px]"
            />
          )}
          {!armed && (
            <Button variant="outline" size="sm" onClick={() => setMode("armed")}>
              <Lock className="h-3.5 w-3.5" /> Arm programming mode
            </Button>
          )}
          <Button variant="secondary" size="sm" onClick={doSimulate} disabled={busy}>
            <PlayCircle className="h-3.5 w-3.5" /> Simulate
          </Button>
          <Button size="sm" onClick={doWrite} disabled={!canWrite} title={
            !armed
              ? "Arm programming mode first"
              : errorCount > 0
                ? "Fix validation errors first"
                : needsName && typed.trim().length === 0
                  ? "Type the site name to confirm"
                  : "Write and verify"
          }>
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            Write &amp; verify {review ? review.summary.will_send : ""}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
