import * as React from "react";
import { useStore } from "@/store/useStore";
import type { Identity, JobState } from "./types";

// The one push channel (DESIGN_PLAN 10.3): GET /api/events, a text/event-stream
// of named events. EventSource is same-origin and sends the auth cookie
// automatically. Snapshot-on-connect progress arrives as job.progress/done; the
// nav greys as programs land via session.programs.
export function useEventStream() {
  const onJob = useStore((s) => s.onJob);
  const onSessionPrograms = useStore((s) => s.onSessionPrograms);
  const onIdentity = useStore((s) => s.onIdentity);

  React.useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource("/api/events", { withCredentials: true });
    } catch {
      return;
    }
    const jobHandler = (e: MessageEvent) => {
      try {
        onJob(JSON.parse(e.data) as JobState);
      } catch {
        /* heartbeat / malformed */
      }
    };
    es.addEventListener("job.progress", jobHandler);
    es.addEventListener("job.done", jobHandler);
    es.addEventListener("job.error", jobHandler);
    es.addEventListener("session.programs", () => onSessionPrograms());
    es.addEventListener("session.identity", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as { identity?: Identity };
        if (data.identity) onIdentity(data.identity);
      } catch {
        /* ignore */
      }
    });
    return () => es?.close();
  }, [onJob, onSessionPrograms, onIdentity]);
}
