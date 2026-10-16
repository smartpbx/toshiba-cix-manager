import type {
  BackupResult,
  CatalogInfo,
  ConnectResult,
  DiffResult,
  DiscoverResult,
  Health,
  ReadResult,
} from "./types";

// One fetch helper. The engine answers JSON for everything except "/" and the
// zip download; those callers use rawPost / the UI's download path directly.
async function jpost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return (await res.json()) as T;
}

async function jget<T>(path: string): Promise<T> {
  const res = await fetch(path);
  return (await res.json()) as T;
}

export const api = {
  health: () => jget<Health>("/api/health"),
  catalog: () => jget<CatalogInfo>("/api/catalog"),
  discover: () => jget<DiscoverResult>("/api/discover"),

  connect: (p: { ip: string; community: string; port: number }) =>
    jpost<ConnectResult>("/api/connect", p),

  read: (p: {
    ip: string;
    community: string;
    port: number;
    scope: string;
    timeout?: number;
    retries?: number;
  }) => jpost<ReadResult>("/api/read", p),

  catalogBackup: (p: { ip: string; community: string; port: number }) =>
    jpost<BackupResult>("/api/catalog-backup", p),

  diff: (p: { a: unknown; b: unknown; all?: boolean }) =>
    jpost<DiffResult>("/api/diff", p),

  // Download the engine-built .zip for a read doc (programming.json + report).
  async backupZip(doc: unknown): Promise<Blob> {
    const res = await fetch("/api/backup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ doc }),
    });
    return res.blob();
  },
};

export function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function downloadText(filename: string, text: string, mime = "application/json") {
  downloadBlob(filename, new Blob([text], { type: mime }));
}
