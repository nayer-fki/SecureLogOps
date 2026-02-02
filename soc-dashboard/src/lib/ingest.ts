// src/lib/ingest.ts
const INGEST_BASE = import.meta.env.VITE_INGEST_URL || "http://localhost:8000";

export type UploadResponse = {
  status: string;
  upload_id: string;
  stored_name: string;
  queue: string;
  size_bytes: number;
  dataset?: string;
  source?: string;
};

export async function uploadLogsFile(opts: {
  file: File;
  apiKey: string;
  dataset: string;
  source: string;
}): Promise<UploadResponse> {
  const fd = new FormData();
  fd.append("file", opts.file);
  fd.append("dataset", opts.dataset);
  fd.append("source", opts.source);

  const res = await fetch(`${INGEST_BASE}/uploads`, {
    method: "POST",
    headers: { "x-api-key": opts.apiKey },
    body: fd,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.detail || `Upload failed (${res.status})`);

  return data as UploadResponse;
}
