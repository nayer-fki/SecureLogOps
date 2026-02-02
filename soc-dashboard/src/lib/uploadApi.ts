// src/lib/uploadApi.ts
const INGEST_API = import.meta.env.VITE_INGEST_API || "http://localhost:8000";
const INGEST_API_KEY = import.meta.env.VITE_INGEST_API_KEY || "ChangeMe_IngestKey_123";

export async function uploadLogs(opts: {
  file: File;
  dataset?: string;
  source?: string;
}) {
  const fd = new FormData();
  fd.append("file", opts.file);
  if (opts.dataset) fd.append("dataset", opts.dataset);
  if (opts.source) fd.append("source", opts.source);

  const res = await fetch(`${INGEST_API}/uploads`, {
    method: "POST",
    headers: {
      "x-api-key": INGEST_API_KEY,
      // ❌ لا تحط Content-Type مع FormData
    },
    body: fd,
  });

  const text = await res.text().catch(() => "");
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}: ${text || "Upload failed"}`);
  }

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
