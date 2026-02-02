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
    },
    body: fd,
  });

  const ct = res.headers.get("content-type") || "";
  const bodyText = await res.text().catch(() => "");

  if (!res.ok) {
    throw new Error(
      `${res.status} ${res.statusText}: ${bodyText || "Upload failed"}`
    );
  }

  // لو رجّع JSON
  if (ct.includes("application/json")) return JSON.parse(bodyText);
  return bodyText;
}
