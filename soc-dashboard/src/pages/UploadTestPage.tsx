// src/pages/UploadTestPage.tsx
import { useState } from "react";
import { uploadLogs } from "../lib/uploadApi";

export default function UploadTestPage() {
  const [file, setFile] = useState<File | null>(null);
  const [dataset, setDataset] = useState("auth");
  const [source, setSource] = useState("frontend-test");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string>("");
  const [error, setError] = useState<string>("");

  const onUpload = async () => {
    setError("");
    setResult("");

    if (!file) {
      setError("Choose a file first (.json/.jsonl/.ndjson/.csv).");
      return;
    }

    setLoading(true);
    try {
      const r = await uploadLogs({ file, dataset, source });
      setResult(JSON.stringify(r, null, 2));
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", padding: 24, fontFamily: "system-ui", background: "#0b0b0f", color: "#eaeaf0" }}>
      <div style={{ maxWidth: 820, margin: "0 auto", border: "1px solid #2a2a33", borderRadius: 16, padding: 20, background: "rgba(255,255,255,0.03)" }}>
        <h1 style={{ margin: 0, fontSize: 22 }}>Upload Test (No Login)</h1>
        <p style={{ marginTop: 8, color: "#a8a8b5" }}>
          This page uploads logs to <code>{import.meta.env.VITE_INGEST_API || "http://localhost:8000"}</code> using <code>x-api-key</code>.
        </p>

        <div style={{ marginTop: 18 }}>
          <label style={{ fontSize: 12, color: "#a8a8b5" }}>File (allowed: .csv .json .jsonl .ndjson)</label>
          <input
            type="file"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            style={{ display: "block", marginTop: 8 }}
          />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 18 }}>
          <div>
            <label style={{ fontSize: 12, color: "#a8a8b5" }}>dataset</label>
            <input
              value={dataset}
              onChange={(e) => setDataset(e.target.value)}
              style={{ width: "100%", marginTop: 8, padding: 10, borderRadius: 10, border: "1px solid #2a2a33", background: "#0f0f15", color: "#eaeaf0" }}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, color: "#a8a8b5" }}>source</label>
            <input
              value={source}
              onChange={(e) => setSource(e.target.value)}
              style={{ width: "100%", marginTop: 8, padding: 10, borderRadius: 10, border: "1px solid #2a2a33", background: "#0f0f15", color: "#eaeaf0" }}
            />
          </div>
        </div>

        <button
          onClick={onUpload}
          disabled={!file || loading}
          style={{
            width: "100%",
            marginTop: 16,
            padding: 12,
            borderRadius: 12,
            border: "none",
            cursor: loading ? "not-allowed" : "pointer",
            opacity: !file || loading ? 0.6 : 1,
            background: "#34d399",
            color: "#08110c",
            fontWeight: 700,
          }}
        >
          {loading ? "Uploading..." : "Upload"}
        </button>

        {error ? (
          <pre style={{ marginTop: 14, padding: 12, borderRadius: 12, border: "1px solid #51202a", background: "rgba(255,0,60,0.08)", color: "#ffb4c1", whiteSpace: "pre-wrap" }}>
            {error}
          </pre>
        ) : null}

        {result ? (
          <pre style={{ marginTop: 14, padding: 12, borderRadius: 12, border: "1px solid #1f3a2c", background: "rgba(0,255,140,0.06)", color: "#b9ffd7", whiteSpace: "pre-wrap" }}>
            {result}
          </pre>
        ) : null}
      </div>
    </div>
  );
}
