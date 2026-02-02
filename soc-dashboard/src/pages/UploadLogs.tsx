import { useState } from "react";
import { uploadLogs } from "../lib/api";

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [dataset, setDataset] = useState("app");
  const [source, setSource] = useState("manual-upload");
  const [loading, setLoading] = useState(false);
  const [ok, setOk] = useState<string>("");
  const [err, setErr] = useState<string>("");

  const onUpload = async () => {
    setErr("");
    setOk("");

    if (!file) {
      setErr("Please choose a file first.");
      return;
    }

    setLoading(true);
    try {
      const r = await uploadLogs({ file, dataset, source });
      setOk(`Uploaded ✅ ${JSON.stringify(r)}`);
    } catch (e: any) {
      setErr(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center px-4">
      <div className="w-full max-w-xl rounded-2xl border border-zinc-800 bg-zinc-900/40 backdrop-blur-xl p-8">
        <h1 className="text-2xl font-semibold">Upload Logs</h1>
        <p className="text-sm text-zinc-400 mt-1">
          Upload a log file to ingestion-service (no JWT needed).
        </p>

        <div className="mt-6 space-y-4">
          <div>
            <label className="text-xs text-zinc-400">File</label>
            <input
              type="file"
              className="mt-2 block w-full text-sm"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-zinc-400">dataset</label>
              <input
                value={dataset}
                onChange={(e) => setDataset(e.target.value)}
                className="mt-2 w-full rounded-xl bg-zinc-950/60 border border-zinc-800 px-3 py-2 text-sm outline-none focus:border-emerald-500/60"
              />
            </div>

            <div>
              <label className="text-xs text-zinc-400">source</label>
              <input
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="mt-2 w-full rounded-xl bg-zinc-950/60 border border-zinc-800 px-3 py-2 text-sm outline-none focus:border-emerald-500/60"
              />
            </div>
          </div>

          <button
            onClick={onUpload}
            disabled={loading || !file}
            className="w-full rounded-xl bg-emerald-500 text-zinc-950 font-medium py-3 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-emerald-400 transition"
          >
            {loading ? "Uploading..." : "Upload"}
          </button>

          {ok ? (
            <pre className="text-xs whitespace-pre-wrap rounded-xl bg-zinc-950/60 border border-zinc-800 p-3 text-emerald-300">
              {ok}
            </pre>
          ) : null}

          {err ? (
            <pre className="text-xs whitespace-pre-wrap rounded-xl bg-zinc-950/60 border border-zinc-800 p-3 text-red-300">
              {err}
            </pre>
          ) : null}
        </div>
      </div>
    </div>
  );
}
