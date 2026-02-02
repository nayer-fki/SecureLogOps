import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../api/http";
import { clearToken } from "../auth/token";
import { useNavigate } from "react-router-dom";

type Incident = {
  id: string;
  status: "open" | "ack" | "closed";
  severity: "critical" | "high" | "medium" | "low";
  type: string;
  title: string;
  description?: string | null;
  source?: { ip?: string | null; host?: string | null; user?: string | null };
  created_at: string;
  updated_at: string;
  acked_by?: string | null;
  closed_by?: string | null;
};

export default function Incidents() {
  const [items, setItems] = useState<Incident[]>([]);
  const [status, setStatus] = useState<string>("open");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const nav = useNavigate();

  async function load() {
    setErr(null);
    setLoading(true);
    try {
      const data = await apiFetch(`/incidents?status=${encodeURIComponent(status)}`);
      setItems(data);
    } catch (e: any) {
      setErr(e.message || "Failed");
      if ((e.message || "").includes("Missing Bearer token")) {
        clearToken();
        nav("/login");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  const counts = useMemo(() => {
    const m = { open: 0, ack: 0, closed: 0 };
    for (const x of items) m[x.status]++;
    return m;
  }, [items]);

  return (
    <div style={{ maxWidth: 1100, margin: "24px auto", padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
        <h2 style={{ margin: 0 }}>Incidents</h2>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={() => nav("/login")}>Change token</button>
          <button onClick={load}>Refresh</button>
        </div>
      </div>

      <div style={{ marginTop: 12, display: "flex", gap: 10, alignItems: "center" }}>
        <label>Status:</label>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="open">open</option>
          <option value="ack">ack</option>
          <option value="closed">closed</option>
        </select>

        <div style={{ marginLeft: "auto", opacity: 0.8, fontSize: 12 }}>
          loaded: {items.length} | open: {counts.open} | ack: {counts.ack} | closed: {counts.closed}
        </div>
      </div>

      {err && (
        <div style={{ marginTop: 12, color: "crimson" }}>
          Error: {err}
        </div>
      )}

      <div style={{ marginTop: 14, border: "1px solid #ddd", borderRadius: 8, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#f7f7f7", textAlign: "left" }}>
              <th style={{ padding: 10 }}>Severity</th>
              <th style={{ padding: 10 }}>Status</th>
              <th style={{ padding: 10 }}>Title</th>
              <th style={{ padding: 10 }}>Type</th>
              <th style={{ padding: 10 }}>Source IP</th>
              <th style={{ padding: 10 }}>Updated</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td style={{ padding: 12 }} colSpan={6}>Loading...</td></tr>
            ) : items.length === 0 ? (
              <tr><td style={{ padding: 12 }} colSpan={6}>No incidents</td></tr>
            ) : (
              items.map((it) => (
                <tr key={it.id} style={{ borderTop: "1px solid #eee" }}>
                  <td style={{ padding: 10 }}>{it.severity}</td>
                  <td style={{ padding: 10 }}>{it.status}</td>
                  <td style={{ padding: 10 }}>{it.title}</td>
                  <td style={{ padding: 10 }}>{it.type}</td>
                  <td style={{ padding: 10 }}>{it.source?.ip ?? "-"}</td>
                  <td style={{ padding: 10 }}>{new Date(it.updated_at).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
