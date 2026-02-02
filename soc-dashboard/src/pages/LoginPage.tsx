// src/pages/LoginPage.tsx
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { decodeJwt, normalizeToken, setToken, isTokenExpired } from "../lib/auth";

export default function LoginPage() {
  const nav = useNavigate();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string>("");

  const cleaned = useMemo(() => normalizeToken(value), [value]);
  const decoded = useMemo(() => (cleaned ? decodeJwt(cleaned) : null), [cleaned]);
  const role = decoded?.role;
  const sub = decoded?.sub;

  const onSave = () => {
    const t = normalizeToken(value);
    if (!t) return setError("Token required");

    const d = decodeJwt(t);
    if (!d?.role || !d?.sub) return setError("Invalid token (missing role/sub)");

    if (isTokenExpired(t)) return setError("Token expired. Generate a new one.");

    setToken(t);

    // route حسب الدور (بدّلها حسب routes متاعك)
    if (d.role === "admin") return nav("/soc");
    if (d.role === "analyst") return nav("/soc");
    return nav("/soc"); // viewer
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center px-4">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(0,255,170,0.08),transparent_35%),radial-gradient(circle_at_80%_70%,rgba(80,120,255,0.10),transparent_40%)]" />

      <div className="relative w-full max-w-xl">
        <div className="rounded-2xl border border-zinc-800/70 bg-zinc-900/40 backdrop-blur-xl shadow-2xl p-8">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">SOC Dashboard</h1>
              <p className="text-sm text-zinc-400 mt-1">
                Paste your JWT (viewer / analyst / admin). We’ll use it for authorization.
              </p>
            </div>

            {role ? (
              <span className="text-xs px-3 py-1 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-200">
                role: <b>{role}</b>
                {sub ? <span className="text-zinc-400"> · {sub}</span> : null}
              </span>
            ) : (
              <span className="text-xs px-3 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-500">
                no role yet
              </span>
            )}
          </div>

          <div className="mt-6">
            <label className="text-xs text-zinc-400">Bearer token (JWT)</label>
            <textarea
              value={value}
              onChange={(e) => {
                setValue(e.target.value);
                setError("");
              }}
              placeholder='eyJhbGciOi... (or "Bearer eyJ...")'
              className="mt-2 w-full h-32 rounded-xl bg-zinc-950/60 border border-zinc-800 px-4 py-3 text-sm outline-none focus:border-emerald-500/60 focus:ring-2 focus:ring-emerald-500/10"
            />
            {error ? <p className="mt-2 text-sm text-red-400">{error}</p> : null}
          </div>

          <button
            onClick={onSave}
            disabled={!cleaned}
            className="mt-5 w-full rounded-xl bg-emerald-500 text-zinc-950 font-medium py-3 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-emerald-400 transition"
          >
            Save token & continue
          </button>

          <p className="mt-4 text-xs text-zinc-500">
            Tip: generate tokens from your terminal using your python jwt script.
          </p>
        </div>
      </div>
    </div>
  );
}
