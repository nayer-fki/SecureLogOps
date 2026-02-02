// src/pages/Login.tsx
import { useState } from "react";
import { setToken, normalizeToken } from "../auth/token";
import { useNavigate } from "react-router-dom";

export default function Login() {
  const [token, setTok] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const nav = useNavigate();

  function onSave() {
    setErr(null);
    const cleaned = normalizeToken(token);
    if (!cleaned) {
      setErr("Token required");
      return;
    }
    setToken(cleaned);
    nav("/soc"); // ✅ بدل /
  }

  return (
    <div style={{ maxWidth: 520, margin: "60px auto", padding: 16 }}>
      <h1 style={{ fontSize: 28, marginBottom: 8 }}>SOC Dashboard</h1>
      <p style={{ opacity: 0.8, marginBottom: 16 }}>
        Paste your JWT (viewer/analyst/admin). We’ll use it for Authorization.
      </p>

      <textarea
        value={token}
        onChange={(e) => setTok(e.target.value)}
        rows={6}
        style={{ width: "100%", padding: 12, fontFamily: "monospace" }}
        placeholder='Paste token here (you can paste with or without "Bearer ")'
      />

      {err && <div style={{ color: "crimson", marginTop: 10 }}>{err}</div>}

      <button
        onClick={onSave}
        style={{
          marginTop: 12,
          width: "100%",
          padding: "10px 14px",
          cursor: "pointer",
        }}
      >
        Save token & continue
      </button>
    </div>
  );
}
