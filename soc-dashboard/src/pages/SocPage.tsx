import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getToken, clearToken } from "../lib/auth";
import { fetchOverview, fetchIncidents } from "../lib/api";

export default function SocPage() {
  const nav = useNavigate();
  const [err, setErr] = useState("");

  useEffect(() => {
    const t = getToken();
    if (!t) {
      nav("/", { replace: true });
      return;
    }

    (async () => {
      try {
        await fetchOverview();
        await fetchIncidents({ status: "open" });
      } catch (e: any) {
        const msg = String(e?.message || e);
        setErr(msg);

        if (msg.includes("401")) {
          clearToken();
          nav("/", { replace: true });
        }
      }
    })();
  }, [nav]);

  return (
    <div>
      {err ? <p style={{ color: "red" }}>{err}</p> : null}
      {/* باقي الداشبورد */}
    </div>
  );
}
