// src/lib/auth.ts
export type Role = "admin" | "analyst" | "viewer";

export type JwtPayload = {
  sub?: string;
  role?: Role;
  iat?: number;
  exp?: number;
};

const TOKEN_KEY = "soc_token";

/** Remove Bearer + quotes + trims */
export function normalizeToken(input?: string | null): string {
  if (!input) return "";
  let t = String(input).trim();

  // remove surrounding quotes if pasted "xxx"
  t = t.replace(/^"+|"+$/g, "").trim();

  // remove Bearer prefix if provided
  if (/^bearer\s+/i.test(t)) t = t.replace(/^bearer\s+/i, "").trim();

  return t;
}

/** Decode JWT payload (no signature verify; front only) */
export function decodeJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;

    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);

    const json = atob(padded);
    return JSON.parse(json) as JwtPayload;
  } catch {
    return null;
  }
}

export function setToken(raw: string) {
  const t = normalizeToken(raw);
  if (!t) return;
  localStorage.setItem(TOKEN_KEY, t);
}

export function getToken(): string {
  return normalizeToken(localStorage.getItem(TOKEN_KEY));
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export function getRoleFromStorage(): Role | undefined {
  const t = getToken();
  const p = t ? decodeJwt(t) : null;
  return p?.role;
}

export function isTokenExpired(token: string): boolean {
  const p = decodeJwt(token);
  if (!p?.exp) return false;
  const now = Math.floor(Date.now() / 1000);
  return now >= p.exp;
}
