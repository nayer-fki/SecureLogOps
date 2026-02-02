const KEY = "soc_token";

export function normalizeToken(input: string): string {
  if (!input) return "";

  // remove quotes/newlines/spaces
  let t = input.trim().replace(/^"+|"+$/g, "").replace(/^'+|'+$/g, "");

  // allow pasting "Bearer xxx"
  if (/^bearer\s+/i.test(t)) t = t.replace(/^bearer\s+/i, "");

  return t.trim();
}

export function setToken(token: string) {
  const t = normalizeToken(token);
  localStorage.setItem(KEY, t);
}

export function getToken(): string {
  return localStorage.getItem(KEY) || "";
}

export function clearToken() {
  localStorage.removeItem(KEY);
}
