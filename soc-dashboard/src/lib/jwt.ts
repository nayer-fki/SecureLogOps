export type JwtPayload = {
  sub?: string;
  role?: "admin" | "analyst" | "viewer";
  iat?: number;
  exp?: number;
};

export function decodeJwt(token: string): JwtPayload | null {
  try {
    const payload = token.split(".")[1];
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(json);
  } catch {
    return null;
  }
}
