// src/lib/types.ts

export type IncidentStatus = "open" | "ack" | "closed";

export type Incident = {
  id: string;
  status: IncidentStatus;
  severity: string; // low/medium/high/critical
  type: string;
  title: string;
  description?: string | null;
  source?: { ip?: string | null; host?: string | null; user?: string | null } | null;
  tags?: string[];
  updated_at: string;
  created_at: string;
  acked_at?: string | null;
  acked_by?: string | null;
  closed_at?: string | null;
  closed_by?: string | null;
};

export type OverviewStats = {
  status?: {
    open?: number;
    ack?: number;
    closed?: number;
  };
  severity?: Record<string, number>;
  total?: number;
};
