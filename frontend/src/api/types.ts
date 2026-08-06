export interface Envelope<T> {
  success: boolean;
  data: T | null;
  error: string | null;
  request_id: string | null;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  refresh_expires_in: number;
}

export interface User {
  id: number;
  email: string;
  username: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface TimelineEntry {
  ts: string;
  actor: string;
  action: string;
  note: string | null;
  details: Record<string, unknown> | null;
}

export type IncidentStatus = "open" | "in_progress" | "resolved" | "closed";
export type IncidentSeverity = "low" | "medium" | "high" | "critical";

export interface Incident {
  id: number;
  title: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assignee_id: number | null;
  alert_ids: number[];
  timeline: TimelineEntry[];
  created_at: string;
  updated_at: string;
}

export type ActionType = "block" | "quarantine" | "notify";
export type ActionTargetType = "ip" | "port" | "host" | "email";
export type ActionStatus = "pending" | "executing" | "succeeded" | "failed";

export interface ResponseAction {
  id: number;
  incident_id: number;
  action_type: ActionType;
  target_type: ActionTargetType;
  target_value: string;
  status: ActionStatus;
  details: Record<string, unknown>[];
  created_by: number | null;
  executed_at: string | null;
  created_at: string;
}

export interface Notification {
  id: number;
  incident_id: number | null;
  title: string;
  body: string | null;
  severity: string | null;
  read: boolean;
  created_at: string;
}

export interface RealtimeEvent {
  type: string;
  payload: unknown;
}

export type SensorStatus = "online" | "offline" | "disabled";

export interface Sensor {
  id: number;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  version: string | null;
  status: SensorStatus;
  enabled: boolean;
  config: Record<string, unknown>;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface FleetSummary {
  total: number;
  online: number;
  offline: number;
  disabled: number;
  alerts_last_24h: number;
  alerts_by_sensor: Record<string, number>;
  captures_by_sensor: Record<string, number>;
}
