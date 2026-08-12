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

export interface PolicyAction {
  action_type: ActionType;
  target_type: ActionTargetType;
  target_value: string;
}

export interface PolicyConditions {
  severity: string[];
  detectors: string[];
  categories: string[];
  min_risk_score: number;
}

export interface ResponsePolicy {
  id: number;
  name: string;
  enabled: boolean;
  conditions: PolicyConditions;
  actions: PolicyAction[];
  cooldown_seconds: number;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface ConnectorStatus {
  name: string;
  kind: string;
  enabled: boolean;
  description: string;
}

export interface SiemRun {
  id: number;
  status: string;
  alerts_exported: number;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
}

export interface SiemStatus {
  enabled: boolean;
  endpoint_configured: boolean;
  endpoint: string | null;
  batch_size: number;
  configured: boolean;
  pending_alerts: number;
  last_run: SiemRun | null;
}

export interface ModelMetadata {
  path: string;
  exists: boolean;
  enabled: boolean;
  size_bytes?: number;
  modified_at?: string;
}

export interface MlStatus extends ModelMetadata {
  min_samples: number;
  contamination: number;
}

export interface AutoencoderStatus extends ModelMetadata {
  threshold: number;
}

export interface UebaStatus extends ModelMetadata {
  window_hours: number;
  threshold: number;
}

export interface YaraRuleRef {
  file: string;
  name: string;
}

export interface YaraLoadError {
  file: string;
  error: string;
}

export interface YaraStatus {
  enabled: boolean;
  rules_dir: string;
  max_payload_bytes: number;
  rule_count: number;
  rules: YaraRuleRef[];
  load_errors: YaraLoadError[];
}

export interface OidcConfig {
  enabled: boolean;
  issuer: string | null;
  client_id: string | null;
  scopes: string;
  redirect_path: string;
}

export interface OidcAuthorize {
  url: string;
  state: string;
}

export interface Packet {
  id: number;
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  proto: string;
  length: number;
  flags: string | null;
  payload_hash: string | null;
  raw_ref: string | null;
  ts: string;
}

export interface PacketIngestSummary {
  ingested: number;
  alerts: number;
}
