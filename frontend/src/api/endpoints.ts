import { api, clearTokens, setTokens } from "./client";
import type {
  ActionStatus,
  ActionType,
  ActionTargetType,
  FleetSummary,
  Incident,
  IncidentSeverity,
  IncidentStatus,
  Notification,
  Paginated,
  ResponseAction,
  Sensor,
  SensorStatus,
  TokenPair,
  User,
} from "./types";

const BASE = "/api/v1";

export interface LoginInput {
  identifier: string;
  password: string;
}

export interface RegisterInput {
  email: string;
  username: string;
  password: string;
  full_name?: string;
}

export async function login(input: LoginInput): Promise<void> {
  const pair = await api.post<TokenPair>(`${BASE}/auth/login`, input);
  setTokens(pair);
}

export async function register(input: RegisterInput): Promise<User> {
  return api.post<User>(`${BASE}/auth/register`, input);
}

export async function fetchMe(): Promise<User> {
  return api.get<User>(`${BASE}/auth/me`);
}

export async function logout(): Promise<void> {
  try {
    await api.postEmpty<boolean>(`${BASE}/auth/logout`);
  } finally {
    clearTokens();
  }
}

export interface IncidentQuery {
  status?: IncidentStatus;
  severity?: IncidentSeverity;
  assignee_id?: number;
  page?: number;
  page_size?: number;
}

export async function listIncidents(query: IncidentQuery = {}): Promise<Paginated<Incident>> {
  const params = new URLSearchParams();
  if (query.status) params.set("status", query.status);
  if (query.severity) params.set("severity", query.severity);
  if (query.assignee_id) params.set("assignee_id", String(query.assignee_id));
  if (query.page) params.set("page", String(query.page));
  if (query.page_size) params.set("page_size", String(query.page_size));
  const qs = params.toString();
  return api.get<Paginated<Incident>>(`${BASE}/incidents${qs ? `?${qs}` : ""}`);
}

export async function getIncident(id: number): Promise<Incident> {
  return api.get<Incident>(`${BASE}/incidents/${id}`);
}

export async function createIncident(input: {
  title: string;
  severity: IncidentSeverity;
  note?: string;
}): Promise<Incident> {
  return api.post<Incident>(`${BASE}/incidents`, { ...input, alert_ids: [] });
}

export async function updateIncident(
  id: number,
  input: Partial<Pick<Incident, "title" | "severity">> & { assignee_id?: number | null },
): Promise<Incident> {
  return api.patch<Incident>(`${BASE}/incidents/${id}`, input);
}

export async function setIncidentStatus(id: number, status: IncidentStatus): Promise<Incident> {
  return api.patch<Incident>(`${BASE}/incidents/${id}/status`, { status });
}

export async function addTimelineEntry(
  id: number,
  input: { action: string; note?: string },
): Promise<Incident> {
  return api.post<Incident>(`${BASE}/incidents/${id}/timeline`, input);
}

export async function listActions(id: number): Promise<ResponseAction[]> {
  return api.get<ResponseAction[]>(`${BASE}/incidents/${id}/actions`);
}

export async function createAction(
  id: number,
  input: { action_type: ActionType; target_type: ActionTargetType; target_value: string },
): Promise<ResponseAction> {
  return api.post<ResponseAction>(`${BASE}/incidents/${id}/actions`, input);
}

export async function executeAction(incidentId: number, actionId: number): Promise<ResponseAction> {
  return api.postEmpty<ResponseAction>(
    `${BASE}/incidents/${incidentId}/actions/${actionId}/execute`,
  );
}

export async function listNotifications(
  query: {
    unread_only?: boolean;
    page?: number;
    page_size?: number;
  } = {},
): Promise<Paginated<Notification>> {
  const params = new URLSearchParams();
  if (query.unread_only) params.set("unread_only", "true");
  if (query.page) params.set("page", String(query.page));
  if (query.page_size) params.set("page_size", String(query.page_size));
  const qs = params.toString();
  return api.get<Paginated<Notification>>(`${BASE}/notifications${qs ? `?${qs}` : ""}`);
}

export async function unreadCount(): Promise<number> {
  return api.get<number>(`${BASE}/notifications/unread-count`);
}

export async function markNotificationRead(id: number): Promise<Notification> {
  return api.postEmpty<Notification>(`${BASE}/notifications/${id}/read`);
}

export async function markAllNotificationsRead(): Promise<number> {
  return api.postEmpty<number>(`${BASE}/notifications/read-all`);
}

export async function listSensors(
  query: { status?: SensorStatus; page?: number; page_size?: number } = {},
): Promise<Paginated<Sensor>> {
  const params = new URLSearchParams();
  if (query.status) params.set("status", query.status);
  if (query.page) params.set("page", String(query.page));
  if (query.page_size) params.set("page_size", String(query.page_size));
  const qs = params.toString();
  return api.get<Paginated<Sensor>>(`${BASE}/sensors${qs ? `?${qs}` : ""}`);
}

export async function getFleetSummary(): Promise<FleetSummary> {
  return api.get<FleetSummary>(`${BASE}/sensors/fleet`);
}

export interface SensorRegistration {
  sensor: Sensor;
  token: string;
}

export async function registerSensor(input: {
  name: string;
  hostname?: string;
  ip_address?: string;
  version?: string;
}): Promise<SensorRegistration> {
  return api.post<SensorRegistration>(`${BASE}/sensors`, input);
}

export async function updateSensor(
  id: number,
  input: {
    name?: string;
    hostname?: string;
    ip_address?: string;
    version?: string;
    enabled?: boolean;
  },
): Promise<Sensor> {
  return api.patch<Sensor>(`${BASE}/sensors/${id}`, input);
}

export async function rotateSensorToken(id: number): Promise<{ token: string }> {
  return api.postEmpty<{ token: string }>(`${BASE}/sensors/${id}/rotate-token`);
}

export async function deleteSensor(id: number): Promise<{ deleted: boolean }> {
  return api.del<{ deleted: boolean }>(`${BASE}/sensors/${id}`);
}

export const ACTION_STATUSES: ActionStatus[] = ["pending", "executing", "succeeded", "failed"];
