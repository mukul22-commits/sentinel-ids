import type { APIRequestContext, Page, TestInfo } from "@playwright/test";

/**
 * Shared helpers for the Sentinel IDS e2e suite.
 *
 * Token storage (frontend/src/api/client.ts):
 *   - localStorage "sentinel.access_token"
 *   - localStorage "sentinel.refresh_token"
 *
 * API routing:
 *   - By default API calls go through the frontend origin (the Vite dev server
 *     proxies /api to the backend on :8000, see frontend/vite.config.ts).
 *   - Set E2E_API_URL (e.g. http://localhost:8000) to talk to the backend
 *     directly when the proxy is not available.
 */

export const DEFAULT_PASSWORD = "E2e-Strong-Passw0rd!";

export interface TestUser {
  email: string;
  username: string;
  password: string;
  id?: number;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  refresh_expires_in: number;
}

interface Envelope<T> {
  success: boolean;
  data: T | null;
  error: string | null;
  request_id: string | null;
}

/** Resolve the frontend base URL the current test is running against. */
export function appBaseUrl(testInfo: TestInfo): string {
  return testInfo.project.use.baseURL ?? process.env.E2E_BASE_URL ?? "http://localhost:5173";
}

/** Resolve the API base URL (frontend proxy by default, backend override allowed). */
export function apiBaseUrl(baseURL: string): string {
  return process.env.E2E_API_URL ?? baseURL;
}

function randomSuffix(): string {
  return `${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36).slice(-4)}`;
}

/** Unique email, e.g. e2e.abc123@example.com */
export function randomEmail(): string {
  return `e2e.${randomSuffix()}@example.com`;
}

/** Unique username, e.g. e2e_abc123 */
export function randomUsername(): string {
  return `e2e_${randomSuffix()}`;
}

/** Register a user via POST /api/v1/auth/register (open in dev/test). */
export async function registerUser(request: APIRequestContext, baseURL: string): Promise<TestUser> {
  const user: TestUser = {
    email: randomEmail(),
    username: randomUsername(),
    password: DEFAULT_PASSWORD,
  };
  const response = await request.post(`${apiBaseUrl(baseURL)}/api/v1/auth/register`, {
    data: { email: user.email, username: user.username, password: user.password },
  });
  if (!response.ok()) {
    throw new Error(
      `register failed (${response.status()}): ${(await response.text()).slice(0, 300)}`,
    );
  }
  const envelope = (await response.json()) as Envelope<{ id: number }>;
  user.id = envelope.data?.id;
  return user;
}

/** Log in via POST /api/v1/auth/login and return the token pair. */
export async function loginViaApi(
  request: APIRequestContext,
  baseURL: string,
  identifier: string,
  password: string,
): Promise<TokenPair> {
  const response = await request.post(`${apiBaseUrl(baseURL)}/api/v1/auth/login`, {
    data: { identifier, password },
  });
  if (!response.ok()) {
    throw new Error(`login failed (${response.status()}): ${(await response.text()).slice(0, 300)}`);
  }
  const envelope = (await response.json()) as Envelope<TokenPair>;
  if (!envelope.data) {
    throw new Error("login succeeded but returned no token pair");
  }
  return envelope.data;
}

/** Register + login via API; returns the user and its token pair. */
export async function createAuthenticatedUser(
  request: APIRequestContext,
  baseURL: string,
): Promise<{ user: TestUser; tokens: TokenPair }> {
  const user = await registerUser(request, baseURL);
  const tokens = await loginViaApi(request, baseURL, user.email, user.password);
  return { user, tokens };
}

/**
 * Seed the app's localStorage tokens on every navigation for this page.
 * Must be called before the first page.goto() so AuthProvider finds the
 * session during bootstrap (frontend/src/auth/AuthContext.tsx).
 */
export async function seedTokens(page: Page, tokens: TokenPair): Promise<void> {
  await page.addInitScript(
    ({ access, refresh }) => {
      window.localStorage.setItem("sentinel.access_token", access);
      window.localStorage.setItem("sentinel.refresh_token", refresh);
    },
    { access: tokens.access_token, refresh: tokens.refresh_token },
  );
}

/**
 * Create an incident via POST /api/v1/incidents so the incidents list is
 * deterministic. Returns the created incident id, or null when the backend
 * rejects the request (e.g. no manage_incidents permission).
 */
export async function createIncidentViaApi(
  request: APIRequestContext,
  baseURL: string,
  accessToken: string,
  title: string,
): Promise<{ id: number } | null> {
  const response = await request.post(`${apiBaseUrl(baseURL)}/api/v1/incidents`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    data: { title, severity: "medium", note: "created by the e2e suite", alert_ids: [] },
  });
  if (!response.ok()) {
    return null;
  }
  const envelope = (await response.json()) as Envelope<{ id: number }>;
  return envelope.data ?? null;
}
