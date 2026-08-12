import type { Envelope } from "./types";

export const ACCESS_TOKEN_KEY = "sentinel.access_token";
export const REFRESH_TOKEN_KEY = "sentinel.refresh_token";

const AUTH_REFRESH_PATH = "/api/v1/auth/refresh";

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(pair: { access_token: string; refresh_token: string }): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, pair.access_token);
  localStorage.setItem(REFRESH_TOKEN_KEY, pair.refresh_token);
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

let refreshPromise: Promise<boolean> | null = null;

async function doFetch(path: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(path, init);
  } catch {
    throw new ApiError("Backend unreachable", 0);
  }
}

function buildHeaders(init: RequestInit): Headers {
  const headers = new Headers(init.headers);
  const token = getAccessToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (init.body !== undefined && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  return headers;
}

async function tryRefreshToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    return false;
  }
  if (refreshPromise) {
    return refreshPromise;
  }
  refreshPromise = (async () => {
    try {
      const response = await doFetch(AUTH_REFRESH_PATH, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!response.ok) {
        return false;
      }
      const payload = (await response.json().catch(() => null)) as Envelope<{
        access_token: string;
        refresh_token: string;
      }> | null;
      if (!payload || payload.success !== true || !payload.data) {
        return false;
      }
      setTokens(payload.data);
      return true;
    } catch {
      return false;
    } finally {
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

function readPayload(response: Response): Promise<Envelope<unknown> | null> {
  return response.json().catch(() => null);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let headers = buildHeaders(init);
  let response = await doFetch(path, { ...init, headers });

  if (response.status === 401 && path !== AUTH_REFRESH_PATH) {
    const refreshed = await tryRefreshToken();
    if (refreshed) {
      headers = buildHeaders(init);
      response = await doFetch(path, { ...init, headers });
    } else {
      clearTokens();
    }
  }

  const payload = (await readPayload(response)) as Envelope<unknown> | null;

  if (!response.ok) {
    throw new ApiError(payload?.error ?? `Request failed (${response.status})`, response.status);
  }
  if (payload && typeof payload === "object" && payload.success === false) {
    throw new ApiError(payload.error ?? "Request failed", response.status);
  }
  return (payload?.data ?? null) as T;
}

function jsonBody(body: unknown): RequestInit {
  return { method: "POST", body: JSON.stringify(body) };
}

export const api = {
  get: <T>(path: string): Promise<T> => request<T>(path),
  post: <T>(path: string, body: unknown): Promise<T> => request<T>(path, jsonBody(body)),
  patch: <T>(path: string, body: unknown): Promise<T> =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  postEmpty: <T>(path: string): Promise<T> => request<T>(path, { method: "POST" }),
  del: <T>(path: string): Promise<T> => request<T>(path, { method: "DELETE" }),
  upload: <T>(path: string, formData: FormData): Promise<T> =>
    request<T>(path, { method: "POST", body: formData }),
};
