import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createPolicy,
  getOidcConfig,
  importPcap,
  listConnectors,
  listPackets,
  listPolicies,
  oidcAuthorize,
  retrainMl,
  testConnector,
} from "../api/endpoints";

const BASE = "/api/v1";

function jsonResponse(data: unknown, ok = true): Response {
  return {
    ok,
    status: ok ? 200 : 400,
    json: async () => ({
      success: ok,
      data,
      error: ok ? null : "boom",
      request_id: "rid",
    }),
  } as unknown as Response;
}

interface Call {
  url: string;
  method: string;
  body: unknown;
}

function mockFetch(data: unknown) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({
        url: String(input),
        method: init?.method ?? "GET",
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      return jsonResponse(data);
    }),
  );
  return calls;
}

beforeEach(() => {
  localStorage.clear();
});

describe("response policy endpoints", () => {
  it("builds a filtered policy list URL", async () => {
    const calls = mockFetch({ items: [], total: 0, page: 1, page_size: 50 });
    await listPolicies({ enabled: false, page: 2, page_size: 50 });
    expect(calls[0].url).toBe(`${BASE}/policies?enabled=false&page=2&page_size=50`);
    expect(calls[0].method).toBe("GET");
  });

  it("omits filters when not provided", async () => {
    const calls = mockFetch({ items: [], total: 0, page: 1, page_size: 50 });
    await listPolicies();
    expect(calls[0].url).toBe(`${BASE}/policies`);
  });

  it("posts the create body", async () => {
    const calls = mockFetch({ id: 1 });
    await createPolicy({
      name: "Block scanner",
      actions: [{ action_type: "block", target_type: "ip", target_value: "1.2.3.4" }],
    });
    expect(calls[0].url).toBe(`${BASE}/policies`);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].body).toEqual({
      name: "Block scanner",
      actions: [{ action_type: "block", target_type: "ip", target_value: "1.2.3.4" }],
    });
  });
});

describe("system endpoints", () => {
  it("lists connectors", async () => {
    const calls = mockFetch([{ name: "http" }]);
    const result = await listConnectors();
    expect(calls[0].url).toBe(`${BASE}/system/connectors`);
    expect(result).toEqual([{ name: "http" }]);
  });

  it("tests a connector", async () => {
    const calls = mockFetch({ status: "ok" });
    await testConnector("email");
    expect(calls[0].url).toBe(`${BASE}/system/connectors/email/test`);
    expect(calls[0].method).toBe("POST");
  });

  it("retrains the ML model", async () => {
    const calls = mockFetch({ status: "skipped" });
    await retrainMl();
    expect(calls[0].url).toBe(`${BASE}/system/ml/retrain`);
    expect(calls[0].method).toBe("POST");
  });
});

describe("packet endpoints", () => {
  it("builds a filtered packet list URL", async () => {
    const calls = mockFetch({ items: [], total: 0, page: 1, page_size: 50 });
    await listPackets({ src_ip: "10.0.0.1", proto: "tcp", page: 2 });
    expect(calls[0].url).toBe(`${BASE}/packets?src_ip=10.0.0.1&proto=tcp&page=2`);
    expect(calls[0].method).toBe("GET");
  });

  it("omits packet filters when not provided", async () => {
    const calls = mockFetch({ items: [], total: 0, page: 1, page_size: 50 });
    await listPackets();
    expect(calls[0].url).toBe(`${BASE}/packets`);
  });

  it("uploads a pcap as multipart form data", async () => {
    const calls: Array<{ url: string; method: string; body: BodyInit | null | undefined }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({
          url: String(input),
          method: init?.method ?? "GET",
          body: init?.body,
        });
        return jsonResponse({ ingested: 5, alerts: 2 });
      }),
    );
    const file = new File(["data"], "capture.pcap", { type: "application/octet-stream" });
    const result = await importPcap(file);
    expect(calls[0].url).toBe(`${BASE}/packets/import`);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].body).toBeInstanceOf(FormData);
    expect(result).toEqual({ ingested: 5, alerts: 2 });
  });
});

describe("OIDC endpoints", () => {
  it("reads public config", async () => {
    const calls = mockFetch({
      enabled: true,
      issuer: null,
      client_id: null,
      scopes: "openid email profile",
      redirect_path: "/api/v1/auth/oidc/callback",
    });
    const config = await getOidcConfig();
    expect(calls[0].url).toBe(`${BASE}/auth/oidc/config`);
    expect(config.enabled).toBe(true);
  });

  it("requests an authorization URL", async () => {
    const calls = mockFetch({ url: "https://idp.example/authorize?state=s", state: "s" });
    const result = await oidcAuthorize();
    expect(calls[0].url).toBe(`${BASE}/auth/oidc/authorize`);
    expect(result.state).toBe("s");
  });
});
