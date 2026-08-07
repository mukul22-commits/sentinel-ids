import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getOidcConfig, oidcAuthorize } from "../api/endpoints";
import { ACCESS_TOKEN_KEY, REFRESH_TOKEN_KEY } from "../api/client";
import { AuthProvider } from "../auth/AuthContext";
import Login from "../pages/Login";
import OidcCallback from "../pages/OidcCallback";

vi.mock("../api/endpoints", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/endpoints")>();
  return {
    ...actual,
    getOidcConfig: vi.fn().mockResolvedValue({
      enabled: true,
      issuer: null,
      client_id: null,
      scopes: "openid email profile",
      redirect_path: "/api/v1/auth/oidc/callback",
    }),
    oidcAuthorize: vi.fn().mockResolvedValue({
      url: "https://idp.example/authorize?state=abc",
      state: "abc",
    }),
  };
});

beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
});

describe("OidcCallback", () => {
  it("stores the token pair and navigates home", async () => {
    render(
      <MemoryRouter initialEntries={["/auth/oidc/callback?access_token=abc&refresh_token=xyz"]}>
        <Routes>
          <Route path="/auth/oidc/callback" element={<OidcCallback />} />
          <Route path="/" element={<div>home-ok</div>} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByText("home-ok")).toBeInTheDocument();
    expect(localStorage.getItem(ACCESS_TOKEN_KEY)).toBe("abc");
    expect(localStorage.getItem(REFRESH_TOKEN_KEY)).toBe("xyz");
  });

  it("shows an error when tokens are missing", async () => {
    render(
      <MemoryRouter initialEntries={["/auth/oidc/callback"]}>
        <Routes>
          <Route path="/auth/oidc/callback" element={<OidcCallback />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByText(/missing tokens/i)).toBeInTheDocument();
  });
});

describe("SSO login button", () => {
  it("redirects to the provider authorization URL on click", async () => {
    const assign = vi.fn();
    Object.defineProperty(window, "location", {
      configurable: true,
      writable: true,
      value: { assign },
    });

    render(
      <MemoryRouter>
        <AuthProvider>
          <Login />
        </AuthProvider>
      </MemoryRouter>,
    );

    const button = await screen.findByRole("button", { name: /sign in with sso/i });
    fireEvent.click(button);
    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith("https://idp.example/authorize?state=abc"),
    );
  });

  it("hides the SSO button when OIDC is disabled", async () => {
    vi.mocked(getOidcConfig).mockResolvedValueOnce({
      enabled: false,
      issuer: null,
      client_id: null,
      scopes: "openid email profile",
      redirect_path: "/api/v1/auth/oidc/callback",
    });

    render(
      <MemoryRouter>
        <AuthProvider>
          <Login />
        </AuthProvider>
      </MemoryRouter>,
    );

    await screen.findByRole("button", { name: "Create account" });
    expect(screen.queryByRole("button", { name: /sign in with sso/i })).not.toBeInTheDocument();
  });

  it("surfaces an error when the authorize call fails", async () => {
    vi.mocked(oidcAuthorize).mockRejectedValueOnce(new Error("SSO unavailable"));

    render(
      <MemoryRouter>
        <AuthProvider>
          <Login />
        </AuthProvider>
      </MemoryRouter>,
    );

    const button = await screen.findByRole("button", { name: /sign in with sso/i });
    fireEvent.click(button);
    expect(await screen.findByText("SSO unavailable")).toBeInTheDocument();
  });
});
