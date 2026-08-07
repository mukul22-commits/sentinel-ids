import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { getOidcConfig, oidcAuthorize } from "../api/endpoints";
import { InlineError } from "../components/Spinner";

type Mode = "signin" | "signup";

const inputClass =
  "w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-emerald-500 focus:outline-hidden focus:ring-1 focus:ring-emerald-500";

export default function Login() {
  const { status, login, register } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<Mode>("signin");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [ssoBusy, setSsoBusy] = useState(false);

  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [fullName, setFullName] = useState("");

  useEffect(() => {
    let cancelled = false;
    getOidcConfig()
      .then((config) => {
        if (!cancelled) setSsoEnabled(config.enabled);
      })
      .catch(() => {
        if (!cancelled) setSsoEnabled(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (status === "authenticated") {
    return <Navigate to="/" replace />;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "signin") {
        await login(identifier, password);
      } else {
        await register({ email, username, password, full_name: fullName || undefined });
      }
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleSso() {
    setError(null);
    setSsoBusy(true);
    try {
      const result = await oidcAuthorize();
      window.location.assign(result.url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "SSO unavailable");
      setSsoBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-6 text-slate-100">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-3xl font-bold tracking-tight text-emerald-400">SENTINEL IDS</h1>
          <p className="mt-1 text-sm text-slate-400">Detect, Analyze, Respond</p>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900 p-6 shadow-xl">
          <div className="mb-5 grid grid-cols-2 gap-1 rounded-md bg-slate-800 p-1 text-sm">
            <button
              type="button"
              onClick={() => setMode("signin")}
              className={`rounded-sm px-3 py-1.5 ${
                mode === "signin" ? "bg-slate-900 text-emerald-300" : "text-slate-400"
              }`}
            >
              Sign in
            </button>
            <button
              type="button"
              onClick={() => setMode("signup")}
              className={`rounded-sm px-3 py-1.5 ${
                mode === "signup" ? "bg-slate-900 text-emerald-300" : "text-slate-400"
              }`}
            >
              Create account
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === "signin" ? (
              <>
                <div>
                  <label
                    htmlFor="identifier"
                    className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400"
                  >
                    Email or username
                  </label>
                  <input
                    id="identifier"
                    className={inputClass}
                    value={identifier}
                    onChange={(event) => setIdentifier(event.target.value)}
                    required
                    autoComplete="username"
                  />
                </div>
                <div>
                  <label
                    htmlFor="password"
                    className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400"
                  >
                    Password
                  </label>
                  <input
                    id="password"
                    type="password"
                    className={inputClass}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    required
                    autoComplete="current-password"
                  />
                </div>
              </>
            ) : (
              <>
                <div>
                  <label
                    htmlFor="email"
                    className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400"
                  >
                    Email
                  </label>
                  <input
                    id="email"
                    type="email"
                    className={inputClass}
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    required
                    autoComplete="email"
                  />
                </div>
                <div>
                  <label
                    htmlFor="username"
                    className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400"
                  >
                    Username
                  </label>
                  <input
                    id="username"
                    className={inputClass}
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    required
                    minLength={3}
                    autoComplete="username"
                  />
                </div>
                <div>
                  <label
                    htmlFor="fullName"
                    className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400"
                  >
                    Full name (optional)
                  </label>
                  <input
                    id="fullName"
                    className={inputClass}
                    value={fullName}
                    onChange={(event) => setFullName(event.target.value)}
                    autoComplete="name"
                  />
                </div>
                <div>
                  <label
                    htmlFor="newPassword"
                    className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400"
                  >
                    Password
                  </label>
                  <input
                    id="newPassword"
                    type="password"
                    className={inputClass}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    required
                    minLength={12}
                    autoComplete="new-password"
                  />
                  <p className="mt-1 text-[11px] text-slate-500">
                    At least 12 characters; avoid common passwords.
                  </p>
                </div>
              </>
            )}

            <InlineError message={error ?? ""} />

            <button
              type="submit"
              disabled={busy}
              className="w-full rounded-md bg-emerald-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
            >
              {busy ? "Please wait…" : mode === "signin" ? "Sign in" : "Create account"}
            </button>
          </form>

          {ssoEnabled && mode === "signin" && (
            <>
              <div className="my-4 flex items-center gap-3 text-xs uppercase tracking-wide text-slate-500">
                <span className="h-px flex-1 bg-slate-700" />
                or
                <span className="h-px flex-1 bg-slate-700" />
              </div>
              <button
                type="button"
                onClick={() => void handleSso()}
                disabled={ssoBusy}
                className="w-full rounded-md border border-slate-600 px-3 py-2 text-sm font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-50"
              >
                {ssoBusy ? "Redirecting…" : "Sign in with SSO"}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
