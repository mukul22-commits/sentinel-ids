import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { setTokens } from "../api/client";
import { InlineError } from "../components/Spinner";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export default function OidcCallback() {
  useDocumentTitle("Completing sign in");
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const accessToken = params.get("access_token");
    const refreshToken = params.get("refresh_token");
    if (!accessToken || !refreshToken) {
      setError("Sign-in response was missing tokens. Please try again.");
      return;
    }
    setTokens({
      access_token: accessToken,
      refresh_token: refreshToken,
    });
    navigate("/", { replace: true });
  }, [params, navigate]);

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 px-6 text-slate-100">
        <div className="w-full max-w-sm space-y-4">
          <h1 className="text-2xl font-semibold tracking-tight">Single sign-on</h1>
          <InlineError message={error} />
          <Link
            to="/login"
            className="inline-block rounded-md bg-emerald-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400"
          >
            Back to sign in
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-100">
      <p className="text-sm text-slate-400">Completing sign-in…</p>
    </div>
  );
}
