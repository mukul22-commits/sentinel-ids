import { useEffect, useState } from "react";

interface PingResponse {
  success: boolean;
  data: string | null;
  error: string | null;
  request_id: string | null;
}

export default function App() {
  const [ping, setPing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/ping")
      .then((response) => response.json() as Promise<PingResponse>)
      .then((data) => setPing(data.data))
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Unknown error");
      });
  }, []);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 bg-slate-950 px-6 text-slate-100">
      <header className="space-y-2 text-center">
        <h1 className="text-4xl font-bold tracking-tight text-emerald-400">
          SENTINEL IDS PLATFORM v3.0
        </h1>
        <p className="text-lg text-slate-400">
          Detect, Analyze, Respond – Secure Every Packet, Every Time.
        </p>
      </header>
      <section className="text-center">
        {error && <p className="text-red-400">Backend unreachable: {error}</p>}
        {!error && ping === null && <p className="text-slate-400">Contacting backend…</p>}
        {!error && ping !== null && <p className="text-emerald-300">Backend says: “{ping}”</p>}
      </section>
    </div>
  );
}
