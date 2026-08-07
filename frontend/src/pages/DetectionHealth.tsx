import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { getUebaStatus, getYaraStatus, reloadYaraRules, retrainUeba } from "../api/endpoints";
import type { UebaStatus, YaraStatus } from "../api/types";
import { InlineError, Spinner } from "../components/Spinner";

function formatBytes(value: number | undefined): string {
  if (value === undefined) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function Badge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ${
        ok
          ? "bg-emerald-500/20 text-emerald-300 ring-emerald-500/40"
          : "bg-amber-500/20 text-amber-300 ring-amber-500/40"
      }`}
    >
      {label}
    </span>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-0.5 text-sm text-slate-100">{value}</p>
    </div>
  );
}

export default function DetectionHealth() {
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const yaraQuery = useQuery({
    queryKey: ["system", "detection", "yara"],
    queryFn: getYaraStatus,
  });

  const uebaQuery = useQuery({
    queryKey: ["system", "detection", "ueba"],
    queryFn: getUebaStatus,
  });

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ["system", "detection"] });
  }

  const reload = useMutation({
    mutationFn: reloadYaraRules,
    onSuccess: () => invalidate(),
    onError: (err: Error) => setError(err.message),
  });

  const uebaRetrain = useMutation({
    mutationFn: retrainUeba,
    onSuccess: (result) => {
      setError(null);
      if (result.status === "skipped") {
        setError(String(result.reason ?? "Not enough flow history to rebuild baselines yet."));
      }
      invalidate();
    },
    onError: (err: Error) => setError(err.message),
  });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Detection health</h1>
        <p className="text-sm text-slate-400">YARA rule engine and UEBA baseline status</p>
      </header>

      <InlineError message={error ?? ""} />

      <section>
        <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">YARA</h2>
        <YaraCard
          yara={yaraQuery.data}
          loading={yaraQuery.isLoading}
          reloading={reload.isPending}
          onReload={() => reload.mutate()}
        />
      </section>

      <section>
        <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
          UEBA baselines
        </h2>
        <UebaCard
          ueba={uebaQuery.data}
          loading={uebaQuery.isLoading}
          retraining={uebaRetrain.isPending}
          onRetrain={() => uebaRetrain.mutate()}
        />
      </section>
    </div>
  );
}

function YaraCard({
  yara,
  loading,
  reloading,
  onReload,
}: {
  yara: YaraStatus | undefined;
  loading: boolean;
  reloading: boolean;
  onReload: () => void;
}) {
  if (loading) return <Spinner label="YARA status…" />;
  if (!yara) return null;
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Badge ok={yara.enabled} label={yara.enabled ? "enabled" : "disabled"} />
          <Badge ok={yara.rule_count > 0} label={`${yara.rule_count} rules loaded`} />
        </div>
        <button
          type="button"
          onClick={onReload}
          disabled={reloading}
          className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
        >
          {reloading ? "Reloading…" : "Reload rules"}
        </button>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <Stat label="Rules directory" value={yara.rules_dir} />
        <Stat label="Rules" value={yara.rule_count} />
        <Stat label="Max payload bytes" value={yara.max_payload_bytes} />
      </div>

      {yara.load_errors.length > 0 && (
        <div className="mt-4 rounded-md border border-amber-500/30 bg-amber-500/10 p-3">
          <p className="text-xs font-medium uppercase tracking-wide text-amber-300">
            Load errors ({yara.load_errors.length})
          </p>
          <ul className="mt-2 space-y-1 text-xs text-amber-200/80">
            {yara.load_errors.map((item, index) => (
              <li key={index}>
                <span className="font-mono">{item.file}</span>: {item.error}
              </li>
            ))}
          </ul>
        </div>
      )}

      <details className="mt-4">
        <summary className="cursor-pointer text-xs font-medium uppercase tracking-wide text-slate-500 hover:text-slate-300">
          Loaded rules ({yara.rules.length})
        </summary>
        <ul className="mt-2 grid gap-1 text-xs text-slate-400 sm:grid-cols-2">
          {yara.rules.map((rule, index) => (
            <li key={index} className="truncate">
              <span className="font-mono text-emerald-300/80">{rule.name}</span>{" "}
              <span className="text-slate-600">· {rule.file}</span>
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}

function UebaCard({
  ueba,
  loading,
  retraining,
  onRetrain,
}: {
  ueba: UebaStatus | undefined;
  loading: boolean;
  retraining: boolean;
  onRetrain: () => void;
}) {
  if (loading) return <Spinner label="UEBA status…" />;
  if (!ueba) return null;
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Badge ok={ueba.enabled} label={ueba.enabled ? "enabled" : "disabled"} />
          <Badge ok={ueba.exists} label={ueba.exists ? "baselines present" : "not trained"} />
        </div>
        <button
          type="button"
          onClick={onRetrain}
          disabled={retraining}
          className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
        >
          {retraining ? "Retraining…" : "Rebuild baselines"}
        </button>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <Stat label="Window (hours)" value={ueba.window_hours} />
        <Stat label="Deviation threshold" value={ueba.threshold} />
        <Stat label="Baseline size" value={formatBytes(ueba.size_bytes)} />
      </div>
      <p className="mt-2 text-xs text-slate-500">
        Trained at {ueba.modified_at ? new Date(ueba.modified_at).toLocaleString() : "never"}
      </p>
      <p className="mt-1 break-all font-mono text-[11px] text-slate-600">{ueba.path}</p>
    </div>
  );
}
