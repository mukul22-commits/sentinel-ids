import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import {
  exportSiem,
  getAutoencoderStatus,
  getMlStatus,
  getSiemStatus,
  listConnectors,
  retrainAutoencoder,
  retrainMl,
  testConnector,
  testSiem,
} from "../api/endpoints";
import type { AutoencoderStatus, ConnectorStatus, MlStatus, SiemStatus } from "../api/types";
import { InlineError, Spinner } from "../components/Spinner";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

function formatBytes(value: number | undefined): string {
  if (value === undefined) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function ResultNotice({ result }: { result: Record<string, unknown> | null }) {
  if (!result) return null;
  const status = result.status;
  const reason = result.reason ? String(result.reason) : null;
  const anomalyRate = result.anomaly_rate;
  return (
    <div
      className={`mt-2 rounded-md border p-3 text-sm ${
        status === "skipped"
          ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
          : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
      }`}
    >
      <p className="font-medium">{status === "skipped" ? "Skipped" : "Trained"}</p>
      {reason && <p className="text-xs opacity-80">{reason}</p>}
      {typeof anomalyRate === "number" && (
        <p className="text-xs opacity-80">anomaly rate {anomalyRate}</p>
      )}
    </div>
  );
}

function ConnectorCard({
  connector,
  onTest,
  busy,
}: {
  connector: ConnectorStatus;
  onTest: () => void;
  busy: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="font-medium text-slate-100">{connector.name}</p>
          <p className="text-xs text-slate-500">{connector.kind}</p>
        </div>
        <span
          className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ${
            connector.enabled
              ? "bg-emerald-500/20 text-emerald-300 ring-emerald-500/40"
              : "bg-slate-500/20 text-slate-300 ring-slate-500/40"
          }`}
        >
          {connector.enabled ? "ready" : "disabled"}
        </span>
      </div>
      <p className="mt-2 text-sm text-slate-400">{connector.description}</p>
      <button
        type="button"
        onClick={onTest}
        disabled={busy}
        className="mt-3 rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
      >
        {busy ? "Testing…" : "Test connection"}
      </button>
    </div>
  );
}

export default function SystemStatus() {
  useDocumentTitle("System status");
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  const connectorsQuery = useQuery({
    queryKey: ["system", "connectors"],
    queryFn: listConnectors,
  });

  const siemQuery = useQuery({
    queryKey: ["system", "siem"],
    queryFn: getSiemStatus,
  });

  const mlQuery = useQuery({
    queryKey: ["system", "ml"],
    queryFn: getMlStatus,
  });

  const autoencoderQuery = useQuery({
    queryKey: ["system", "ml", "autoencoder"],
    queryFn: getAutoencoderStatus,
  });

  function invalidateSystem() {
    void queryClient.invalidateQueries({ queryKey: ["system"] });
  }

  const testConnectorMutation = useMutation({
    mutationFn: (name: string) => testConnector(name),
    onSuccess: (result) => setNotice({ status: "trained", ...result }),
    onError: (err: Error) => setError(err.message),
  });

  const siemTest = useMutation({
    mutationFn: testSiem,
    onSuccess: (result) => setNotice(result),
    onError: (err: Error) => setError(err.message),
  });

  const siemExport = useMutation({
    mutationFn: exportSiem,
    onSuccess: (result) => setNotice(result),
    onError: (err: Error) => setError(err.message),
  });

  const retrainMlMutation = useMutation({
    mutationFn: retrainMl,
    onSuccess: (result) => {
      setNotice(result);
      invalidateSystem();
    },
    onError: (err: Error) => setError(err.message),
  });

  const retrainAeMutation = useMutation({
    mutationFn: retrainAutoencoder,
    onSuccess: (result) => {
      setNotice(result);
      invalidateSystem();
    },
    onError: (err: Error) => setError(err.message),
  });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">System status</h1>
        <p className="text-sm text-slate-400">
          Connector plugins, SIEM export and ML model artifacts
        </p>
      </header>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </div>
      )}
      {notice && <ResultNotice result={notice} />}
      {(connectorsQuery.isError || siemQuery.isError || mlQuery.isError) && (
        <InlineError message="One or more system queries failed to load." />
      )}

      <section>
        <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
          Connectors
        </h2>
        {connectorsQuery.isLoading ? (
          <Spinner />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {(connectorsQuery.data ?? []).map((connector) => (
              <ConnectorCard
                key={connector.name}
                connector={connector}
                busy={testConnectorMutation.isPending}
                onTest={() => testConnectorMutation.mutate(connector.name)}
              />
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
          SIEM export
        </h2>
        <SiemCard
          siem={siemQuery.data}
          loading={siemQuery.isLoading}
          testBusy={siemTest.isPending}
          exportBusy={siemExport.isPending}
          onTest={() => siemTest.mutate()}
          onExport={() => siemExport.mutate()}
        />
      </section>

      <section>
        <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
          Machine learning
        </h2>
        <div className="grid gap-3 lg:grid-cols-2">
          <ModelCard
            title="Isolation forest anomaly detector"
            model={mlQuery.data}
            loading={mlQuery.isLoading}
            busy={retrainMlMutation.isPending}
            onRetrain={() => retrainMlMutation.mutate()}
            extra={
              mlQuery.data
                ? [
                    `min samples ${mlQuery.data.min_samples}`,
                    `contamination ${mlQuery.data.contamination}`,
                  ]
                : []
            }
          />
          <ModelCard
            title="Flow autoencoder"
            model={autoencoderQuery.data}
            loading={autoencoderQuery.isLoading}
            busy={retrainAeMutation.isPending}
            onRetrain={() => retrainAeMutation.mutate()}
            extra={autoencoderQuery.data ? [`threshold ${autoencoderQuery.data.threshold}`] : []}
          />
        </div>
      </section>
    </div>
  );
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

function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-0.5 text-sm text-slate-100">{value}</p>
    </div>
  );
}

function SiemCard({
  siem,
  loading,
  testBusy,
  exportBusy,
  onTest,
  onExport,
}: {
  siem: SiemStatus | undefined;
  loading: boolean;
  testBusy: boolean;
  exportBusy: boolean;
  onTest: () => void;
  onExport: () => void;
}) {
  if (loading) return <Spinner />;
  if (!siem) return null;
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Badge ok={siem.enabled} label={siem.enabled ? "enabled" : "disabled"} />
          <Badge ok={siem.configured} label={siem.configured ? "configured" : "not configured"} />
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onTest}
            disabled={testBusy || !siem.configured}
            className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
          >
            {testBusy ? "Sending…" : "Send test event"}
          </button>
          <button
            type="button"
            onClick={onExport}
            disabled={exportBusy || !siem.configured}
            className="rounded-md bg-emerald-500 px-2.5 py-1 text-xs font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
          >
            {exportBusy ? "Exporting…" : "Export pending alerts"}
          </button>
        </div>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <Stat label="Endpoint" value={siem.endpoint ?? "—"} />
        <Stat label="Pending alerts" value={siem.pending_alerts} />
        <Stat label="Batch size" value={siem.batch_size} />
      </div>
      {siem.last_run && (
        <div className="mt-3 rounded-md border border-slate-800 bg-slate-950/50 p-3 text-xs text-slate-400">
          <p>
            Last run: {siem.last_run.status} · {siem.last_run.alerts_exported} alert
            {siem.last_run.alerts_exported === 1 ? "" : "s"} exported ·{" "}
            {siem.last_run.finished_at
              ? new Date(siem.last_run.finished_at).toLocaleString()
              : "in progress"}
          </p>
          {siem.last_run.error && <p className="mt-1 text-red-300">{siem.last_run.error}</p>}
        </div>
      )}
    </div>
  );
}

function ModelCard({
  title,
  model,
  loading,
  busy,
  onRetrain,
  extra,
}: {
  title: string;
  model: MlStatus | AutoencoderStatus | undefined;
  loading: boolean;
  busy: boolean;
  onRetrain: () => void;
  extra: string[];
}) {
  if (loading) return <Spinner label={title} />;
  if (!model) return null;
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex items-center justify-between">
        <p className="font-medium text-slate-100">{title}</p>
        <div className="flex items-center gap-2">
          <Badge ok={model.enabled} label={model.enabled ? "enabled" : "disabled"} />
          <Badge ok={model.exists} label={model.exists ? "artifact present" : "not trained"} />
        </div>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        <Stat label="Size" value={formatBytes(model.size_bytes)} />
        <Stat
          label="Trained at"
          value={model.modified_at ? new Date(model.modified_at).toLocaleString() : "—"}
        />
      </div>
      {extra.length > 0 && <p className="mt-2 text-xs text-slate-500">{extra.join(" · ")}</p>}
      <p className="mt-2 break-all font-mono text-[11px] text-slate-600">{model.path}</p>
      <button
        type="button"
        onClick={onRetrain}
        disabled={busy}
        className="mt-3 rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
      >
        {busy ? "Retraining…" : "Retrain"}
      </button>
    </div>
  );
}
