import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import {
  deleteSensor,
  getFleetSummary,
  listSensors,
  registerSensor,
  rotateSensorToken,
  updateSensor,
} from "../api/endpoints";
import type { Sensor, SensorStatus } from "../api/types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { InlineError, Spinner } from "../components/Spinner";
import { useToast } from "../components/toast";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

const STATUSES: SensorStatus[] = ["online", "offline", "disabled"];

const inputClass =
  "rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 focus:border-emerald-500 focus:outline-hidden";

const STATUS_STYLES: Record<SensorStatus, string> = {
  online: "bg-emerald-500/20 text-emerald-300 ring-emerald-500/40",
  offline: "bg-amber-500/20 text-amber-300 ring-amber-500/40",
  disabled: "bg-slate-500/20 text-slate-300 ring-slate-500/40",
};

export default function Fleet() {
  useDocumentTitle("Fleet");
  const queryClient = useQueryClient();
  const { success, error: toastError } = useToast();
  const [status, setStatus] = useState<SensorStatus | "">("");
  const [showRegister, setShowRegister] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [hostname, setHostname] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [registeredToken, setRegisteredToken] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = useState<Sensor | null>(null);

  const sensorsQuery = useQuery({
    queryKey: ["sensors", "list", { status }],
    queryFn: () => listSensors({ status: status || undefined, page_size: 100 }),
  });

  const summaryQuery = useQuery({
    queryKey: ["sensors", "fleet"],
    queryFn: getFleetSummary,
  });

  function invalidateSensors() {
    void queryClient.invalidateQueries({ queryKey: ["sensors"] });
  }

  const register = useMutation({
    mutationFn: (input: { name: string; hostname?: string; ip_address?: string }) =>
      registerSensor(input),
    onSuccess: (result) => {
      setRegisteredToken(result.token);
      setShowRegister(false);
      setFormError(null);
      setName("");
      setHostname("");
      setIpAddress("");
      invalidateSensors();
    },
    onError: (err: Error) => setFormError(err.message),
  });

  const toggleEnabled = useMutation({
    mutationFn: (sensor: Sensor) => updateSensor(sensor.id, { enabled: !sensor.enabled }),
    onSuccess: (_result, sensor) => {
      invalidateSensors();
      success(`Sensor "${sensor.name}" ${sensor.enabled ? "disabled" : "enabled"}.`);
    },
    onError: (err: Error) => toastError(err.message),
  });

  const rotate = useMutation({
    mutationFn: (id: number) => rotateSensorToken(id),
    onSuccess: (result) => {
      setActionNotice(`New token for sensor: ${result.token}`);
      success("Sensor token rotated.");
    },
    onError: (err: Error) => setActionNotice(err.message),
  });

  const remove = useMutation({
    mutationFn: (id: number) => deleteSensor(id),
    onSuccess: () => {
      invalidateSensors();
      success("Sensor deleted.");
    },
    onError: (err: Error) => toastError(err.message),
  });

  function handleRegister(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    setRegisteredToken(null);
    register.mutate({
      name,
      hostname: hostname || undefined,
      ip_address: ipAddress || undefined,
    });
  }

  function handleRemove() {
    if (!removeTarget) {
      return;
    }
    remove.mutate(removeTarget.id);
    setRemoveTarget(null);
  }

  const summary = summaryQuery.data;
  const sensors = sensorsQuery.data?.items ?? [];

  return (
    <div className="space-y-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Fleet</h1>
          <p className="text-sm text-slate-400">
            {summary?.total ?? 0} registered sensor{summary?.total === 1 ? "" : "s"}
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setShowRegister((value) => !value);
            setRegisteredToken(null);
            setFormError(null);
          }}
          className="rounded-md bg-emerald-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400"
        >
          {showRegister ? "Cancel" : "+ Register sensor"}
        </button>
      </header>

      {actionNotice && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300">
          <p className="mb-1 font-medium">Token</p>
          <code className="break-all font-mono text-xs">{actionNotice}</code>
        </div>
      )}

      {showRegister && (
        <form
          onSubmit={handleRegister}
          className="space-y-3 rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <div className="grid gap-3 sm:grid-cols-3">
            <div>
              <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
                Name
              </label>
              <input
                className={`${inputClass} w-full`}
                value={name}
                onChange={(event) => setName(event.target.value)}
                required
                minLength={1}
                maxLength={128}
                placeholder="edge-01"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
                Hostname (optional)
              </label>
              <input
                className={`${inputClass} w-full`}
                value={hostname}
                onChange={(event) => setHostname(event.target.value)}
                placeholder="edge-01"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
                IP address (optional)
              </label>
              <input
                className={`${inputClass} w-full`}
                value={ipAddress}
                onChange={(event) => setIpAddress(event.target.value)}
                placeholder="10.0.0.10"
              />
            </div>
          </div>
          <InlineError message={formError ?? ""} />
          <button
            type="submit"
            disabled={register.isPending}
            className="rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
          >
            Register sensor
          </button>
        </form>
      )}

      {registeredToken && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4">
          <p className="mb-1 text-sm font-medium text-emerald-300">
            Sensor registered — copy this token now. It is shown only once.
          </p>
          <code className="block break-all font-mono text-xs text-emerald-100">
            {registeredToken}
          </code>
        </div>
      )}

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <SummaryCard label="Total" value={summary?.total ?? "—"} />
        <SummaryCard label="Online" value={summary?.online ?? "—"} accent="text-emerald-400" />
        <SummaryCard label="Offline" value={summary?.offline ?? "—"} accent="text-amber-400" />
        <SummaryCard label="Disabled" value={summary?.disabled ?? "—"} accent="text-slate-400" />
        <SummaryCard
          label="Alerts (24h)"
          value={summary?.alerts_last_24h ?? "—"}
          accent="text-red-400"
        />
      </section>

      {sensorsQuery.isError && (
        <InlineError message={sensorsQuery.error?.message ?? "Failed to load sensors"} />
      )}

      <section className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-left text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Version</th>
              <th className="px-4 py-3">Host</th>
              <th className="px-4 py-3">Last seen</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
            <tr className="border-b border-slate-800">
              <th colSpan={7} className="px-4 py-2">
                <div className="flex items-center gap-2">
                  <select
                    className={inputClass}
                    value={status}
                    onChange={(event) => setStatus(event.target.value as SensorStatus | "")}
                  >
                    <option value="">Any status</option>
                    {STATUSES.map((item) => (
                      <option key={item} value={item}>
                        {item}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    onClick={() => void sensorsQuery.refetch()}
                    className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    Refresh
                  </button>
                </div>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {sensorsQuery.isLoading && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center">
                  <Spinner />
                </td>
              </tr>
            )}
            {!sensorsQuery.isLoading && sensors.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                  No sensors registered yet.
                </td>
              </tr>
            )}
            {sensors.map((sensor) => (
              <SensorRow
                key={sensor.id}
                sensor={sensor}
                onToggle={() => toggleEnabled.mutate(sensor)}
                onRotate={() => rotate.mutate(sensor.id)}
                onRemove={() => setRemoveTarget(sensor)}
              />
            ))}
          </tbody>
        </table>
      </section>

      <ConfirmDialog
        open={removeTarget !== null}
        title="Delete sensor"
        message={
          removeTarget
            ? `Delete sensor "${removeTarget.name}"? This invalidates its token and removes it from the fleet.`
            : ""
        }
        confirmLabel="Delete sensor"
        onConfirm={handleRemove}
        onCancel={() => setRemoveTarget(null)}
      />
    </div>
  );
}

function SummaryCard({
  label,
  value,
  accent = "text-slate-100",
}: {
  label: string;
  value: string | number;
  accent?: string;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-1 text-2xl font-semibold ${accent}`}>{value}</p>
    </div>
  );
}

function SensorRow({
  sensor,
  onToggle,
  onRotate,
  onRemove,
}: {
  sensor: Sensor;
  onToggle: () => void;
  onRotate: () => void;
  onRemove: () => void;
}) {
  return (
    <tr className="hover:bg-slate-800/50">
      <td className="px-4 py-3 text-slate-500">#{sensor.id}</td>
      <td className="px-4 py-3">
        <p className="font-medium text-slate-100">{sensor.name}</p>
        <p className="text-xs text-slate-500">{sensor.ip_address ?? "—"}</p>
      </td>
      <td className="px-4 py-3">
        <span
          className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ${STATUS_STYLES[sensor.status]}`}
        >
          {sensor.status}
        </span>
      </td>
      <td className="px-4 py-3 text-slate-400">{sensor.version ?? "—"}</td>
      <td className="px-4 py-3 text-slate-400">{sensor.hostname ?? "—"}</td>
      <td className="px-4 py-3 text-xs text-slate-500">
        {sensor.last_seen_at ? new Date(sensor.last_seen_at).toLocaleString() : "never"}
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onToggle}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
          >
            {sensor.enabled ? "Disable" : "Enable"}
          </button>
          <button
            type="button"
            onClick={onRotate}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
          >
            Rotate token
          </button>
          <button
            type="button"
            onClick={onRemove}
            className="rounded-md border border-red-500/40 px-2 py-1 text-xs text-red-300 hover:bg-red-500/10"
          >
            Delete
          </button>
        </div>
      </td>
    </tr>
  );
}
