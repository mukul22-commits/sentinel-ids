import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";
import { useParams } from "react-router-dom";
import {
  addTimelineEntry,
  createAction,
  executeAction,
  getIncident,
  listActions,
  setIncidentStatus,
  updateIncident,
} from "../api/endpoints";
import type {
  ActionTargetType,
  ActionType,
  Incident,
  IncidentSeverity,
  IncidentStatus,
  ResponseAction,
} from "../api/types";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { InlineError, Spinner } from "../components/Spinner";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useIncidentEvents } from "../realtime/RealtimeContext";

const SEVERITIES: IncidentSeverity[] = ["low", "medium", "high", "critical"];
const STATUSES: IncidentStatus[] = ["open", "in_progress", "resolved", "closed"];
const ACTION_TYPES: ActionType[] = ["block", "quarantine", "notify"];
const TARGET_TYPES: ActionTargetType[] = ["ip", "port", "host", "email"];

const inputClass =
  "rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 focus:border-emerald-500 focus:outline-hidden";
const buttonClass =
  "rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-40";

export default function IncidentDetail() {
  const { id: rawId } = useParams();
  const incidentId = Number(rawId);
  useDocumentTitle(Number.isInteger(incidentId) ? `Incident #${incidentId}` : "Incident");
  const queryClient = useQueryClient();

  const incidentQuery = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => getIncident(incidentId),
    enabled: Number.isInteger(incidentId) && incidentId > 0,
  });

  const actionsQuery = useQuery({
    queryKey: ["actions", incidentId],
    queryFn: () => listActions(incidentId),
    enabled: Number.isInteger(incidentId) && incidentId > 0,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    void queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
    void queryClient.invalidateQueries({ queryKey: ["actions", incidentId] });
  };

  useIncidentEvents((event) => {
    if (event.type.startsWith("incident.")) invalidate();
  });

  const incident = incidentQuery.data;

  return (
    <div className="space-y-5">
      {incidentQuery.isLoading && <Spinner label="Loading incident…" />}
      {incidentQuery.isError && !incident && (
        <InlineError message="Incident not found or failed to load." />
      )}
      {incident && (
        <>
          <DetailHeader incident={incident} incidentId={incidentId} onSaved={invalidate} />
          <div className="grid gap-5 lg:grid-cols-2">
            <TimelinePanel incident={incident} onSaved={invalidate} />
            <ActionsPanel
              incidentId={incidentId}
              actions={actionsQuery.data ?? []}
              onSaved={invalidate}
            />
          </div>
        </>
      )}
    </div>
  );
}

function DetailHeader({
  incident,
  incidentId,
  onSaved,
}: {
  incident: Incident;
  incidentId: number;
  onSaved: () => void;
}) {
  const [title, setTitle] = useState(incident?.title ?? "");
  const [assignee, setAssignee] = useState(
    incident?.assignee_id != null ? String(incident.assignee_id) : "",
  );
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!incident) return;
    setTitle(incident.title);
    setAssignee(incident.assignee_id != null ? String(incident.assignee_id) : "");
  }, [incident]);

  const setStatus = useMutation({
    mutationFn: (status: IncidentStatus) => setIncidentStatus(incidentId, status),
    onSuccess: onSaved,
    onError: (err: Error) => setError(err.message),
  });

  const changeSeverity = useMutation({
    mutationFn: (severity: IncidentSeverity) => updateIncident(incidentId, { severity }),
    onSuccess: onSaved,
    onError: (err: Error) => setError(err.message),
  });

  const save = useMutation({
    mutationFn: () =>
      updateIncident(incidentId, {
        title: title !== incident?.title ? title : undefined,
        assignee_id:
          assignee === ""
            ? null
            : assignee !== String(incident?.assignee_id)
              ? Number(assignee)
              : undefined,
      }),
    onSuccess: onSaved,
    onError: (err: Error) => setError(err.message),
  });

  if (!incident) return null;

  const saveDirty =
    title !== incident.title ||
    assignee !== (incident.assignee_id != null ? String(incident.assignee_id) : "");

  return (
    <header className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm text-slate-500">#{incident.id}</span>
        <input
          className={`${inputClass} min-w-0 flex-1 text-base font-semibold`}
          value={title}
          onChange={(event) => setTitle(event.target.value)}
        />
        <SeverityBadge severity={incident.severity} />
        <StatusBadge status={incident.status} />
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3 text-sm">
        <label className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wide text-slate-500">Severity</span>
          <select
            className={inputClass}
            value={incident.severity}
            onChange={(event) => changeSeverity.mutate(event.target.value as IncidentSeverity)}
          >
            {SEVERITIES.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
        </label>

        <label className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wide text-slate-500">Status</span>
          <select
            className={inputClass}
            value={incident.status}
            onChange={(event) => setStatus.mutate(event.target.value as IncidentStatus)}
          >
            {STATUSES.map((item) => (
              <option key={item} value={item}>
                {item.replace("_", " ")}
              </option>
            ))}
          </select>
        </label>

        <label className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wide text-slate-500">Assignee id</span>
          <input
            className={`${inputClass} w-24`}
            type="number"
            min={1}
            placeholder="—"
            value={assignee}
            onChange={(event) => setAssignee(event.target.value)}
          />
        </label>

        {saveDirty && (
          <button
            type="button"
            onClick={() => save.mutate()}
            disabled={save.isPending}
            className="rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
          >
            Save
          </button>
        )}

        <span className="ml-auto text-xs text-slate-500">
          Created {new Date(incident.created_at).toLocaleString()} · Updated{" "}
          {new Date(incident.updated_at).toLocaleString()}
        </span>
      </div>
      <div className="mt-3">
        <InlineError message={error ?? ""} />
      </div>
    </header>
  );
}

function TimelinePanel({ incident, onSaved }: { incident: Incident; onSaved: () => void }) {
  const [action, setAction] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const addEntry = useMutation({
    mutationFn: () => addTimelineEntry(incident.id, { action, note: note || undefined }),
    onSuccess: () => {
      setAction("");
      setNote("");
      setError(null);
      onSaved();
    },
    onError: (err: Error) => setError(err.message),
  });

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    addEntry.mutate();
  }

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900">
      <h2 className="border-b border-slate-800 px-4 py-3 text-sm font-semibold text-slate-200">
        Timeline
      </h2>
      <ol className="max-h-[24rem] divide-y divide-slate-800 overflow-y-auto">
        {incident.timeline.map((entry, index) => (
          <li key={`${entry.ts}-${index}`} className="px-4 py-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-medium text-slate-200">{entry.action}</span>
              <span className="shrink-0 text-xs text-slate-500">
                {entry.actor} · {new Date(entry.ts).toLocaleString()}
              </span>
            </div>
            {entry.note && <p className="mt-1 text-sm text-slate-400">{entry.note}</p>}
            {entry.details && (
              <pre className="mt-1 overflow-x-auto text-[11px] text-slate-500">
                {JSON.stringify(entry.details)}
              </pre>
            )}
          </li>
        ))}
        {incident.timeline.length === 0 && (
          <li className="px-4 py-8 text-center text-sm text-slate-500">No timeline entries.</li>
        )}
      </ol>
      <form onSubmit={handleSubmit} className="space-y-2 border-t border-slate-800 p-4">
        <div className="flex gap-2">
          <input
            className={`${inputClass} min-w-0 flex-1`}
            value={action}
            onChange={(event) => setAction(event.target.value)}
            required
            maxLength={100}
            placeholder="e.g. contacted asset owner"
          />
          <button
            type="submit"
            disabled={addEntry.isPending}
            className="rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
          >
            Add
          </button>
        </div>
        <input
          className={`${inputClass} w-full`}
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="Note (optional)"
        />
        <InlineError message={error ?? ""} />
      </form>
    </section>
  );
}

function ActionsPanel({
  incidentId,
  actions,
  onSaved,
}: {
  incidentId: number;
  actions: ResponseAction[];
  onSaved: () => void;
}) {
  const [actionType, setActionType] = useState<ActionType>("block");
  const [targetType, setTargetType] = useState<ActionTargetType>("ip");
  const [targetValue, setTargetValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      createAction(incidentId, {
        action_type: actionType,
        target_type: targetType,
        target_value: targetValue,
      }),
    onSuccess: () => {
      setTargetValue("");
      setError(null);
      onSaved();
    },
    onError: (err: Error) => setError(err.message),
  });

  const execute = useMutation({
    mutationFn: (actionId: number) => executeAction(incidentId, actionId),
    onSuccess: onSaved,
    onError: (err: Error) => setError(err.message),
  });

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    create.mutate();
  }

  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900">
      <h2 className="border-b border-slate-800 px-4 py-3 text-sm font-semibold text-slate-200">
        Response actions
      </h2>
      <form onSubmit={handleSubmit} className="space-y-2 border-b border-slate-800 p-4">
        <div className="grid grid-cols-3 gap-2">
          <select
            className={inputClass}
            value={actionType}
            onChange={(event) => setActionType(event.target.value as ActionType)}
          >
            {ACTION_TYPES.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
          <select
            className={inputClass}
            value={targetType}
            onChange={(event) => setTargetType(event.target.value as ActionTargetType)}
          >
            {TARGET_TYPES.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
          <input
            className={inputClass}
            value={targetValue}
            onChange={(event) => setTargetValue(event.target.value)}
            required
            maxLength={512}
            placeholder="target value"
          />
        </div>
        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={create.isPending}
            className="rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
          >
            Queue action
          </button>
          <InlineError message={error ?? ""} />
        </div>
      </form>

      <ul className="divide-y divide-slate-800">
        {actions.length === 0 && (
          <li className="px-4 py-6 text-center text-sm text-slate-500">
            No actions queued for this incident.
          </li>
        )}
        {actions.map((action) => (
          <li key={action.id} className="flex items-center gap-3 px-4 py-3">
            <span className="w-24 shrink-0">
              <ActionStatusBadge status={action.status} />
            </span>
            <span className="min-w-0 flex-1 truncate text-sm text-slate-200">
              {action.action_type} on {action.target_type}:{action.target_value}
            </span>
            {(action.status === "pending" || action.status === "failed") && (
              <button
                type="button"
                onClick={() => execute.mutate(action.id)}
                disabled={execute.isPending}
                className={buttonClass}
              >
                Execute
              </button>
            )}
            {action.status === "succeeded" && action.details.length > 0 && (
              <details className="text-xs text-slate-500">
                <summary className="cursor-pointer hover:text-slate-300">steps</summary>
                <pre className="mt-1 overflow-x-auto text-[11px]">
                  {JSON.stringify(action.details, null, 2)}
                </pre>
              </details>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

function ActionStatusBadge({ status }: { status: import("../api/types").ActionStatus }) {
  const styles: Record<string, string> = {
    pending: "bg-slate-500/20 text-slate-300 ring-slate-500/40",
    executing: "bg-blue-500/20 text-blue-300 ring-blue-500/40",
    succeeded: "bg-emerald-500/20 text-emerald-300 ring-emerald-500/40",
    failed: "bg-red-500/20 text-red-300 ring-red-500/40",
  };
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ${styles[status] ?? styles.pending}`}
    >
      {status}
    </span>
  );
}
