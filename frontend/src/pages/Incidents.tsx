import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { createIncident, listIncidents } from "../api/endpoints";
import type { IncidentSeverity, IncidentStatus, Incident } from "../api/types";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { InlineError, Spinner } from "../components/Spinner";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useIncidentEvents } from "../realtime/RealtimeContext";

const SEVERITIES: IncidentSeverity[] = ["low", "medium", "high", "critical"];
const STATUSES: IncidentStatus[] = ["open", "in_progress", "resolved", "closed"];

const inputClass =
  "rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 focus:border-emerald-500 focus:outline-hidden";

export default function Incidents() {
  useDocumentTitle("Incidents");
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<IncidentStatus | "">("");
  const [severity, setSeverity] = useState<IncidentSeverity | "">("");
  const [page, setPage] = useState(1);
  const [showCreate, setShowCreate] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [newSeverity, setNewSeverity] = useState<IncidentSeverity>("medium");
  const [note, setNote] = useState("");

  const query = useQuery({
    queryKey: ["incidents", "list", { status, severity, page }],
    queryFn: () =>
      listIncidents({
        status: status || undefined,
        severity: severity || undefined,
        page,
        page_size: 25,
      }),
  });

  useIncidentEvents((event) => {
    if (event.type.startsWith("incident.")) {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    }
  });

  const create = useMutation({
    mutationFn: (input: { title: string; severity: IncidentSeverity; note?: string }) =>
      createIncident(input),
    onSuccess: () => {
      setShowCreate(false);
      setTitle("");
      setNote("");
      setCreateError(null);
      setStatus("");
      setPage(1);
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
    onError: (err: Error) => setCreateError(err.message),
  });

  function handleCreate(event: FormEvent) {
    event.preventDefault();
    setCreateError(null);
    create.mutate({ title, severity: newSeverity, note: note || undefined });
  }

  const data = query.data;
  const incidents = data?.items ?? [];
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / 25));

  return (
    <div className="space-y-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Incidents</h1>
          <p className="text-sm text-slate-400">{data?.total ?? 0} total</p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreate((value) => !value)}
          className="rounded-md bg-emerald-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400"
        >
          {showCreate ? "Cancel" : "+ New incident"}
        </button>
      </header>

      {showCreate && (
        <form
          onSubmit={handleCreate}
          className="space-y-3 rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="sm:col-span-2">
              <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
                Title
              </label>
              <input
                className={`${inputClass} w-full`}
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                required
                minLength={3}
                placeholder="Describe the suspected intrusion"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
                Severity
              </label>
              <select
                className={`${inputClass} w-full`}
                value={newSeverity}
                onChange={(event) => setNewSeverity(event.target.value as IncidentSeverity)}
              >
                {SEVERITIES.map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
              Note (optional)
            </label>
            <textarea
              className={`${inputClass} w-full`}
              value={note}
              onChange={(event) => setNote(event.target.value)}
              rows={2}
              placeholder="Initial context for the timeline"
            />
          </div>
          <InlineError message={createError ?? ""} />
          <button
            type="submit"
            disabled={create.isPending}
            className="rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
          >
            Create incident
          </button>
        </form>
      )}

      {query.isError && (
        <InlineError message={query.error?.message ?? "Failed to load incidents"} />
      )}

      <section className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-left text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Assignee</th>
              <th className="px-4 py-3 text-right">Updated</th>
            </tr>
            <tr className="border-b border-slate-800">
              <th colSpan={6} className="px-4 py-2">
                <div className="flex gap-2">
                  <select
                    className={inputClass}
                    value={status}
                    onChange={(event) => {
                      setStatus(event.target.value as IncidentStatus | "");
                      setPage(1);
                    }}
                  >
                    <option value="">Any status</option>
                    {STATUSES.map((item) => (
                      <option key={item} value={item}>
                        {item.replace("_", " ")}
                      </option>
                    ))}
                  </select>
                  <select
                    className={inputClass}
                    value={severity}
                    onChange={(event) => {
                      setSeverity(event.target.value as IncidentSeverity | "");
                      setPage(1);
                    }}
                  >
                    <option value="">Any severity</option>
                    {SEVERITIES.map((item) => (
                      <option key={item} value={item}>
                        {item}
                      </option>
                    ))}
                  </select>
                </div>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {query.isLoading && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center">
                  <Spinner />
                </td>
              </tr>
            )}
            {!query.isLoading && incidents.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  No incidents match the current filters.
                </td>
              </tr>
            )}
            {incidents.map((incident) => (
              <IncidentRow key={incident.id} incident={incident} />
            ))}
          </tbody>
        </table>
      </section>

      <div className="flex items-center justify-between text-sm text-slate-400">
        <button
          type="button"
          onClick={() => setPage((value) => Math.max(1, value - 1))}
          disabled={page <= 1}
          className="rounded-md border border-slate-700 px-3 py-1.5 hover:bg-slate-800 disabled:opacity-40"
        >
          Previous
        </button>
        <span>
          Page {page} of {totalPages}
        </span>
        <button
          type="button"
          onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
          disabled={page >= totalPages}
          className="rounded-md border border-slate-700 px-3 py-1.5 hover:bg-slate-800 disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

function IncidentRow({ incident }: { incident: Incident }) {
  return (
    <tr className="hover:bg-slate-800/50">
      <td className="px-4 py-3 text-slate-500">#{incident.id}</td>
      <td className="px-4 py-3">
        <Link to={`/incidents/${incident.id}`} className="text-slate-100 hover:text-emerald-300">
          {incident.title}
        </Link>
      </td>
      <td className="px-4 py-3">
        <SeverityBadge severity={incident.severity} />
      </td>
      <td className="px-4 py-3">
        <StatusBadge status={incident.status} />
      </td>
      <td className="px-4 py-3 text-slate-400">
        {incident.assignee_id ? `#${incident.assignee_id}` : "—"}
      </td>
      <td className="px-4 py-3 text-right text-xs text-slate-500">
        {new Date(incident.updated_at).toLocaleString()}
      </td>
    </tr>
  );
}
