import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { createPolicy, deletePolicy, listPolicies, updatePolicy } from "../api/endpoints";
import type { ActionTargetType, ActionType, PolicyConditions, ResponsePolicy } from "../api/types";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { InlineError, Spinner } from "../components/Spinner";
import { useToast } from "../components/toast";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

const ACTION_TYPES: ActionType[] = ["block", "quarantine", "notify"];
const TARGET_TYPES: ActionTargetType[] = ["ip", "port", "host", "email"];
const SEVERITIES = ["low", "medium", "high", "critical"];

const inputClass =
  "rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 focus:border-emerald-500 focus:outline-hidden";

interface PolicyDraft {
  name: string;
  enabled: boolean;
  cooldown_seconds: string;
  min_risk_score: string;
  severities: string[];
  detectors: string;
  categories: string;
  actions: Array<{ action_type: ActionType; target_type: ActionTargetType; target_value: string }>;
}

function emptyDraft(): PolicyDraft {
  return {
    name: "",
    enabled: true,
    cooldown_seconds: "3600",
    min_risk_score: "0",
    severities: [],
    detectors: "",
    categories: "",
    actions: [{ action_type: "block", target_type: "ip", target_value: "" }],
  };
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function Policies() {
  useDocumentTitle("Response policies");
  const queryClient = useQueryClient();
  const { success, error: toastError } = useToast();
  const [filter, setFilter] = useState<"" | "true" | "false">("");
  const [editing, setEditing] = useState<ResponsePolicy | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [draft, setDraft] = useState<PolicyDraft>(emptyDraft);
  const [formError, setFormError] = useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = useState<ResponsePolicy | null>(null);

  const policiesQuery = useQuery({
    queryKey: ["policies", "list", { enabled: filter || undefined }],
    queryFn: () =>
      listPolicies({
        enabled: filter === "" ? undefined : filter === "true",
        page_size: 200,
      }),
  });

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ["policies"] });
  }

  function resetForm() {
    setDraft(emptyDraft());
    setEditing(null);
    setFormError(null);
    setShowForm(false);
  }

  const save = useMutation({
    mutationFn: () => {
      const conditions: PolicyConditions = {
        severity: draft.severities,
        detectors: splitList(draft.detectors),
        categories: splitList(draft.categories),
        min_risk_score: Number(draft.min_risk_score) || 0,
      };
      const actions = draft.actions.map((action) => ({
        action_type: action.action_type,
        target_type: action.target_type,
        target_value: action.target_value,
      }));
      if (editing) {
        return updatePolicy(editing.id, {
          name: draft.name,
          enabled: draft.enabled,
          cooldown_seconds: Number(draft.cooldown_seconds) || 0,
          conditions,
          actions,
        });
      }
      return createPolicy({
        name: draft.name,
        enabled: draft.enabled,
        cooldown_seconds: Number(draft.cooldown_seconds) || 0,
        conditions,
        actions,
      });
    },
    onSuccess: () => {
      invalidate();
      resetForm();
      success(editing ? "Policy updated." : "Policy created.");
    },
    onError: (err: Error) => setFormError(err.message),
  });

  const toggleEnabled = useMutation({
    mutationFn: (policy: ResponsePolicy) => updatePolicy(policy.id, { enabled: !policy.enabled }),
    onSuccess: (_result, policy) => {
      invalidate();
      success(`Policy "${policy.name}" ${policy.enabled ? "disabled" : "enabled"}.`);
    },
    onError: (err: Error) => toastError(err.message),
  });

  const remove = useMutation({
    mutationFn: (id: number) => deletePolicy(id),
    onSuccess: () => {
      invalidate();
      success("Policy deleted.");
    },
    onError: (err: Error) => toastError(err.message),
  });

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    save.mutate();
  }

  function beginEdit(policy: ResponsePolicy) {
    setEditing(policy);
    setDraft({
      name: policy.name,
      enabled: policy.enabled,
      cooldown_seconds: String(policy.cooldown_seconds),
      min_risk_score: String(policy.conditions.min_risk_score),
      severities: policy.conditions.severity,
      detectors: policy.conditions.detectors.join(", "),
      categories: policy.conditions.categories.join(", "),
      actions: policy.actions.map((action) => ({
        action_type: action.action_type,
        target_type: action.target_type,
        target_value: action.target_value,
      })),
    });
    setFormError(null);
    setShowForm(true);
  }

  function handleRemove() {
    if (!removeTarget) {
      return;
    }
    remove.mutate(removeTarget.id);
    setRemoveTarget(null);
  }

  const policies = policiesQuery.data?.items ?? [];

  return (
    <div className="space-y-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Response policies</h1>
          <p className="text-sm text-slate-400">
            {policiesQuery.data?.total ?? 0} polic
            {policiesQuery.data?.total === 1 ? "y" : "ies"} — automated actions triggered by
            matching alerts
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setShowForm((value) => !value);
            if (!showForm) resetForm();
          }}
          className="rounded-md bg-emerald-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400"
        >
          {showForm ? "Cancel" : editing ? "Edit policy" : "+ New policy"}
        </button>
      </header>

      {showForm && (
        <PolicyForm
          draft={draft}
          editing={editing}
          error={formError}
          busy={save.isPending}
          onChange={setDraft}
          onSubmit={handleSubmit}
        />
      )}

      <section className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-left text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Conditions</th>
              <th className="px-4 py-3">Actions</th>
              <th className="px-4 py-3">Cooldown</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
            <tr className="border-b border-slate-800">
              <th colSpan={6} className="px-4 py-2">
                <div className="flex items-center gap-2">
                  <select
                    className={inputClass}
                    value={filter}
                    onChange={(event) => setFilter(event.target.value as "" | "true" | "false")}
                  >
                    <option value="">Any status</option>
                    <option value="true">Enabled</option>
                    <option value="false">Disabled</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => void policiesQuery.refetch()}
                    className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    Refresh
                  </button>
                </div>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {policiesQuery.isLoading && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center">
                  <Spinner />
                </td>
              </tr>
            )}
            {!policiesQuery.isLoading && policies.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  No response policies yet.
                </td>
              </tr>
            )}
            {policies.map((policy) => (
              <PolicyRow
                key={policy.id}
                policy={policy}
                onToggle={() => toggleEnabled.mutate(policy)}
                onEdit={() => beginEdit(policy)}
                onRemove={() => setRemoveTarget(policy)}
              />
            ))}
          </tbody>
        </table>
      </section>

      <ConfirmDialog
        open={removeTarget !== null}
        title="Delete policy"
        message={
          removeTarget
            ? `Delete policy "${removeTarget.name}"? This stops all automated actions it defines.`
            : ""
        }
        confirmLabel="Delete policy"
        onConfirm={handleRemove}
        onCancel={() => setRemoveTarget(null)}
      />
    </div>
  );
}

function PolicyForm({
  draft,
  editing,
  error,
  busy,
  onChange,
  onSubmit,
}: {
  draft: PolicyDraft;
  editing: ResponsePolicy | null;
  error: string | null;
  busy: boolean;
  onChange: (draft: PolicyDraft) => void;
  onSubmit: (event: FormEvent) => void;
}) {
  function set<K extends keyof PolicyDraft>(key: K, value: PolicyDraft[K]) {
    onChange({ ...draft, [key]: value });
  }

  function setAction(index: number, patch: Partial<PolicyDraft["actions"][number]>) {
    const actions = draft.actions.map((action, i) =>
      i === index ? { ...action, ...patch } : action,
    );
    set("actions", actions);
  }

  function toggleSeverity(severity: string) {
    set(
      "severities",
      draft.severities.includes(severity)
        ? draft.severities.filter((item) => item !== severity)
        : [...draft.severities, severity],
    );
  }

  return (
    <form
      onSubmit={onSubmit}
      className="space-y-4 rounded-lg border border-slate-800 bg-slate-900 p-4"
    >
      <div className="grid gap-3 sm:grid-cols-4">
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
            Name
          </label>
          <input
            className={`${inputClass} w-full`}
            value={draft.name}
            onChange={(event) => set("name", event.target.value)}
            required
            minLength={1}
            maxLength={200}
            placeholder="Block scanner source"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
            Cooldown (seconds)
          </label>
          <input
            type="number"
            min={0}
            className={`${inputClass} w-full`}
            value={draft.cooldown_seconds}
            onChange={(event) => set("cooldown_seconds", event.target.value)}
            required
          />
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(event) => set("enabled", event.target.checked)}
              className="accent-emerald-500"
            />
            Enabled
          </label>
        </div>
      </div>

      <div>
        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">
          Conditions
        </p>
        <div className="grid gap-3 sm:grid-cols-3">
          <div>
            <label className="mb-1 block text-xs text-slate-500">Severities</label>
            <div className="flex flex-wrap gap-2">
              {SEVERITIES.map((severity) => (
                <button
                  key={severity}
                  type="button"
                  onClick={() => toggleSeverity(severity)}
                  className={`rounded-full px-2.5 py-0.5 text-xs ring-1 ${
                    draft.severities.includes(severity)
                      ? "bg-emerald-500/20 text-emerald-300 ring-emerald-500/40"
                      : "bg-slate-800 text-slate-400 ring-slate-700"
                  }`}
                >
                  {severity}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-500">Detectors (comma-separated)</label>
            <input
              className={`${inputClass} w-full`}
              value={draft.detectors}
              onChange={(event) => set("detectors", event.target.value)}
              placeholder="signature, yara, ml"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-500">
              Categories (comma-separated)
            </label>
            <input
              className={`${inputClass} w-full`}
              value={draft.categories}
              onChange={(event) => set("categories", event.target.value)}
              placeholder="scan, malware, exfil"
            />
          </div>
        </div>
        <div className="mt-3">
          <label className="mb-1 block text-xs text-slate-500">
            Minimum risk score: {draft.min_risk_score || "0"}
          </label>
          <input
            type="range"
            min={0}
            max={100}
            className="w-full accent-emerald-500"
            value={draft.min_risk_score}
            onChange={(event) => set("min_risk_score", event.target.value)}
          />
        </div>
      </div>

      <div>
        <div className="mb-2 flex items-center justify-between">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-400">Actions</p>
          <button
            type="button"
            onClick={() =>
              set("actions", [
                ...draft.actions,
                { action_type: "block", target_type: "ip", target_value: "" },
              ])
            }
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
          >
            + Add action
          </button>
        </div>
        <div className="space-y-2">
          {draft.actions.map((action, index) => (
            <div key={index} className="grid gap-2 sm:grid-cols-[1fr_1fr_2fr_auto]">
              <select
                className={inputClass}
                value={action.action_type}
                onChange={(event) =>
                  setAction(index, { action_type: event.target.value as ActionType })
                }
              >
                {ACTION_TYPES.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
              <select
                className={inputClass}
                value={action.target_type}
                onChange={(event) =>
                  setAction(index, { target_type: event.target.value as ActionTargetType })
                }
              >
                {TARGET_TYPES.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
              <input
                className={inputClass}
                value={action.target_value}
                onChange={(event) => setAction(index, { target_value: event.target.value })}
                required
                placeholder="1.2.3.4, host, alert@example.com…"
              />
              <button
                type="button"
                onClick={() =>
                  set(
                    "actions",
                    draft.actions.filter((_, i) => i !== index),
                  )
                }
                disabled={draft.actions.length === 1}
                className="rounded-md border border-red-500/40 px-2 py-1 text-xs text-red-300 hover:bg-red-500/10 disabled:opacity-40"
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      </div>

      <InlineError message={error ?? ""} />

      <button
        type="submit"
        disabled={busy}
        className="rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
      >
        {busy ? "Saving…" : editing ? "Save changes" : "Create policy"}
      </button>
    </form>
  );
}

function PolicyRow({
  policy,
  onToggle,
  onEdit,
  onRemove,
}: {
  policy: ResponsePolicy;
  onToggle: () => void;
  onEdit: () => void;
  onRemove: () => void;
}) {
  return (
    <tr className="hover:bg-slate-800/50">
      <td className="px-4 py-3">
        <p className="font-medium text-slate-100">{policy.name}</p>
        <p className="text-xs text-slate-500">
          min risk {policy.conditions.min_risk_score}, cooldown {policy.cooldown_seconds}s
        </p>
      </td>
      <td className="px-4 py-3 text-xs text-slate-400">
        {policy.conditions.severity.length > 0 && (
          <p>severity: {policy.conditions.severity.join(", ")}</p>
        )}
        {policy.conditions.detectors.length > 0 && (
          <p>detectors: {policy.conditions.detectors.join(", ")}</p>
        )}
        {policy.conditions.categories.length > 0 && (
          <p>categories: {policy.conditions.categories.join(", ")}</p>
        )}
        {policy.conditions.severity.length === 0 &&
          policy.conditions.detectors.length === 0 &&
          policy.conditions.categories.length === 0 && <span className="text-slate-600">any</span>}
      </td>
      <td className="px-4 py-3 text-xs text-slate-400">
        {policy.actions.map((action, index) => (
          <p key={index} className="whitespace-nowrap">
            {action.action_type} {action.target_type} = {action.target_value}
          </p>
        ))}
      </td>
      <td className="px-4 py-3 text-slate-400">{policy.cooldown_seconds}s</td>
      <td className="px-4 py-3">
        <span
          className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ${
            policy.enabled
              ? "bg-emerald-500/20 text-emerald-300 ring-emerald-500/40"
              : "bg-slate-500/20 text-slate-300 ring-slate-500/40"
          }`}
        >
          {policy.enabled ? "enabled" : "disabled"}
        </span>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onToggle}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
          >
            {policy.enabled ? "Disable" : "Enable"}
          </button>
          <button
            type="button"
            onClick={onEdit}
            className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
          >
            Edit
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
