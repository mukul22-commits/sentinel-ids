import type { IncidentStatus } from "../api/types";

const STYLES: Record<IncidentStatus, string> = {
  open: "bg-emerald-500/20 text-emerald-300 ring-emerald-500/40",
  in_progress: "bg-blue-500/20 text-blue-300 ring-blue-500/40",
  resolved: "bg-teal-500/20 text-teal-300 ring-teal-500/40",
  closed: "bg-slate-500/20 text-slate-300 ring-slate-500/40",
};

export function StatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ${STYLES[status] ?? STYLES.open}`}
    >
      {status.replace("_", " ")}
    </span>
  );
}
