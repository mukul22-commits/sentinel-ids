import type { IncidentSeverity } from "../api/types";

const STYLES: Record<IncidentSeverity, string> = {
  low: "bg-slate-500/20 text-slate-300 ring-slate-500/40",
  medium: "bg-amber-500/20 text-amber-300 ring-amber-500/40",
  high: "bg-orange-500/20 text-orange-300 ring-orange-500/40",
  critical: "bg-red-500/20 text-red-300 ring-red-500/40",
};

export function SeverityBadge({ severity }: { severity: IncidentSeverity }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ${STYLES[severity] ?? STYLES.medium}`}
    >
      {severity}
    </span>
  );
}
