import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { listIncidents, unreadCount } from "../api/endpoints";
import type { IncidentSeverity } from "../api/types";
import { useIncidentEvents } from "../realtime/RealtimeContext";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { Spinner } from "../components/Spinner";

const SEVERITY_ORDER: IncidentSeverity[] = ["low", "medium", "high", "critical"];
const SEVERITY_COLORS: Record<IncidentSeverity, string> = {
  low: "#64748b",
  medium: "#f59e0b",
  high: "#f97316",
  critical: "#ef4444",
};

const STATUS_ORDER = ["open", "in_progress", "resolved", "closed"];

const TOOLTIP_STYLE = {
  backgroundColor: "#0f172a",
  border: "1px solid #334155",
  borderRadius: 8,
  color: "#e2e8f0",
};

export default function Dashboard() {
  const queryClient = useQueryClient();

  const incidentsQuery = useQuery({
    queryKey: ["incidents", "all"],
    queryFn: () => listIncidents({ page_size: 200 }),
    refetchInterval: 60_000,
  });

  const unreadQuery = useQuery({
    queryKey: ["unread-count"],
    queryFn: unreadCount,
  });

  useIncidentEvents((event) => {
    if (event.type.startsWith("incident.")) {
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
    }
  });

  const incidents = incidentsQuery.data?.items ?? [];
  const bySeverity = SEVERITY_ORDER.map((severity) => ({
    name: severity,
    value: incidents.filter((incident) => incident.severity === severity).length,
    color: SEVERITY_COLORS[severity],
  }));
  const byStatus = STATUS_ORDER.map((status) => ({
    name: status.replace("_", " "),
    value: incidents.filter((incident) => incident.status === status).length,
  }));

  const openCount = incidents.filter((incident) => incident.status === "open").length;
  const activeCount = incidents.filter(
    (incident) => incident.severity === "high" || incident.severity === "critical",
  ).length;
  const recent = [...incidents]
    .sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at))
    .slice(0, 8);

  if (incidentsQuery.isLoading) {
    return <Spinner label="Loading dashboard…" />;
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Operations dashboard</h1>
        <p className="text-sm text-slate-400">Incident response overview, updated in real time.</p>
      </header>

      <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KpiCard label="Total incidents" value={incidents.length} accent="text-slate-100" />
        <KpiCard label="Open" value={openCount} accent="text-emerald-400" />
        <KpiCard label="High / critical" value={activeCount} accent="text-red-400" />
        <KpiCard label="Unread alerts" value={unreadQuery.data ?? 0} accent="text-amber-400" />
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <ChartCard title="Incidents by severity">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={bySeverity}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
              <YAxis allowDecimals={false} stroke="#64748b" fontSize={12} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="value" name="incidents" radius={[4, 4, 0, 0]}>
                {bySeverity.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Incidents by status">
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie
                data={byStatus}
                dataKey="value"
                nameKey="name"
                innerRadius={55}
                outerRadius={90}
                paddingAngle={2}
              >
                {byStatus.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={
                      entry.name === "open"
                        ? "#10b981"
                        : entry.name === "in progress"
                          ? "#3b82f6"
                          : entry.name === "resolved"
                            ? "#14b8a6"
                            : "#475569"
                    }
                  />
                ))}
              </Pie>
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>
      </section>

      <section className="rounded-lg border border-slate-800 bg-slate-900">
        <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
          <h2 className="text-sm font-semibold text-slate-200">Recent incidents</h2>
          <Link to="/incidents" className="text-sm text-emerald-400 hover:text-emerald-300">
            View all →
          </Link>
        </div>
        {recent.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-slate-500">
            No incidents yet. Create one from the Incidents page.
          </p>
        ) : (
          <ul className="divide-y divide-slate-800">
            {recent.map((incident) => (
              <li key={incident.id}>
                <Link
                  to={`/incidents/${incident.id}`}
                  className="flex items-center gap-3 px-4 py-3 hover:bg-slate-800/60"
                >
                  <span className="w-24 shrink-0">
                    <SeverityBadge severity={incident.severity} />
                  </span>
                  <span className="min-w-0 flex-1 truncate text-sm text-slate-200">
                    {incident.title}
                  </span>
                  <StatusBadge status={incident.status} />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function KpiCard({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 px-4 py-3">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-1 text-3xl font-semibold ${accent}`}>{value}</p>
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="mb-3 text-sm font-semibold text-slate-200">{title}</h2>
      {children}
    </div>
  );
}
