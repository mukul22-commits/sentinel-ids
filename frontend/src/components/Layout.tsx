import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { useRealtime } from "../realtime/RealtimeContext";
import { NotificationBell } from "./NotificationBell";

const NAV_LINKS = [
  { to: "/", label: "Dashboard" },
  { to: "/incidents", label: "Incidents" },
];

function navClass(isActive: boolean): string {
  return `rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
    isActive
      ? "bg-slate-800 text-emerald-300"
      : "text-slate-300 hover:bg-slate-800 hover:text-slate-100"
  }`;
}

export function Layout() {
  const { user, logout } = useAuth();
  const { connected } = useRealtime();
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/60">
        <div className="mx-auto flex max-w-6xl items-center gap-4 px-4 py-3">
          <NavLink to="/" className="flex items-baseline gap-2">
            <span className="text-lg font-bold tracking-tight text-emerald-400">SENTINEL</span>
            <span className="text-xs uppercase tracking-widest text-slate-500">IDS</span>
          </NavLink>
          <nav className="flex items-center gap-1">
            {NAV_LINKS.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.to === "/"}
                className={({ isActive }) => navClass(isActive)}
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3">
            <span
              className={`flex items-center gap-1.5 text-xs ${
                connected ? "text-emerald-400" : "text-slate-500"
              }`}
              title={connected ? "Realtime connected" : "Realtime disconnected"}
            >
              <span
                className={`h-2 w-2 rounded-full ${connected ? "bg-emerald-400" : "bg-slate-600"}`}
              />
              {connected ? "Live" : "Offline"}
            </span>
            <NotificationBell />
            <div className="flex items-center gap-2 border-l border-slate-700 pl-3">
              <div className="text-right leading-tight">
                <p className="text-sm font-medium text-slate-200">
                  {user?.full_name || user?.username}
                </p>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">{user?.role}</p>
              </div>
              <button
                type="button"
                onClick={() => void logout().then(() => navigate("/login"))}
                className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-red-500/50 hover:text-red-300"
              >
                Sign out
              </button>
            </div>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
