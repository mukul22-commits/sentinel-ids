import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { useRealtime } from "../realtime/RealtimeContext";
import { NotificationBell } from "./NotificationBell";

interface NavLinkDef {
  to: string;
  label: string;
  end?: boolean;
  roles?: string[];
}

const NAV_LINKS: NavLinkDef[] = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/incidents", label: "Incidents" },
  { to: "/packets", label: "Packets" },
  { to: "/fleet", label: "Fleet", roles: ["admin"] },
  { to: "/policies", label: "Policies", roles: ["admin"] },
  { to: "/system", label: "System", roles: ["admin"] },
  { to: "/detection", label: "Detection" },
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
  const [menuOpen, setMenuOpen] = useState(false);

  const role = user?.role ?? "analyst";
  const visibleLinks = NAV_LINKS.filter((link) => !link.roles || link.roles.includes(role));

  function handleSignOut() {
    setMenuOpen(false);
    void logout().then(() => navigate("/login"));
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center gap-4 px-4 py-3">
          <NavLink to="/" className="flex items-baseline gap-2">
            <span className="text-lg font-bold tracking-tight text-emerald-400">SENTINEL</span>
            <span className="text-xs uppercase tracking-widest text-slate-500">IDS</span>
          </NavLink>
          <nav className="hidden items-center gap-1 md:flex" aria-label="Primary">
            {visibleLinks.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.end}
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
            <div className="hidden items-center gap-2 border-l border-slate-700 pl-3 sm:flex">
              <div className="text-right leading-tight">
                <p className="text-sm font-medium text-slate-200">
                  {user?.full_name || user?.username}
                </p>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">{role}</p>
              </div>
              <button
                type="button"
                onClick={handleSignOut}
                className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-red-500/50 hover:text-red-300"
              >
                Sign out
              </button>
            </div>
            <button
              type="button"
              aria-label={menuOpen ? "Close menu" : "Open menu"}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((open) => !open)}
              className="rounded-md border border-slate-700 px-2.5 py-1.5 text-slate-300 hover:bg-slate-800 md:hidden"
            >
              {menuOpen ? "✕" : "☰"}
            </button>
          </div>
        </div>
        {menuOpen && (
          <nav
            aria-label="Primary mobile"
            className="border-t border-slate-800 bg-slate-900 px-4 py-2 md:hidden"
          >
            {visibleLinks.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.end}
                onClick={() => setMenuOpen(false)}
                className={({ isActive }) =>
                  `block rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-slate-800 text-emerald-300"
                      : "text-slate-300 hover:bg-slate-800 hover:text-slate-100"
                  }`
                }
              >
                {link.label}
              </NavLink>
            ))}
            <div className="mt-2 flex items-center justify-between border-t border-slate-800 px-3 pt-3">
              <span className="text-sm text-slate-200">{user?.full_name || user?.username}</span>
              <button
                type="button"
                onClick={handleSignOut}
                className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-red-500/50 hover:text-red-300"
              >
                Sign out
              </button>
            </div>
          </nav>
        )}
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
