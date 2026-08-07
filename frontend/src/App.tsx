import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth/AuthContext";
import { Layout } from "./components/Layout";
import { Spinner } from "./components/Spinner";
import Dashboard from "./pages/Dashboard";
import DetectionHealth from "./pages/DetectionHealth";
import Fleet from "./pages/Fleet";
import IncidentDetail from "./pages/IncidentDetail";
import Incidents from "./pages/Incidents";
import Login from "./pages/Login";
import OidcCallback from "./pages/OidcCallback";
import Policies from "./pages/Policies";
import SystemStatus from "./pages/SystemStatus";

function Protected({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <Spinner label="Restoring session…" />
      </div>
    );
  }
  if (status === "anonymous") {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/auth/oidc/callback" element={<OidcCallback />} />
      <Route
        element={
          <Protected>
            <Layout />
          </Protected>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/fleet" element={<Fleet />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/system" element={<SystemStatus />} />
        <Route path="/detection" element={<DetectionHealth />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
