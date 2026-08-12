import { Suspense, lazy, type ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth/AuthContext";
import { Layout } from "./components/Layout";
import { Spinner } from "./components/Spinner";
import NotFound from "./pages/NotFound";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const DetectionHealth = lazy(() => import("./pages/DetectionHealth"));
const Fleet = lazy(() => import("./pages/Fleet"));
const IncidentDetail = lazy(() => import("./pages/IncidentDetail"));
const Incidents = lazy(() => import("./pages/Incidents"));
const Login = lazy(() => import("./pages/Login"));
const OidcCallback = lazy(() => import("./pages/OidcCallback"));
const Packets = lazy(() => import("./pages/Packets"));
const Policies = lazy(() => import("./pages/Policies"));
const SystemStatus = lazy(() => import("./pages/SystemStatus"));

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

function PageFallback() {
  return (
    <div className="flex min-h-[50vh] items-center justify-center">
      <Spinner label="Loading…" />
    </div>
  );
}

export default function App() {
  return (
    <Suspense fallback={<PageFallback />}>
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
          <Route path="/packets" element={<Packets />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/system" element={<SystemStatus />} />
          <Route path="/detection" element={<DetectionHealth />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  );
}
