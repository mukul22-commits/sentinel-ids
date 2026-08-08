import { Link } from "react-router-dom";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export default function NotFound() {
  useDocumentTitle("Page not found");

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
      <p className="text-6xl font-bold text-slate-700">404</p>
      <h1 className="mt-4 text-xl font-semibold text-slate-200">Page not found</h1>
      <p className="mt-2 max-w-sm text-sm text-slate-400">
        The page you requested does not exist or has been moved.
      </p>
      <Link
        to="/"
        className="mt-6 rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500"
      >
        Back to dashboard
      </Link>
    </div>
  );
}
