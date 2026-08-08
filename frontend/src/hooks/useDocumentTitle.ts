import { useEffect } from "react";

export function useDocumentTitle(title: string): void {
  useEffect(() => {
    const previous = document.title;
    document.title = title ? `${title} · Sentinel IDS` : "Sentinel IDS";
    return () => {
      document.title = previous;
    };
  }, [title]);
}
