import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { getAccessToken } from "../api/client";
import type { RealtimeEvent } from "../api/types";
import { useAuth } from "../auth/AuthContext";

interface RealtimeContextValue {
  connected: boolean;
  subscribe: (callback: (event: RealtimeEvent) => void) => () => void;
}

const RealtimeContext = createContext<RealtimeContextValue | null>(null);

type Listener = (event: RealtimeEvent) => void;

function socketUrl(token: string): string {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}/ws/incidents?token=${encodeURIComponent(token)}`;
}

export function RealtimeProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const listenersRef = useRef<Set<Listener>>(new Set());
  const { status } = useAuth();

  useEffect(() => {
    if (status !== "authenticated") return;
    const token = getAccessToken();
    if (!token) return;
    let closed = false;
    let retries = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let socket: WebSocket | null = null;

    const connect = () => {
      socket = new WebSocket(socketUrl(token));
      socket.onopen = () => {
        retries = 0;
        setConnected(true);
      };
      socket.onmessage = (event) => {
        let parsed: RealtimeEvent;
        try {
          parsed = JSON.parse(event.data) as RealtimeEvent;
        } catch {
          return;
        }
        listenersRef.current.forEach((listener) => listener(parsed));
      };
      socket.onclose = () => {
        setConnected(false);
        if (!closed) {
          const delay = Math.min(1000 * 2 ** retries, 15000);
          retries += 1;
          timer = setTimeout(connect, delay);
        }
      };
      socket.onerror = () => {
        socket?.close();
      };
    };

    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      socket?.close();
    };
  }, [status]);

  const subscribe = useCallback((callback: Listener) => {
    listenersRef.current.add(callback);
    return () => {
      listenersRef.current.delete(callback);
    };
  }, []);

  const value = useMemo(() => ({ connected, subscribe }), [connected, subscribe]);

  return <RealtimeContext.Provider value={value}>{children}</RealtimeContext.Provider>;
}

export function useRealtime(): RealtimeContextValue {
  const context = useContext(RealtimeContext);
  if (!context) {
    throw new Error("useRealtime must be used within RealtimeProvider");
  }
  return context;
}

export function useIncidentEvents(handler: (event: RealtimeEvent) => void): boolean {
  const { subscribe, connected } = useRealtime();
  const handlerRef = useRef(handler);
  handlerRef.current = handler;
  useEffect(() => {
    return subscribe((event) => {
      if (event.type.startsWith("incident.") || event.type === "notification.created") {
        handlerRef.current(event);
      }
    });
  }, [subscribe]);
  return connected;
}
