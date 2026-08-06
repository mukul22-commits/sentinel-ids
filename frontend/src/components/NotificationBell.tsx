import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  listNotifications,
  markAllNotificationsRead,
  markNotificationRead,
  unreadCount,
} from "../api/endpoints";
import type { Notification } from "../api/types";
import { useIncidentEvents } from "../realtime/RealtimeContext";

function relativeTime(iso: string): string {
  const seconds = Math.floor((Date.now() - Date.parse(iso)) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function NotificationBell() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const { data: unread = 0 } = useQuery({
    queryKey: ["unread-count"],
    queryFn: unreadCount,
    refetchInterval: 30_000,
  });

  const { data: page } = useQuery({
    queryKey: ["notifications"],
    queryFn: () => listNotifications({ page_size: 20 }),
  });

  const invalidate = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ["unread-count"] });
    void queryClient.invalidateQueries({ queryKey: ["notifications"] });
  }, [queryClient]);

  useIncidentEvents((event) => {
    if (event.type === "notification.created") invalidate();
  });

  const markRead = useMutation({
    mutationFn: (id: number) => markNotificationRead(id),
    onSuccess: invalidate,
  });

  const markAll = useMutation({
    mutationFn: markAllNotificationsRead,
    onSuccess: invalidate,
  });

  const notifications = page?.items ?? [];
  const showCount = unread > 99 ? "99+" : String(unread);

  return (
    <div className="relative" ref={listRef}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="relative rounded-md p-2 text-slate-300 hover:bg-slate-800 hover:text-slate-100"
        aria-label={`Notifications (${unread} unread)`}
      >
        <svg
          className="h-5 w-5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <path
            d="M18 8a6 6 0 00-12 0c0 7-3 9-3 9h18s-3-2-3-9"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path d="M13.7 21a2 2 0 01-3.4 0" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        {unread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-semibold text-white">
            {showCount}
          </span>
        )}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} aria-hidden="true" />
          <div className="absolute right-0 z-30 mt-2 w-80 overflow-hidden rounded-lg border border-slate-700 bg-slate-900 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-700 px-3 py-2">
              <span className="text-sm font-semibold text-slate-200">Notifications</span>
              <button
                type="button"
                onClick={() => markAll.mutate()}
                className="text-xs text-emerald-400 hover:text-emerald-300"
              >
                Mark all read
              </button>
            </div>
            <ul className="max-h-96 overflow-y-auto divide-y divide-slate-800">
              {notifications.length === 0 && (
                <li className="px-3 py-6 text-center text-sm text-slate-500">No notifications</li>
              )}
              {notifications.map((notification) => (
                <NotificationRow
                  key={notification.id}
                  notification={notification}
                  onOpen={() => {
                    if (!notification.read) markRead.mutate(notification.id);
                    setOpen(false);
                    if (notification.incident_id) {
                      navigate(`/incidents/${notification.incident_id}`);
                    }
                  }}
                />
              ))}
            </ul>
          </div>
        </>
      )}
    </div>
  );
}

function NotificationRow({
  notification,
  onOpen,
}: {
  notification: Notification;
  onOpen: () => void;
}) {
  return (
    <li>
      <button
        type="button"
        onClick={onOpen}
        className={`w-full px-3 py-2 text-left hover:bg-slate-800 ${notification.read ? "opacity-60" : ""}`}
      >
        <div className="flex items-center justify-between gap-2">
          <span className="truncate text-sm font-medium text-slate-200">{notification.title}</span>
          <span className="shrink-0 text-[10px] text-slate-500">
            {relativeTime(notification.created_at)}
          </span>
        </div>
        {notification.body && (
          <p className="mt-0.5 truncate text-xs text-slate-400">{notification.body}</p>
        )}
      </button>
    </li>
  );
}
