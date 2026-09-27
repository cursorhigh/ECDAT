"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "@/lib/api/client";
import type { RecentSession, SessionInfo } from "@/lib/api/types";

const ACTIVE_KEY = "ecdat.active-session";
const RECENT_KEY = "ecdat.recent-sessions";

type SessionContextValue = {
  info: SessionInfo | null;
  activeId: number | null;
  /** True once a scan session is selected. Scan-scoped reads wait for this. */
  hasSession: boolean;
  scopeKey: string;
  ready: boolean;
  loading: boolean;
  error: string | null;
  recentSessions: RecentSession[];
  refresh: () => Promise<void>;
  createSession: (name: string) => Promise<void>;
  switchSession: (id: number) => Promise<void>;
  adoptSession: (id: number, name: string) => Promise<void>;
  resetCurrentScope: () => Promise<void>;
  clearActiveSession: () => Promise<void>;
};

const SessionContext = createContext<SessionContextValue | null>(null);

function readRecent(): RecentSession[] {
  if (typeof window === "undefined") return [];
  try {
    const parsed = JSON.parse(window.localStorage.getItem(RECENT_KEY) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item) => item && typeof item.id === "number" && typeof item.name === "string").slice(0, 8);
  } catch {
    return [];
  }
}

function writeActive(id: number | null) {
  if (typeof window === "undefined") return;
  if (id) window.localStorage.setItem(ACTIVE_KEY, String(id));
  else window.localStorage.removeItem(ACTIVE_KEY);
}

function rememberSession(id: number, name: string) {
  const next = [{ id, name }, ...readRecent().filter((item) => item.id !== id)].slice(0, 8);
  window.localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  return next;
}

export function SessionProvider({ children }: Readonly<{ children: React.ReactNode }>) {
  const queryClient = useQueryClient();
  const [info, setInfo] = useState<SessionInfo | null>(null);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [recentSessions, setRecentSessions] = useState<RecentSession[]>([]);
  const [ready, setReady] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const nextInfo = await api.sessionInfo();
      setInfo(nextInfo);
      setActiveId(nextInfo.session_id);
      writeActive(nextInfo.session_id);
      setReady(true);
    } catch (requestError) {
      setInfo(null);
      setError(requestError instanceof Error ? requestError.message : "Unable to read the active session.");
      setReady(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setRecentSessions(readRecent());
      void refresh();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);

  const createSession = useCallback(
    async (name: string) => {
      const created = await api.createSession(name);
      writeActive(created.id);
      setActiveId(created.id);
      setRecentSessions(rememberSession(created.id, created.name));
      await refresh();
      await queryClient.invalidateQueries();
    },
    [queryClient, refresh]
  );

  const switchSession = useCallback(
    async (id: number) => {
      writeActive(id || null);
      setActiveId(id || null);
      await api.switchSession(id);
      await refresh();
      await queryClient.invalidateQueries();
    },
    [queryClient, refresh]
  );

  const adoptSession = useCallback(
    async (id: number, name: string) => {
      writeActive(id);
      setActiveId(id);
      setRecentSessions(rememberSession(id, name));
      await refresh();
      await queryClient.invalidateQueries();
    },
    [queryClient, refresh]
  );

  const resetCurrentScope = useCallback(async () => {
    await api.resetSession();
    writeActive(null);
    setActiveId(null);
    await refresh();
    await queryClient.invalidateQueries();
  }, [queryClient, refresh]);

  const clearActiveSession = useCallback(async () => {
    writeActive(null);
    setActiveId(null);
    await api.switchSession(0);
    await refresh();
    await queryClient.invalidateQueries();
  }, [queryClient, refresh]);

  const value = useMemo<SessionContextValue>(
    () => ({
      info,
      activeId,
      // Scan-scoped reads wait for this. `ready` only means the session lookup
      // finished, which is true when it found nothing, so gating on `ready`
      // alone fired every scan query against a scope that did not exist.
      hasSession: activeId !== null,
      // A scan and everything derived from it live in one session, so the
      // cache key names that session. With no session there is no dataset to
      // key -- it used to be "all-data", which meant no session quietly became
      // every session's rows mixed into one list.
      scopeKey: activeId ? `session-${activeId}` : "no-session",
      ready,
      loading,
      error,
      recentSessions,
      refresh,
      createSession,
      switchSession,
      adoptSession,
      resetCurrentScope,
      clearActiveSession
    }),
    [info, activeId, ready, loading, error, recentSessions, refresh, createSession, switchSession, adoptSession, resetCurrentScope, clearActiveSession]
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession() {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}

export function sessionErrorMessage(error: unknown) {
  if (error instanceof ApiError) return error.message;
  return error instanceof Error ? error.message : "Unexpected session error";
}
