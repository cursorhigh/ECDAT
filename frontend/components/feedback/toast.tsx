"use client";

import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { CheckCircle2, CircleAlert, Info, X } from "lucide-react";
import { cn } from "@/lib/utils";

type ToastTone = "success" | "error" | "info";
type Toast = { id: number; tone: ToastTone; message: string };

type ToastContextValue = {
  pushToast: (message: string, tone?: ToastTone) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: Readonly<{ children: React.ReactNode }>) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const pushToast = useCallback(
    (message: string, tone: ToastTone = "info") => {
      const id = Date.now() + Math.floor(Math.random() * 1000);
      setToasts((current) => [...current.slice(-3), { id, tone, message }]);
      window.setTimeout(() => dismiss(id), 5200);
    },
    [dismiss]
  );

  const value = useMemo(() => ({ pushToast }), [pushToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[80] flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2" aria-live="polite">
        {toasts.map((toast) => {
          const Icon = toast.tone === "success" ? CheckCircle2 : toast.tone === "error" ? CircleAlert : Info;
          return (
            <div key={toast.id} className={cn("pointer-events-auto flex items-start gap-3 border bg-card px-4 py-3 text-sm shadow-panel", toast.tone === "error" ? "border-destructive/50" : toast.tone === "success" ? "border-success/50" : "border-border")}>
              <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", toast.tone === "error" ? "text-destructive" : toast.tone === "success" ? "text-success" : "text-info")} aria-hidden="true" />
              <p className="min-w-0 flex-1 leading-5">{toast.message}</p>
              <button type="button" className="text-muted-foreground hover:text-foreground" onClick={() => dismiss(toast.id)} aria-label="Dismiss notification">
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast must be used inside ToastProvider");
  return value;
}
