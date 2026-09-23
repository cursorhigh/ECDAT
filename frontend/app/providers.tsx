"use client";

import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SessionProvider } from "@/lib/session-context";
import { ThemeProvider } from "@/lib/theme";
import { ToastProvider } from "@/components/feedback/toast";

export function Providers({ children }: Readonly<{ children: React.ReactNode }>) {
  const [queryClient] = useState(() => new QueryClient({ defaultOptions: { queries: { staleTime: 15000, retry: 1, refetchOnWindowFocus: false } } }));
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <SessionProvider>
          <ToastProvider>{children}</ToastProvider>
        </SessionProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
