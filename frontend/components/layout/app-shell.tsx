"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, Boxes, FileBarChart, Gauge, Menu, Route, ScrollText, Search, Settings2, ShieldAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { HealthIndicator } from "@/components/data/health-indicator";
import { SessionScope } from "@/components/layout/session-scope";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { useSession } from "@/lib/session-context";
import { cn } from "@/lib/utils";

const workspaceNavigation = [
  { href: "/dashboard", label: "Dashboard", icon: Gauge },
  { href: "/scans", label: "Discovery & scans", icon: Activity },
  { href: "/assets", label: "Cryptographic assets", icon: Boxes },
  { href: "/analysis", label: "Risk analysis", icon: ShieldAlert },
  { href: "/mitigation", label: "Mitigation & migration", icon: Route },
  { href: "/reports", label: "Reports & CBOM", icon: FileBarChart }
];

const systemNavigation = [
  { href: "/settings", label: "Settings", icon: Settings2 },
  { href: "/audit", label: "Audit trail", icon: ScrollText }
];

const navigation = [...workspaceNavigation, ...systemNavigation];

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <aside className="flex h-full w-[252px] shrink-0 flex-col border-r bg-card">
      <div className="flex h-16 items-center border-b px-5">
        <Link href="/dashboard" onClick={onNavigate} className="group flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center bg-primary text-primary-foreground"><span className="text-sm font-black">E</span></span>
          <span><span className="block text-sm font-bold tracking-[0.18em]">ECDAT</span><span className="mt-0.5 block text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">Crypto intelligence</span></span>
        </Link>
      </div>
      <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto px-3 py-5">
        <p className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">Scans</p>
        <nav className="space-y-2" aria-label="Primary navigation">
          {workspaceNavigation.map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
            return <Link key={item.href} href={item.href} onClick={onNavigate} className={cn("group flex h-10 items-center gap-3 border-l-2 px-3 text-sm transition-colors", active ? "border-primary bg-primary/10 font-medium text-foreground" : "border-transparent text-muted-foreground hover:bg-secondary hover:text-foreground")} aria-current={active ? "page" : undefined}><Icon className={cn("h-4 w-4", active ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} aria-hidden="true" /><span className="truncate">{item.label}</span></Link>;
          })}
        </nav>
      </div>
      <div className="shrink-0 border-t px-3 py-4">
        <p className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">System</p>
        <nav className="space-y-1" aria-label="System navigation">
          {systemNavigation.map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
            return <Link key={item.href} href={item.href} onClick={onNavigate} className={cn("group flex h-10 items-center gap-3 border-l-2 px-3 text-sm transition-colors", active ? "border-primary bg-primary/10 font-medium" : "border-transparent text-muted-foreground hover:bg-secondary hover:text-foreground")} aria-current={active ? "page" : undefined}><Icon className="h-4 w-4" aria-hidden="true" />{item.label}</Link>;
          })}
        </nav>
        <div className="mt-3 flex items-center justify-between border-t px-1 pt-3 text-[10px] text-muted-foreground"><span>ECDAT console</span><span className="tnum">v0.1</span></div>
      </div>
    </aside>
  );
}

function Topbar({ onMenu }: { onMenu: () => void }) {
  const pathname = usePathname();
  const current = navigation.find((item) => pathname === item.href || pathname.startsWith(`${item.href}/`));
  const { error } = useSession();
  return (
    <header className="z-30 flex min-h-16 shrink-0 items-center justify-between gap-3 border-b bg-background/95 px-4 backdrop-blur sm:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <Button type="button" variant="ghost" size="icon" className="lg:hidden" onClick={onMenu} aria-label="Open navigation"><Menu className="h-5 w-5" aria-hidden="true" /></Button>
        <div className="min-w-0"><div className="flex items-center gap-2 text-[11px] text-muted-foreground"><span>Scan</span><span>/</span><span className="truncate text-foreground">{current?.label || "Overview"}</span></div><p className="mt-1 hidden text-[11px] text-muted-foreground sm:block">Cryptographic discovery, risk, and migration control plane</p></div>
      </div>
      <div className="flex shrink-0 items-center gap-2 sm:gap-3">
        {error ? <span className="hidden border border-destructive/30 bg-destructive/5 px-2 py-1 text-[10px] text-destructive md:inline-flex">Session unavailable</span> : null}
        <div className="hidden md:block"><HealthIndicator /></div>
        <SessionScope compact />
        <ThemeToggle />
        <Link href="/assets" className="inline-flex h-9 w-9 items-center justify-center border border-transparent text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground" aria-label="Search cryptographic assets" title="Search cryptographic assets"><Search className="h-4 w-4" aria-hidden="true" /></Link>
      </div>
    </header>
  );
}

export function AppShell({ children }: Readonly<{ children: React.ReactNode }>) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { ready } = useSession();
  return (
    <div className="h-screen overflow-hidden bg-background">
      <a href="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:border focus:bg-background focus:px-3 focus:py-2">Skip to content</a>
      <div className="flex h-screen min-h-0">
        <div className="hidden lg:flex"><Sidebar /></div>
        {mobileOpen ? <div className="fixed inset-0 z-50 flex lg:hidden"><button type="button" className="absolute inset-0 bg-background/80" onClick={() => setMobileOpen(false)} aria-label="Close navigation" /><div className="relative flex h-full"><Sidebar onNavigate={() => setMobileOpen(false)} /><button type="button" className="absolute right-[-42px] top-4 border bg-card p-2" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X className="h-4 w-4" aria-hidden="true" /></button></div></div> : null}
        <div className="flex min-h-0 min-w-0 flex-1 flex-col"><Topbar onMenu={() => setMobileOpen(true)} /><main id="main-content" className="scrollbar-thin min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-6 sm:px-6 lg:px-8"><div className="mx-auto w-full max-w-[1440px]">{ready ? children : <div className="flex min-h-[50vh] items-center justify-center text-sm text-muted-foreground">Connecting to the ECDAT workspace…</div>}</div></main></div>
      </div>
    </div>
  );
}
