import { AppShell } from "@/components/layout/app-shell";
import { RiskContextPrompt } from "@/components/data/risk-context-prompt";

export default function WorkspaceLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <AppShell>
      {children}
      {/* Mounted per-route-layout rather than per-page: a run parked in
          AWAITING_CONTEXT is a pending obligation that survives navigation, so
          the operator must be prompted wherever they have wandered to. */}
      <RiskContextPrompt />
    </AppShell>
  );
}
