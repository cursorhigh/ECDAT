import { CircleAlert, Inbox, Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export function LoadingState({ label = "Loading workspace data" }: { label?: string }) {
  return (
    <div className="space-y-4" role="status" aria-live="polite">
      <div className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />{label}</div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((item) => <Skeleton key={item} className="h-28" />)}
      </div>
      <Skeleton className="h-72" />
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message?: string; onRetry?: () => void }) {
  return (
    <div className="flex min-h-56 flex-col items-center justify-center border border-destructive/30 bg-destructive/5 px-6 text-center" role="alert">
      <CircleAlert className="h-7 w-7 text-destructive" aria-hidden="true" />
      <h2 className="mt-3 text-sm font-semibold">Unable to load this view</h2>
      <p className="mt-1 max-w-md text-xs leading-5 text-muted-foreground">{message || "The local API did not return a usable response."}</p>
      {onRetry ? <Button className="mt-4" variant="outline" size="sm" onClick={onRetry}><RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />Retry</Button> : null}
    </div>
  );
}

export function EmptyState({ title = "No records in this scope", description, action }: { title?: string; description?: string; action?: React.ReactNode }) {
  return (
    <div className="flex min-h-52 flex-col items-center justify-center border border-dashed bg-muted/15 px-6 text-center">
      <Inbox className="h-7 w-7 text-muted-foreground" aria-hidden="true" />
      <h2 className="mt-3 text-sm font-semibold">{title}</h2>
      {description ? <p className="mt-1 max-w-md text-xs leading-5 text-muted-foreground">{description}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
