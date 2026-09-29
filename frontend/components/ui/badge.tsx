import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva("inline-flex items-center gap-1.5 whitespace-nowrap border px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.08em]", {
  variants: {
    variant: {
      // `default` tints the background, so the text must use the foreground
      // colour itself. Using -foreground here rendered black-on-black in dark.
      default: "border-primary/30 bg-primary/10 text-primary",
      secondary: "border-border bg-secondary text-secondary-foreground",
      outline: "border-border bg-transparent text-muted-foreground",
      success: "border-emerald-500/35 bg-emerald-500/10 text-emerald-400",
      warning: "border-warning/35 bg-warning/10 text-warning",
      danger: "border-destructive/35 bg-destructive/10 text-destructive",
      purple: "border-purple-500/35 bg-purple-500/10 text-purple-400",
      info: "border-info/35 bg-info/10 text-info",
      muted: "border-border bg-muted text-muted-foreground"
    }
  },
  defaultVariants: { variant: "default" }
});

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}
