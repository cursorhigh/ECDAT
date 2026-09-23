import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva("inline-flex items-center gap-1.5 border px-2 py-0.5 text-[11px] font-medium uppercase tracking-[0.08em]", {
  variants: {
    variant: {
      default: "border-primary/30 bg-primary/10 text-primary-foreground",
      secondary: "border-border bg-secondary text-secondary-foreground",
      outline: "border-border bg-transparent text-muted-foreground",
      success: "border-success/35 bg-success/10 text-success",
      warning: "border-warning/35 bg-warning/10 text-warning",
      danger: "border-destructive/35 bg-destructive/10 text-destructive",
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
