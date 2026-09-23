"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/feedback/toast";

export function CopyButton({ value, label = "Copy value" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const { pushToast } = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      pushToast("Clipboard access is unavailable in this browser.", "error");
    }
  };
  return <Button type="button" variant="ghost" size="icon-sm" onClick={copy} aria-label={label} title={label}>{copied ? <Check className="h-3.5 w-3.5 text-success" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}</Button>;
}
