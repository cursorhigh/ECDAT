"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { FileDown, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip } from "@/components/ui/tooltip";
import { useToast } from "@/components/feedback/toast";
import { api, type CBOMFormat } from "@/lib/api/client";

const FORMATS: Array<{ value: CBOMFormat; label: string; filename: string; hint: string }> = [
  {
    value: "cyclonedx-json",
    label: "CycloneDX",
    filename: "ecdat-cbom.cdx.json",
    hint: "CycloneDX 1.6, the format other tools read. Opens in most supply-chain tooling.",
  },
  {
    value: "cyclonedx-xml",
    label: "CycloneDX XML",
    filename: "ecdat-cbom.cdx.xml",
    hint: "The same bill of materials as XML, for pipelines that expect it.",
  },
  {
    value: "ecdat",
    label: "ECDAT native",
    filename: "ecdat-cbom.json",
    hint: "ECDAT's own format. Richest, and keeps every recorded detail.",
  },
];

/**
 * Download the Cryptographic Bill of Materials.
 *
 * Every option produces a real file, so the menu names the format rather than
 * offering a generic "Export" that hides which standard came out. A 409 means
 * nothing has been discovered yet, which is reported as such instead of
 * silently producing an empty file.
 */
export function CbomExport({ runId, className }: { runId?: number; className?: string }) {
  const { pushToast } = useToast();
  const [busy, setBusy] = useState<CBOMFormat | null>(null);

  const download = useMutation({
    mutationFn: async (format: CBOMFormat) => {
      const blob = await api.cbom(format, runId);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      const option = FORMATS.find((item) => item.value === format)!;
      anchor.href = url;
      anchor.download = option.filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    },
    onMutate: (format) => setBusy(format),
    onSuccess: (_data, format) => {
      const option = FORMATS.find((item) => item.value === format)!;
      pushToast(`${option.filename} downloaded.`, "success");
    },
    onError: (error) =>
      pushToast(
        error instanceof Error && error.message
          ? error.message
          : "The bill of materials could not be generated.",
        "error",
      ),
    onSettled: () => setBusy(null),
  });

  return (
    <div className={className}>
      <div className="flex flex-wrap gap-1.5">
        {FORMATS.map((option) => (
          <Tooltip key={option.value} msg={option.hint} placement="top" offset={8}>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => download.mutate(option.value)}
              disabled={busy !== null}
              aria-label={`Download bill of materials as ${option.label}`}
            >
              {busy === option.value ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              ) : (
                <FileDown className="h-3.5 w-3.5" aria-hidden="true" />
              )}
              {option.label}
            </Button>
          </Tooltip>
        ))}
      </div>
    </div>
  );
}
