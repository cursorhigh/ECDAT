"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { FileDown, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip } from "@/components/ui/tooltip";
import { useToast } from "@/components/feedback/toast";
import { api, type CBOMFormat } from "@/lib/api/client";

const FORMATS: Array<{ value: CBOMFormat; label: string; filename: string; lead: string; detail: string }> = [
  {
    value: "cyclonedx-json",
    label: "CycloneDX",
    filename: "ecdat-cbom.cdx.json",
    lead: "CycloneDX 1.6, the format other tools read.",
    detail: "Opens in most supply-chain tooling, and the safest choice when something downstream has to parse it.",
  },
  {
    value: "cyclonedx-xml",
    label: "CycloneDX XML",
    filename: "ecdat-cbom.cdx.xml",
    lead: "The same bill of materials as XML.",
    detail: "For pipelines that expect XML rather than JSON. Carries exactly the same assets as the JSON export.",
  },
  {
    value: "ecdat",
    label: "ECDAT native",
    filename: "ecdat-cbom.json",
    lead: "ECDAT's own format.",
    detail: "The richest of the three and the only one that keeps every recorded detail, including how each asset was validated. Use this when the file is coming back into ECDAT.",
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
      {/*
       * A bordered group rather than a bare row of buttons. The formats differ in
       * ways that matter to whoever picks one, so the filename each produces is
       * named on the button itself and the reason to choose it is on the hover --
       * "CycloneDX" alone does not say which of the two CycloneDX exports is meant.
       * Wrapping is explicit so the group reflows as one block instead of
       * scattering buttons across two lines when the panel narrows.
       */}
      <div
        role="group"
        aria-label="Export bill of materials"
        className="flex flex-wrap items-center gap-1.5 border bg-muted/20 p-2"
      >
        {/*
         * The tooltip content is elements, not a string with newlines in it. The
         * bubble is `whitespace-normal`, so an embedded "\n\n" would have
         * collapsed into one run-on sentence -- the line breaks have to be real
         * elements.
         */}
        {FORMATS.map((option) => (
          <Tooltip
            key={option.value}
            msg={
              <span className="flex flex-col gap-1">
                <span>{option.lead}</span>
                <span className="text-muted-foreground">{option.detail}</span>
                <span className="font-mono text-[10px] text-muted-foreground">
                  {option.filename}
                </span>
              </span>
            }
            placement="bottom"
            offset={8}
          >
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => download.mutate(option.value)}
              disabled={busy !== null}
              aria-label={`Download bill of materials as ${option.label}, saved as ${option.filename}`}
              className="h-auto min-h-8 flex-col items-start gap-0.5 px-2.5 py-1.5 text-left"
            >
              <span className="flex items-center gap-1.5">
                {busy === option.value ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                ) : (
                  <FileDown className="h-3.5 w-3.5" aria-hidden="true" />
                )}
                {option.label}
              </span>
              <span className="font-mono text-[10px] font-normal text-muted-foreground">
                {option.filename}
              </span>
            </Button>
          </Tooltip>
        ))}
      </div>
    </div>
  );
}
