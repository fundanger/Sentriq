"use client";

import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { DetectionLanguage } from "@/lib/constants";

const FILE_EXTENSIONS: Record<DetectionLanguage, string> = {
  kql: "kql",
  sigma: "yml",
  splunk: "spl",
  yara: "yar",
  elastic: "eql",
  sentinelone: "txt",
  cloudflare: "txt",
  falco: "yml",
};

export function DownloadButton({
  value,
  filename,
  language,
}: {
  value: string;
  filename: string;
  language: DetectionLanguage;
}) {
  function handleDownload() {
    const extension = FILE_EXTENSIONS[language];
    const blob = new Blob([value], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${filename}.${extension}`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Button
      variant="outline"
      size="icon-sm"
      aria-label="Download rule body"
      onClick={handleDownload}
    >
      <Download />
    </Button>
  );
}
