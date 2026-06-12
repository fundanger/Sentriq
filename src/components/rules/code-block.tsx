import { highlightRuleBody } from "@/lib/code-highlight";
import type { DetectionLanguage } from "@/lib/constants";
import { CopyButton } from "@/components/rules/copy-button";
import { DownloadButton } from "@/components/rules/download-button";

export async function CodeBlock({
  code,
  language,
  filename,
}: {
  code: string;
  language: DetectionLanguage;
  filename?: string;
}) {
  const html = await highlightRuleBody(code, language);

  return (
    <div className="group relative">
      <div className="absolute right-2 top-2 z-10 flex gap-1 opacity-0 transition-opacity group-hover:opacity-100">
        <CopyButton value={code} />
        {filename && <DownloadButton value={code} filename={filename} language={language} />}
      </div>
      <div
        className="overflow-x-auto rounded-lg border border-border text-[13px] leading-relaxed [&_pre]:p-4 [&_pre]:!bg-transparent"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </div>
  );
}
