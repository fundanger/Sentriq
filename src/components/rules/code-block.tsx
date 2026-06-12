import { highlightRuleBody } from "@/lib/code-highlight";
import type { DetectionLanguage } from "@/lib/constants";
import { CopyButton } from "@/components/rules/copy-button";

export async function CodeBlock({
  code,
  language,
}: {
  code: string;
  language: DetectionLanguage;
}) {
  const html = await highlightRuleBody(code, language);

  return (
    <div className="group relative">
      <div className="absolute right-2 top-2 z-10 opacity-0 transition-opacity group-hover:opacity-100">
        <CopyButton value={code} />
      </div>
      <div
        className="overflow-x-auto rounded-lg border border-border text-[13px] leading-relaxed [&_pre]:p-4 [&_pre]:!bg-transparent"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </div>
  );
}
