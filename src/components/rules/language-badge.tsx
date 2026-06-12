import { Badge } from "@/components/ui/badge";
import { DETECTION_LANGUAGES, type DetectionLanguage } from "@/lib/constants";
import { cn } from "@/lib/utils";

export function LanguageBadge({
  language,
  className,
}: {
  language: DetectionLanguage;
  className?: string;
}) {
  const label =
    DETECTION_LANGUAGES.find((l) => l.value === language)?.label ?? language;

  return (
    <Badge variant="secondary" className={cn("uppercase", className)}>
      {label}
    </Badge>
  );
}
