import { Badge } from "@/components/ui/badge";
import { SEVERITY_BADGE_VARIANTS, type Severity } from "@/lib/constants";
import { cn } from "@/lib/utils";

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <Badge
      variant="outline"
      className={cn("capitalize", SEVERITY_BADGE_VARIANTS[severity], className)}
    >
      {severity}
    </Badge>
  );
}
