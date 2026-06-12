import { Info, CircleArrowDown, CircleAlert, TriangleAlert, Flame } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_BADGE_VARIANTS, type Severity } from "@/lib/constants";
import { cn } from "@/lib/utils";

const SEVERITY_ICONS: Record<Severity, typeof Info> = {
  informational: Info,
  low: CircleArrowDown,
  medium: CircleAlert,
  high: TriangleAlert,
  critical: Flame,
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  const Icon = SEVERITY_ICONS[severity];

  return (
    <Badge
      variant="outline"
      className={cn("capitalize", SEVERITY_BADGE_VARIANTS[severity], className)}
    >
      <Icon />
      {severity}
    </Badge>
  );
}
