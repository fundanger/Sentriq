import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const STATUS_VARIANTS: Record<string, string> = {
  stable: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  experimental: "bg-violet-500/15 text-violet-400 border-violet-500/30",
  deprecated: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  draft: "bg-amber-500/15 text-amber-400 border-amber-500/30",
};

export function StatusBadge({
  status,
  className,
}: {
  status: string;
  className?: string;
}) {
  return (
    <Badge
      variant="outline"
      className={cn("capitalize", STATUS_VARIANTS[status], className)}
    >
      {status}
    </Badge>
  );
}
