import Link from "next/link";
import { Badge } from "@/components/ui/badge";

export function MitreChip({
  id,
  name,
  tactic,
  url,
}: {
  id: string;
  name: string;
  tactic: string;
  url: string;
}) {
  return (
    <Link href={url} target="_blank" rel="noreferrer">
      <Badge
        variant="outline"
        className="gap-1.5 border-border py-1 text-xs transition-colors hover:bg-muted"
      >
        <span className="font-mono font-semibold">{id}</span>
        <span className="text-muted-foreground">{name}</span>
        <span className="text-muted-foreground">·</span>
        <span className="text-muted-foreground">{tactic}</span>
      </Badge>
    </Link>
  );
}
