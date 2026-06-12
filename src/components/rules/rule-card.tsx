import Link from "next/link";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/rules/severity-badge";
import { LanguageBadge } from "@/components/rules/language-badge";
import { StatusBadge } from "@/components/rules/status-badge";
import { Download } from "lucide-react";
import type { Severity, DetectionLanguage } from "@/lib/constants";

interface RuleCardProps {
  slug: string;
  title: string;
  descriptionSummary: string;
  severity: Severity;
  language: DetectionLanguage;
  status: string;
  categoryName?: string | null;
  sourceProject?: string | null;
}

export function RuleCard({
  slug,
  title,
  descriptionSummary,
  severity,
  language,
  status,
  categoryName,
  sourceProject,
}: RuleCardProps) {
  return (
    <Link href={`/rules/${slug}`}>
      <Card className="h-full transition-colors hover:bg-muted/50">
        <CardHeader>
          <div className="flex items-start justify-between gap-2">
            <CardTitle className="leading-snug">{title}</CardTitle>
          </div>
          <CardDescription className="line-clamp-2">
            {descriptionSummary}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={severity} />
          <LanguageBadge language={language} />
          <StatusBadge status={status} />
          {sourceProject && (
            <Badge variant="outline" className="gap-1 text-muted-foreground">
              <Download className="size-3" />
              {sourceProject}
            </Badge>
          )}
          {categoryName && (
            <span className="ml-auto text-xs text-muted-foreground">
              {categoryName}
            </span>
          )}
        </CardContent>
      </Card>
    </Link>
  );
}
