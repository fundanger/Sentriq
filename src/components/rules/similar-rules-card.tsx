import Link from "next/link";
import { auth } from "@/lib/auth";
import { findSimilarRules } from "@/lib/ai/rag";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { LanguageBadge } from "@/components/rules/language-badge";
import { Sparkles } from "lucide-react";

interface SimilarRulesCardProps {
  rule: {
    id: string;
    title: string;
    descriptionSummary: string;
    descriptionFull?: string | null;
    embedding?: number[] | null;
  };
}

export async function SimilarRulesCard({ rule }: SimilarRulesCardProps) {
  const session = await auth();
  if (!session?.user?.id) {
    return null;
  }

  const matches = await findSimilarRules(session.user.id, rule, 5);

  if (matches.length === 0) {
    return null;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="size-4 text-muted-foreground" />
          Similar rules
        </CardTitle>
        <CardDescription>
          Other rules in the library with related detection logic, found via
          semantic search.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col divide-y divide-border">
        {matches.map((match) => (
          <Link
            key={match.slug}
            href={`/rules/${match.slug}`}
            className="flex items-center justify-between gap-3 py-2.5 text-sm transition-colors hover:text-primary first:pt-0 last:pb-0"
          >
            <div className="flex flex-col">
              <span className="font-medium">{match.title}</span>
              <span className="line-clamp-1 text-xs text-muted-foreground">
                {match.descriptionSummary}
              </span>
            </div>
            <LanguageBadge language={match.language} className="shrink-0" />
          </Link>
        ))}
      </CardContent>
    </Card>
  );
}
