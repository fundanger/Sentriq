import Link from "next/link";
import { notFound } from "next/navigation";
import { eq } from "drizzle-orm";
import { db } from "@/db";
import { detectionRules } from "@/db/schema";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SeverityBadge } from "@/components/rules/severity-badge";
import { LanguageBadge } from "@/components/rules/language-badge";
import { StatusBadge } from "@/components/rules/status-badge";
import { CodeBlock } from "@/components/rules/code-block";
import { MitreChip } from "@/components/rules/mitre-chip";
import { CvssBadge } from "@/components/rules/cvss-badge";
import {
  ArrowLeft,
  Pencil,
  ShieldAlert,
  ExternalLink,
  Sparkles,
} from "lucide-react";

interface RuleDetailPageProps {
  params: Promise<{ slug: string }>;
}

const REFERENCE_TYPE_LABELS: Record<string, string> = {
  vendor_advisory: "Vendor advisory",
  blog_post: "Blog post",
  mitre_page: "MITRE ATT&CK",
  cve_record: "CVE record",
  documentation: "Documentation",
  other: "Reference",
};

export default async function RuleDetailPage({ params }: RuleDetailPageProps) {
  const { slug } = await params;

  const rule = await db.query.detectionRules.findFirst({
    where: eq(detectionRules.slug, slug),
    with: {
      primaryCategory: true,
      family: true,
      mitreMappings: { with: { technique: true } },
      cveMappings: { with: { cve: true } },
      references: true,
    },
  });

  if (!rule) {
    notFound();
  }

  const sortedReferences = [...rule.references].sort(
    (a, b) => a.sortOrder - b.sortOrder
  );
  const description = rule.descriptionFull ?? rule.family?.conceptDescription ?? null;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-3">
        <Button variant="ghost" size="sm" className="w-fit" render={<Link href="/rules" />}>
          <ArrowLeft />
          Back to library
        </Button>

        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex flex-col gap-2">
            <h1 className="font-heading text-2xl font-semibold tracking-tight">
              {rule.title}
            </h1>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={rule.severity} />
              <LanguageBadge language={rule.language} />
              <StatusBadge status={rule.status} />
              {rule.primaryCategory && (
                <span className="text-xs text-muted-foreground">
                  {rule.primaryCategory.name}
                </span>
              )}
              {rule.platformVariant && (
                <span className="text-xs text-muted-foreground">
                  · {rule.platformVariant}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm">
              <Sparkles />
              Ask AI about this rule
            </Button>
            <Button variant="outline" size="sm" render={<Link href={`/rules/${rule.slug}/edit`} />}>
              <Pencil />
              Edit
            </Button>
          </div>
        </div>

        <p className="max-w-3xl text-sm text-muted-foreground">
          {rule.descriptionSummary}
        </p>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="code">Rule Code</TabsTrigger>
          <TabsTrigger value="mitre">MITRE &amp; CVE</TabsTrigger>
          <TabsTrigger value="tuning">FP &amp; Tuning</TabsTrigger>
          <TabsTrigger value="references">References</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4 flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Attack technique &amp; detection logic</CardTitle>
              <CardDescription>
                How this rule works and what it&apos;s designed to catch.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {description ? (
                <div className="flex flex-col gap-3 whitespace-pre-line text-sm leading-relaxed text-foreground/90">
                  {description}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  No extended description has been written for this rule yet.
                </p>
              )}
            </CardContent>
          </Card>

          {rule.dataSourceRequirements && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ShieldAlert className="size-4 text-muted-foreground" />
                  Data source requirements
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  {rule.dataSourceRequirements}
                </p>
              </CardContent>
            </Card>
          )}

          <div className="grid gap-2 text-sm text-muted-foreground sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <span className="font-medium text-foreground">Author</span>
              <p>{rule.author}</p>
            </div>
            <div>
              <span className="font-medium text-foreground">Rule version</span>
              <p>{rule.ruleVersion}</p>
            </div>
            {rule.ruleFormatVersion && (
              <div>
                <span className="font-medium text-foreground">Format</span>
                <p>{rule.ruleFormatVersion}</p>
              </div>
            )}
            {rule.family && (
              <div>
                <span className="font-medium text-foreground">Rule family</span>
                <p>{rule.family.name}</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="code" className="mt-4">
          <CodeBlock code={rule.ruleBody} language={rule.language} />
        </TabsContent>

        <TabsContent value="mitre" className="mt-4 flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>MITRE ATT&amp;CK mapping</CardTitle>
              <CardDescription>
                Techniques and sub-techniques this rule detects.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {rule.mitreMappings.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {rule.mitreMappings.map(({ technique }) => (
                    <MitreChip
                      key={technique.id}
                      id={technique.id}
                      name={technique.name}
                      tactic={technique.tactic}
                      url={technique.url}
                    />
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  No MITRE techniques mapped.
                </p>
              )}
            </CardContent>
          </Card>

          {rule.cveMappings.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Linked CVEs</CardTitle>
                <CardDescription>
                  Rule severity is set independently of CVE severity - detection
                  quality and vulnerability impact are tracked separately.
                </CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                {rule.cveMappings.map(({ cve }) => (
                  <div
                    key={cve.id}
                    className="flex flex-col gap-3 rounded-lg border border-border p-3 sm:flex-row sm:items-start sm:justify-between"
                  >
                    <div className="flex flex-col gap-1">
                      <Link
                        href={cve.referenceUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 font-mono text-sm font-semibold hover:underline"
                      >
                        {cve.id}
                        <ExternalLink className="size-3" />
                      </Link>
                      <p className="max-w-2xl text-sm text-muted-foreground">
                        {cve.description}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Vector: <span className="font-mono">{cve.cvssVector}</span>
                      </p>
                    </div>
                    <CvssBadge score={cve.cvssScore} version={cve.cvssVersion} />
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="tuning" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>False positive &amp; tuning notes</CardTitle>
              <CardDescription>
                Known benign triggers and recommended adjustments.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {rule.falsePositiveNotes ? (
                <p className="whitespace-pre-line text-sm leading-relaxed text-foreground/90">
                  {rule.falsePositiveNotes}
                </p>
              ) : (
                <p className="text-sm text-muted-foreground">
                  No false-positive guidance has been documented for this rule.
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="references" className="mt-4">
          {sortedReferences.length > 0 ? (
            <Card>
              <CardContent className="flex flex-col divide-y divide-border">
                {sortedReferences.map((ref) => (
                  <Link
                    key={ref.id}
                    href={ref.url}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between gap-3 py-2.5 text-sm transition-colors hover:text-primary first:pt-0 last:pb-0"
                  >
                    <span className="flex items-center gap-2">
                      <ExternalLink className="size-3.5 text-muted-foreground" />
                      {ref.title}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {REFERENCE_TYPE_LABELS[ref.referenceType] ?? ref.referenceType}
                    </span>
                  </Link>
                ))}
              </CardContent>
            </Card>
          ) : (
            <Alert>
              <AlertTitle>No references</AlertTitle>
              <AlertDescription>
                This rule doesn&apos;t have any linked references yet.
              </AlertDescription>
            </Alert>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
