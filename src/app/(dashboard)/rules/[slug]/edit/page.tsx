import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { eq } from "drizzle-orm";
import { db } from "@/db";
import { auth } from "@/lib/auth";
import { canManageRules } from "@/lib/permissions";
import { detectionRules } from "@/db/schema";
import { getOrderedCategories } from "@/lib/categories";
import { Button } from "@/components/ui/button";
import { RuleForm, type RuleFormDefaults } from "@/components/rules/rule-form";
import { updateRuleAction, deleteRuleAction } from "@/actions/rules";
import { ArrowLeft, Trash2 } from "lucide-react";

interface EditRulePageProps {
  params: Promise<{ slug: string }>;
}

export default async function EditRulePage({ params }: EditRulePageProps) {
  const session = await auth();

  if (!canManageRules(session?.user?.role)) {
    redirect("/rules");
  }

  const { slug } = await params;

  const [rule, categories, mitreTechniques] = await Promise.all([
    db.query.detectionRules.findFirst({
      where: eq(detectionRules.slug, slug),
      with: {
        mitreMappings: true,
      },
    }),
    getOrderedCategories(),
    db.query.mitreTechniques.findMany({
      orderBy: (t, { asc }) => [asc(t.id)],
    }),
  ]);

  if (!rule) {
    notFound();
  }

  const defaultValues: RuleFormDefaults = {
    title: rule.title,
    slug: rule.slug,
    language: rule.language,
    platformVariant: rule.platformVariant ?? "",
    primaryCategoryId: rule.primaryCategoryId,
    severity: rule.severity,
    status: rule.status,
    author: rule.author,
    ruleVersion: rule.ruleVersion,
    ruleFormatVersion: rule.ruleFormatVersion ?? "",
    descriptionSummary: rule.descriptionSummary,
    descriptionFull: rule.descriptionFull ?? "",
    ruleBody: rule.ruleBody,
    falsePositiveNotes: rule.falsePositiveNotes ?? "",
    dataSourceRequirements: rule.dataSourceRequirements ?? "",
    mitreTechniqueIds: rule.mitreMappings.map((m) => m.techniqueId),
  };

  const boundUpdateAction = updateRuleAction.bind(null, rule.id);
  const boundDeleteAction = deleteRuleAction.bind(null, rule.id);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-3">
        <Button
          variant="ghost"
          size="sm"
          className="w-fit"
          render={<Link href={`/rules/${rule.slug}`} />}
        >
          <ArrowLeft />
          Back to rule
        </Button>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="font-heading text-2xl font-semibold tracking-tight">
              Edit detection rule
            </h1>
            <p className="text-sm text-muted-foreground">{rule.title}</p>
          </div>
          <form action={boundDeleteAction}>
            <Button type="submit" variant="destructive" size="sm">
              <Trash2 />
              Delete rule
            </Button>
          </form>
        </div>
      </div>

      <RuleForm
        action={boundUpdateAction}
        categories={categories}
        mitreTechniques={mitreTechniques}
        defaultValues={defaultValues}
        submitLabel="Save changes"
        cancelHref={`/rules/${rule.slug}`}
      />
    </div>
  );
}
