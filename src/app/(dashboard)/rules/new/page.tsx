import Link from "next/link";
import { db } from "@/db";
import { Button } from "@/components/ui/button";
import { RuleForm } from "@/components/rules/rule-form";
import { createRuleAction } from "@/actions/rules";
import { ArrowLeft } from "lucide-react";

export default async function NewRulePage() {
  const [categories, mitreTechniques] = await Promise.all([
    db.query.categories.findMany({
      orderBy: (c, { asc }) => [asc(c.sortOrder)],
    }),
    db.query.mitreTechniques.findMany({
      orderBy: (t, { asc }) => [asc(t.id)],
    }),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-3">
        <Button variant="ghost" size="sm" className="w-fit" render={<Link href="/rules" />}>
          <ArrowLeft />
          Back to library
        </Button>
        <div>
          <h1 className="font-heading text-2xl font-semibold tracking-tight">
            New detection rule
          </h1>
          <p className="text-sm text-muted-foreground">
            Author a new rule manually, or use the AI assistant later to draft
            one from a description.
          </p>
        </div>
      </div>

      <RuleForm
        action={createRuleAction}
        categories={categories}
        mitreTechniques={mitreTechniques}
        submitLabel="Create rule"
      />
    </div>
  );
}
