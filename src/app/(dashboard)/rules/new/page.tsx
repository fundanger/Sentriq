import Link from "next/link";
import { redirect } from "next/navigation";
import { db } from "@/db";
import { auth } from "@/lib/auth";
import { canManageRules } from "@/lib/permissions";
import { getOrderedCategories } from "@/lib/categories";
import { Button } from "@/components/ui/button";
import { NewRuleForm } from "@/components/rules/new-rule-form";
import { ArrowLeft } from "lucide-react";

export default async function NewRulePage() {
  const session = await auth();

  if (!canManageRules(session?.user?.role)) {
    redirect("/rules");
  }

  const [categories, mitreTechniques] = await Promise.all([
    getOrderedCategories(),
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
            Author a new rule manually, or describe the threat behavior and
            let the AI assistant draft one for you to review and edit.
          </p>
        </div>
      </div>

      <NewRuleForm categories={categories} mitreTechniques={mitreTechniques} />
    </div>
  );
}
