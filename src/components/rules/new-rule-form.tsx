"use client";

import { useState } from "react";
import { RuleForm, type RuleFormDefaults } from "@/components/rules/rule-form";
import { GenerateWithAiDialog } from "@/components/rules/generate-with-ai-dialog";
import type { MitreTechniqueOption } from "@/components/rules/mitre-technique-picker";
import { createRuleAction } from "@/actions/rules";
import type { GenerateRuleDraftResult } from "@/actions/ai-rule-generation";

interface Category {
  id: string;
  name: string;
}

function slugify(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function NewRuleForm({
  categories,
  mitreTechniques,
}: {
  categories: Category[];
  mitreTechniques: MitreTechniqueOption[];
}) {
  const [defaults, setDefaults] = useState<RuleFormDefaults | undefined>(undefined);
  const [formKey, setFormKey] = useState(0);

  function applyDraft(result: GenerateRuleDraftResult) {
    const draft = result.draft;
    if (!draft) return;

    setDefaults((prev) => ({
      title: draft.title,
      slug: slugify(draft.title),
      language: result.language ?? prev?.language ?? "",
      platformVariant: prev?.platformVariant ?? "",
      primaryCategoryId: result.primaryCategoryId ?? prev?.primaryCategoryId ?? "",
      severity: draft.severity,
      status: "draft",
      author: prev?.author ?? "",
      ruleVersion: prev?.ruleVersion ?? "1.0",
      ruleFormatVersion: prev?.ruleFormatVersion ?? "",
      descriptionSummary: draft.descriptionSummary,
      descriptionFull: draft.descriptionFull,
      ruleBody: draft.ruleBody,
      falsePositiveNotes: draft.falsePositiveNotes,
      dataSourceRequirements: prev?.dataSourceRequirements ?? "",
      mitreTechniqueIds: draft.suggestedMitreTechniqueIds,
    }));
    setFormKey((k) => k + 1);
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-end">
        <GenerateWithAiDialog categories={categories} onApply={applyDraft} />
      </div>

      <RuleForm
        key={formKey}
        action={createRuleAction}
        categories={categories}
        mitreTechniques={mitreTechniques}
        defaultValues={defaults}
        submitLabel="Create rule"
      />
    </div>
  );
}
