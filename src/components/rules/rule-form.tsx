"use client";

import { useActionState } from "react";
import Link from "next/link";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Alert, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  MitreTechniquePicker,
  type MitreTechniqueOption,
} from "@/components/rules/mitre-technique-picker";
import { DETECTION_LANGUAGES, SEVERITY_LEVELS } from "@/lib/constants";
import type { RuleFormResult } from "@/actions/rules";
import { AlertCircle } from "lucide-react";

const STATUS_OPTIONS = ["stable", "experimental", "deprecated", "draft"] as const;

interface Category {
  id: string;
  name: string;
}

export interface RuleFormDefaults {
  title: string;
  slug: string;
  language: string;
  platformVariant: string;
  primaryCategoryId: string;
  severity: string;
  status: string;
  author: string;
  ruleVersion: string;
  ruleFormatVersion: string;
  descriptionSummary: string;
  descriptionFull: string;
  ruleBody: string;
  falsePositiveNotes: string;
  dataSourceRequirements: string;
  mitreTechniqueIds: string[];
}

const EMPTY_DEFAULTS: RuleFormDefaults = {
  title: "",
  slug: "",
  language: "",
  platformVariant: "",
  primaryCategoryId: "",
  severity: "",
  status: "draft",
  author: "",
  ruleVersion: "1.0",
  ruleFormatVersion: "",
  descriptionSummary: "",
  descriptionFull: "",
  ruleBody: "",
  falsePositiveNotes: "",
  dataSourceRequirements: "",
  mitreTechniqueIds: [],
};

export function RuleForm({
  action,
  categories,
  mitreTechniques,
  defaultValues = EMPTY_DEFAULTS,
  submitLabel = "Create rule",
  cancelHref = "/rules",
}: {
  action: (
    prevState: RuleFormResult | undefined,
    formData: FormData
  ) => Promise<RuleFormResult>;
  categories: Category[];
  mitreTechniques: MitreTechniqueOption[];
  defaultValues?: RuleFormDefaults;
  submitLabel?: string;
  cancelHref?: string;
}) {
  const [state, formAction, isPending] = useActionState(action, undefined);
  const fieldErrors = state?.fieldErrors ?? {};

  return (
    <form action={formAction} className="flex flex-col gap-4">
      {state?.error && (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>{state.error}</AlertTitle>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Basic information</CardTitle>
          <CardDescription>
            Title, language, category, and classification.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5 sm:col-span-2">
            <Label htmlFor="title">Title</Label>
            <Input
              id="title"
              name="title"
              defaultValue={defaultValues.title}
              aria-invalid={!!fieldErrors.title}
              required
            />
            {fieldErrors.title && (
              <p className="text-xs text-destructive">{fieldErrors.title}</p>
            )}
          </div>

          <div className="flex flex-col gap-1.5 sm:col-span-2">
            <Label htmlFor="slug">Slug</Label>
            <Input
              id="slug"
              name="slug"
              placeholder="e.g. kerberoasting-multiple-rc4-tgs-requests-kql"
              defaultValue={defaultValues.slug}
              aria-invalid={!!fieldErrors.slug}
              required
            />
            {fieldErrors.slug && (
              <p className="text-xs text-destructive">{fieldErrors.slug}</p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="language">Language</Label>
            <Select name="language" defaultValue={defaultValues.language || undefined}>
              <SelectTrigger id="language" className="w-full" aria-invalid={!!fieldErrors.language}>
                <SelectValue placeholder="Select a language" />
              </SelectTrigger>
              <SelectContent>
                {DETECTION_LANGUAGES.map((lang) => (
                  <SelectItem key={lang.value} value={lang.value}>
                    {lang.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {fieldErrors.language && (
              <p className="text-xs text-destructive">{fieldErrors.language}</p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="platformVariant">Platform variant (optional)</Label>
            <Input
              id="platformVariant"
              name="platformVariant"
              placeholder="e.g. Microsoft Sentinel"
              defaultValue={defaultValues.platformVariant}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="primaryCategoryId">Category</Label>
            <Select
              name="primaryCategoryId"
              defaultValue={defaultValues.primaryCategoryId || undefined}
            >
              <SelectTrigger
                id="primaryCategoryId"
                className="w-full"
                aria-invalid={!!fieldErrors.primaryCategoryId}
              >
                <SelectValue placeholder="Select a category" />
              </SelectTrigger>
              <SelectContent>
                {categories.map((cat) => (
                  <SelectItem key={cat.id} value={cat.id}>
                    {cat.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {fieldErrors.primaryCategoryId && (
              <p className="text-xs text-destructive">{fieldErrors.primaryCategoryId}</p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="severity">Severity</Label>
            <Select name="severity" defaultValue={defaultValues.severity || undefined}>
              <SelectTrigger id="severity" className="w-full" aria-invalid={!!fieldErrors.severity}>
                <SelectValue placeholder="Select severity" />
              </SelectTrigger>
              <SelectContent>
                {SEVERITY_LEVELS.map((sev) => (
                  <SelectItem key={sev} value={sev} className="capitalize">
                    {sev}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {fieldErrors.severity && (
              <p className="text-xs text-destructive">{fieldErrors.severity}</p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="status">Status</Label>
            <Select name="status" defaultValue={defaultValues.status || "draft"}>
              <SelectTrigger id="status" className="w-full">
                <SelectValue placeholder="Select status" />
              </SelectTrigger>
              <SelectContent>
                {STATUS_OPTIONS.map((status) => (
                  <SelectItem key={status} value={status} className="capitalize">
                    {status}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="author">Author</Label>
            <Input
              id="author"
              name="author"
              defaultValue={defaultValues.author}
              aria-invalid={!!fieldErrors.author}
              required
            />
            {fieldErrors.author && (
              <p className="text-xs text-destructive">{fieldErrors.author}</p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="ruleVersion">Rule version</Label>
            <Input
              id="ruleVersion"
              name="ruleVersion"
              defaultValue={defaultValues.ruleVersion}
              aria-invalid={!!fieldErrors.ruleVersion}
              required
            />
            {fieldErrors.ruleVersion && (
              <p className="text-xs text-destructive">{fieldErrors.ruleVersion}</p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="ruleFormatVersion">Rule format (optional)</Label>
            <Input
              id="ruleFormatVersion"
              name="ruleFormatVersion"
              placeholder="e.g. Sentinel Analytics Rule (Scheduled)"
              defaultValue={defaultValues.ruleFormatVersion}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Descriptions</CardTitle>
          <CardDescription>
            Summary for list views, plus a deep-dive explanation of the attack
            technique and detection logic.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="descriptionSummary">Summary</Label>
            <Textarea
              id="descriptionSummary"
              name="descriptionSummary"
              rows={2}
              defaultValue={defaultValues.descriptionSummary}
              aria-invalid={!!fieldErrors.descriptionSummary}
              required
            />
            {fieldErrors.descriptionSummary && (
              <p className="text-xs text-destructive">{fieldErrors.descriptionSummary}</p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="descriptionFull">Full description (markdown)</Label>
            <Textarea
              id="descriptionFull"
              name="descriptionFull"
              rows={8}
              placeholder="Explain the attack technique, why the rule works, and what normal vs. malicious activity looks like."
              defaultValue={defaultValues.descriptionFull}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Rule code</CardTitle>
          <CardDescription>
            The raw query or rule body, rendered with syntax highlighting on the
            detail page.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="ruleBody">Rule body</Label>
            <Textarea
              id="ruleBody"
              name="ruleBody"
              rows={14}
              className="font-mono text-xs"
              defaultValue={defaultValues.ruleBody}
              aria-invalid={!!fieldErrors.ruleBody}
              required
            />
            {fieldErrors.ruleBody && (
              <p className="text-xs text-destructive">{fieldErrors.ruleBody}</p>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>MITRE ATT&amp;CK mapping</CardTitle>
          <CardDescription>
            Select the techniques and sub-techniques this rule detects.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <MitreTechniquePicker
            techniques={mitreTechniques}
            defaultSelected={defaultValues.mitreTechniqueIds}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Tuning &amp; data sources</CardTitle>
          <CardDescription>
            False-positive guidance and data source requirements for analysts.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="falsePositiveNotes">False positive notes</Label>
            <Textarea
              id="falsePositiveNotes"
              name="falsePositiveNotes"
              rows={4}
              placeholder="Describe legitimate activity that may trigger this rule and how to tune it."
              defaultValue={defaultValues.falsePositiveNotes}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="dataSourceRequirements">Data source requirements</Label>
            <Textarea
              id="dataSourceRequirements"
              name="dataSourceRequirements"
              rows={2}
              placeholder="e.g. Requires SecurityEvent table with Event ID 4769 auditing enabled."
              defaultValue={defaultValues.dataSourceRequirements}
            />
          </div>
        </CardContent>
      </Card>

      <div className="flex items-center justify-end gap-2">
        <Button type="button" variant="outline" render={<Link href={cancelHref} />}>
          Cancel
        </Button>
        <Button type="submit" disabled={isPending}>
          {isPending ? "Saving..." : submitLabel}
        </Button>
      </div>
    </form>
  );
}
