import { z } from "zod";
import { eq } from "drizzle-orm";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { detectionRules } from "@/db/schema";
import { getActiveLlmProvider } from "@/lib/ai/provider";
import { searchSimilarRules } from "@/lib/ai/rag";
import type { PlatformContext, PlatformRuleContext } from "@/lib/ai/types";

const requestSchema = z.object({
  messages: z.array(
    z.object({
      role: z.enum(["user", "assistant"]),
      content: z.string(),
    })
  ).min(1),
  ruleSlug: z.string().optional(),
});

export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user?.id) {
    return new Response("Unauthorized", { status: 401 });
  }

  const body = await req.json();
  const parsed = requestSchema.safeParse(body);
  if (!parsed.success) {
    return new Response("Invalid request", { status: 400 });
  }

  const { messages, ruleSlug } = parsed.data;

  const provider = await getActiveLlmProvider(session.user.id);
  if (!provider) {
    return new Response(
      "No AI provider configured. Add one in Settings > AI Provider.",
      { status: 412 }
    );
  }

  const context: PlatformContext = {};

  if (ruleSlug) {
    const rule = await db.query.detectionRules.findFirst({
      where: eq(detectionRules.slug, ruleSlug),
      with: { mitreMappings: { with: { technique: true } } },
    });

    if (rule) {
      context.currentRule = toPlatformRuleContext(rule);
    }
  }

  const lastUserMessage = [...messages].reverse().find((m) => m.role === "user");
  if (lastUserMessage) {
    const ragMatches = await searchSimilarRules(session.user.id, lastUserMessage.content, 5);
    if (ragMatches.length > 0) {
      context.ragMatches = ragMatches;
    }
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        for await (const chunk of provider.chat(messages, context)) {
          controller.enqueue(encoder.encode(chunk));
        }
      } catch (err) {
        controller.enqueue(encoder.encode(`\n\n[Error: ${(err as Error).message}]`));
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-cache",
    },
  });
}

function toPlatformRuleContext(rule: {
  title: string;
  slug: string;
  language: string;
  severity: string;
  descriptionSummary: string;
  descriptionFull: string | null;
  ruleBody: string;
  falsePositiveNotes: string | null;
  mitreMappings: { technique: { id: string; name: string } }[];
}): PlatformRuleContext {
  return {
    title: rule.title,
    slug: rule.slug,
    language: rule.language as PlatformRuleContext["language"],
    severity: rule.severity as PlatformRuleContext["severity"],
    descriptionSummary: rule.descriptionSummary,
    descriptionFull: rule.descriptionFull,
    ruleBody: rule.ruleBody,
    falsePositiveNotes: rule.falsePositiveNotes,
    mitreTechniques: rule.mitreMappings.map((m) => ({
      id: m.technique.id,
      name: m.technique.name,
    })),
  };
}
