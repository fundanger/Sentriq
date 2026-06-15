import { eq } from "drizzle-orm";
import { db } from "@/db";
import { integrations } from "@/db/schema";
import { decrypt } from "@/lib/crypto";
import { SentinelAdapter } from "./adapters/sentinel";
import { ElasticAdapter } from "./adapters/elastic";
import { SplunkAdapter } from "./adapters/splunk";
import { SentinelOneAdapter } from "./adapters/sentinelone";
import { CloudflareAdapter } from "./adapters/cloudflare";
import type { IntegrationCredentials, PlatformIntegrationAdapter } from "./types";

export function createAdapter(
  platform: string,
  credentials: IntegrationCredentials
): PlatformIntegrationAdapter {
  switch (platform) {
    case "sentinel":
      return new SentinelAdapter(credentials);
    case "elastic":
      return new ElasticAdapter(credentials);
    case "splunk":
      return new SplunkAdapter(credentials);
    case "sentinelone":
      return new SentinelOneAdapter(credentials);
    case "cloudflare":
      return new CloudflareAdapter(credentials);
    default:
      throw new Error(`Unknown integration platform: ${platform}`);
  }
}

export async function getIntegrationAdapter(
  integrationId: string
): Promise<{ adapter: PlatformIntegrationAdapter; integration: typeof integrations.$inferSelect } | null> {
  const integration = await db.query.integrations.findFirst({
    where: eq(integrations.id, integrationId),
  });

  if (!integration) {
    return null;
  }

  const credentialsJson = decrypt({
    ciphertext: integration.encryptedCredentials,
    iv: integration.credentialsIv,
    authTag: integration.credentialsAuthTag,
  });

  const credentials = JSON.parse(credentialsJson) as IntegrationCredentials;
  const adapter = createAdapter(integration.platform, credentials);

  return { adapter, integration };
}
