import type {
  ConnectionTestResult,
  IntegrationCredentials,
  IntegrationRuleContext,
  PlatformIntegrationAdapter,
  PushRuleResult,
  TriggerCountResult,
} from "../types";

const CF_API_BASE = "https://api.cloudflare.com/client/v4";
const ENTRYPOINT_PHASE = "http_request_firewall_custom";

export class CloudflareAdapter implements PlatformIntegrationAdapter {
  readonly platform = "cloudflare" as const;

  private zoneId: string;
  private apiToken: string;

  constructor(credentials: IntegrationCredentials) {
    this.zoneId = credentials.zoneId ?? "";
    this.apiToken = credentials.apiToken ?? "";
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.apiToken}`,
      "Content-Type": "application/json",
    };
  }

  private rulesetUrl(): string {
    return `${CF_API_BASE}/zones/${this.zoneId}/rulesets/phases/${ENTRYPOINT_PHASE}/entrypoint`;
  }

  async testConnection(): Promise<ConnectionTestResult> {
    try {
      const response = await fetch(this.rulesetUrl(), { headers: this.headers() });
      const data = (await response.json()) as { success: boolean; errors?: { message: string }[] };

      if (!response.ok || !data.success) {
        return {
          success: false,
          message: data.errors?.map((e) => e.message).join("; ") || `Request failed (${response.status}).`,
        };
      }

      return { success: true, message: "Connected to Cloudflare zone WAF custom ruleset." };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : "Unknown error testing connection.",
      };
    }
  }

  async pushRule(rule: IntegrationRuleContext, remoteRuleId?: string | null): Promise<PushRuleResult> {
    const entrypoint = await this.getOrCreateEntrypoint();

    const ruleBody = {
      action: "block",
      expression: rule.ruleBody.trim(),
      description: `${rule.title} (Sentriq: ${rule.slug})`,
      enabled: true,
    };

    if (remoteRuleId) {
      const response = await fetch(`${CF_API_BASE}/zones/${this.zoneId}/rulesets/${entrypoint.id}/rules/${remoteRuleId}`, {
        method: "PATCH",
        headers: this.headers(),
        body: JSON.stringify(ruleBody),
      });

      const data = (await response.json()) as { success: boolean; errors?: { message: string }[] };
      if (!response.ok || !data.success) {
        throw new Error(`Cloudflare rule update failed: ${data.errors?.map((e) => e.message).join("; ") ?? response.status}`);
      }

      return { remoteRuleId, status: "drift" };
    }

    const response = await fetch(`${CF_API_BASE}/zones/${this.zoneId}/rulesets/${entrypoint.id}/rules`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(ruleBody),
    });

    const data = (await response.json()) as {
      success: boolean;
      errors?: { message: string }[];
      result?: { rules: { id: string; description?: string }[] };
    };

    if (!response.ok || !data.success) {
      throw new Error(`Cloudflare rule create failed: ${data.errors?.map((e) => e.message).join("; ") ?? response.status}`);
    }

    const created = data.result?.rules.find((r) => r.description?.includes(rule.slug));
    if (!created) {
      throw new Error("Cloudflare rule create succeeded but the new rule could not be located in the ruleset response.");
    }

    return { remoteRuleId: created.id, status: "deployed" };
  }

  private async getOrCreateEntrypoint(): Promise<{ id: string }> {
    const response = await fetch(this.rulesetUrl(), { headers: this.headers() });
    const data = (await response.json()) as { success: boolean; result?: { id: string } };

    if (response.ok && data.success && data.result) {
      return { id: data.result.id };
    }

    const createResponse = await fetch(`${CF_API_BASE}/zones/${this.zoneId}/rulesets`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        name: "Sentriq managed WAF rules",
        kind: "zone",
        phase: ENTRYPOINT_PHASE,
        rules: [],
      }),
    });

    const createData = (await createResponse.json()) as {
      success: boolean;
      errors?: { message: string }[];
      result?: { id: string };
    };

    if (!createResponse.ok || !createData.success || !createData.result) {
      throw new Error(
        `Cloudflare ruleset entrypoint creation failed: ${createData.errors?.map((e) => e.message).join("; ") ?? createResponse.status}`
      );
    }

    return { id: createData.result.id };
  }

  async deleteRule(remoteRuleId: string): Promise<void> {
    const entrypoint = await this.getOrCreateEntrypoint();

    const response = await fetch(`${CF_API_BASE}/zones/${this.zoneId}/rulesets/${entrypoint.id}/rules/${remoteRuleId}`, {
      method: "DELETE",
      headers: this.headers(),
    });

    if (!response.ok && response.status !== 404) {
      const text = await response.text();
      throw new Error(`Cloudflare rule delete failed (${response.status}): ${text.slice(0, 500)}`);
    }
  }

  async getTriggerCounts(): Promise<TriggerCountResult[]> {
    throw new Error(
      "Trigger counts for Cloudflare WAF rules require GraphQL Analytics API access, which is not yet implemented."
    );
  }
}
