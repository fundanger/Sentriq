import type {
  ConnectionTestResult,
  IntegrationCredentials,
  IntegrationRuleContext,
  PlatformIntegrationAdapter,
  PushRuleResult,
  TriggerCountResult,
} from "../types";

export class SplunkAdapter implements PlatformIntegrationAdapter {
  readonly platform = "splunk" as const;

  private managementUrl: string;
  private token: string;

  constructor(credentials: IntegrationCredentials) {
    this.managementUrl = (credentials.managementUrl ?? "").replace(/\/$/, "");
    this.token = credentials.token ?? "";
  }

  private headers(extra?: Record<string, string>): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
      ...extra,
    };
  }

  async testConnection(): Promise<ConnectionTestResult> {
    try {
      const response = await fetch(
        `${this.managementUrl}/services/server/info?output_mode=json`,
        { headers: this.headers() }
      );

      if (!response.ok) {
        const text = await response.text();
        return {
          success: false,
          message: `Server info request failed (${response.status}): ${text.slice(0, 300)}`,
        };
      }

      return { success: true, message: "Connected to Splunk management API." };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : "Unknown error testing connection.",
      };
    }
  }

  async pushRule(rule: IntegrationRuleContext, remoteRuleId?: string | null): Promise<PushRuleResult> {
    const savedSearchName = remoteRuleId || `sentriq_${rule.slug}`;
    const exists = await this.savedSearchExists(savedSearchName);

    const params = new URLSearchParams({
      search: rule.ruleBody,
      description: rule.descriptionSummary,
      "action.correlationsearch.enabled": "1",
      "action.correlationsearch.label": rule.title,
      "alert.severity": String(mapSeverity(rule.severity)),
      disabled: "0",
    });

    if (exists) {
      const response = await fetch(
        `${this.managementUrl}/servicesNS/nobody/search/saved/searches/${encodeURIComponent(savedSearchName)}?output_mode=json`,
        {
          method: "POST",
          headers: this.headers({ "Content-Type": "application/x-www-form-urlencoded" }),
          body: params,
        }
      );

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`Splunk saved search update failed (${response.status}): ${text.slice(0, 500)}`);
      }

      return { remoteRuleId: savedSearchName, status: "drift" };
    }

    params.set("name", savedSearchName);

    const response = await fetch(
      `${this.managementUrl}/servicesNS/nobody/search/saved/searches?output_mode=json`,
      {
        method: "POST",
        headers: this.headers({ "Content-Type": "application/x-www-form-urlencoded" }),
        body: params,
      }
    );

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Splunk saved search create failed (${response.status}): ${text.slice(0, 500)}`);
    }

    return { remoteRuleId: savedSearchName, status: "deployed" };
  }

  private async savedSearchExists(name: string): Promise<boolean> {
    const response = await fetch(
      `${this.managementUrl}/servicesNS/nobody/search/saved/searches/${encodeURIComponent(name)}?output_mode=json`,
      { headers: this.headers() }
    );
    return response.ok;
  }

  async deleteRule(remoteRuleId: string): Promise<void> {
    const response = await fetch(
      `${this.managementUrl}/servicesNS/nobody/search/saved/searches/${encodeURIComponent(remoteRuleId)}?output_mode=json`,
      {
        method: "DELETE",
        headers: this.headers(),
      }
    );

    if (!response.ok && response.status !== 404) {
      const text = await response.text();
      throw new Error(`Splunk saved search delete failed (${response.status}): ${text.slice(0, 500)}`);
    }
  }

  async getTriggerCounts(remoteRuleIds: string[], since: Date): Promise<TriggerCountResult[]> {
    const results: TriggerCountResult[] = [];

    for (const remoteRuleId of remoteRuleIds) {
      const response = await fetch(
        `${this.managementUrl}/servicesNS/nobody/search/saved/searches/${encodeURIComponent(remoteRuleId)}/history?output_mode=json`,
        { headers: this.headers() }
      );

      if (!response.ok) continue;

      const data = (await response.json()) as { entry?: unknown[] };

      results.push({
        remoteRuleId,
        bucketStart: since,
        count: data.entry?.length ?? 0,
      });
    }

    return results;
  }
}

function mapSeverity(severity: IntegrationRuleContext["severity"]): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}
