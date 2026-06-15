import type {
  ConnectionTestResult,
  IntegrationCredentials,
  IntegrationRuleContext,
  PlatformIntegrationAdapter,
  PushRuleResult,
  TriggerCountResult,
} from "../types";

export class SentinelOneAdapter implements PlatformIntegrationAdapter {
  readonly platform = "sentinelone" as const;

  private consoleUrl: string;
  private apiToken: string;

  constructor(credentials: IntegrationCredentials) {
    this.consoleUrl = (credentials.consoleUrl ?? "").replace(/\/$/, "");
    this.apiToken = credentials.apiToken ?? "";
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `ApiToken ${this.apiToken}`,
      "Content-Type": "application/json",
    };
  }

  async testConnection(): Promise<ConnectionTestResult> {
    try {
      const response = await fetch(`${this.consoleUrl}/web/api/v2.1/system/status`, {
        headers: this.headers(),
      });

      if (!response.ok) {
        const text = await response.text();
        return {
          success: false,
          message: `System status request failed (${response.status}): ${text.slice(0, 300)}`,
        };
      }

      return { success: true, message: "Connected to SentinelOne console." };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : "Unknown error testing connection.",
      };
    }
  }

  async pushRule(rule: IntegrationRuleContext, remoteRuleId?: string | null): Promise<PushRuleResult> {
    const body = {
      data: {
        name: rule.title,
        description: rule.descriptionSummary,
        query: rule.ruleBody,
        queryType: "events",
        ruleSeverity: mapSeverity(rule.severity),
        status: "Active",
        expirationMode: "Permanent",
      },
    };

    if (remoteRuleId) {
      const response = await fetch(`${this.consoleUrl}/web/api/v2.1/cloud-detection/rules/${remoteRuleId}`, {
        method: "PUT",
        headers: this.headers(),
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`SentinelOne rule update failed (${response.status}): ${text.slice(0, 500)}`);
      }

      return { remoteRuleId, status: "drift" };
    }

    const response = await fetch(`${this.consoleUrl}/web/api/v2.1/cloud-detection/rules`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`SentinelOne rule create failed (${response.status}): ${text.slice(0, 500)}`);
    }

    const data = (await response.json()) as { data: { id: string } };

    return { remoteRuleId: data.data.id, status: "deployed" };
  }

  async deleteRule(remoteRuleId: string): Promise<void> {
    const response = await fetch(`${this.consoleUrl}/web/api/v2.1/cloud-detection/rules/${remoteRuleId}`, {
      method: "DELETE",
      headers: this.headers(),
    });

    if (!response.ok && response.status !== 404) {
      const text = await response.text();
      throw new Error(`SentinelOne rule delete failed (${response.status}): ${text.slice(0, 500)}`);
    }
  }

  async getTriggerCounts(remoteRuleIds: string[], since: Date): Promise<TriggerCountResult[]> {
    const results: TriggerCountResult[] = [];

    for (const remoteRuleId of remoteRuleIds) {
      const response = await fetch(
        `${this.consoleUrl}/web/api/v2.1/cloud-detection/alerts?ruleIds=${remoteRuleId}&createdAt__gte=${since.toISOString()}`,
        { headers: this.headers() }
      );

      if (!response.ok) continue;

      const data = (await response.json()) as { data: unknown[] };

      results.push({
        remoteRuleId,
        bucketStart: since,
        count: data.data.length,
      });
    }

    return results;
  }
}

function mapSeverity(severity: IntegrationRuleContext["severity"]): string {
  switch (severity) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return "Low";
  }
}
