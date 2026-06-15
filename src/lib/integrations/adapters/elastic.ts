import type {
  ConnectionTestResult,
  IntegrationCredentials,
  IntegrationRuleContext,
  PlatformIntegrationAdapter,
  PushRuleResult,
  TriggerCountResult,
} from "../types";

export class ElasticAdapter implements PlatformIntegrationAdapter {
  readonly platform = "elastic" as const;

  private kibanaUrl: string;
  private apiKey: string;

  constructor(credentials: IntegrationCredentials) {
    this.kibanaUrl = (credentials.kibanaUrl ?? "").replace(/\/$/, "");
    this.apiKey = credentials.apiKey ?? "";
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `ApiKey ${this.apiKey}`,
      "Content-Type": "application/json",
      "kbn-xsrf": "true",
    };
  }

  async testConnection(): Promise<ConnectionTestResult> {
    try {
      const response = await fetch(`${this.kibanaUrl}/api/status`, {
        headers: this.headers(),
      });

      if (!response.ok) {
        const text = await response.text();
        return {
          success: false,
          message: `Status check failed (${response.status}): ${text.slice(0, 300)}`,
        };
      }

      return { success: true, message: "Connected to Kibana." };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : "Unknown error testing connection.",
      };
    }
  }

  async pushRule(rule: IntegrationRuleContext, remoteRuleId?: string | null): Promise<PushRuleResult> {
    const body = {
      rule_id: remoteRuleId || rule.slug,
      name: rule.title,
      description: rule.descriptionSummary,
      severity: mapSeverity(rule.severity),
      risk_score: mapRiskScore(rule.severity),
      type: "eql",
      language: "eql",
      query: rule.ruleBody,
      index: ["logs-*"],
      enabled: true,
      from: "now-6m",
      interval: "5m",
    };

    const response = await fetch(`${this.kibanaUrl}/api/detection_engine/rules`, {
      method: "PUT",
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Elastic rule push failed (${response.status}): ${text.slice(0, 500)}`);
    }

    const data = (await response.json()) as { id: string; rule_id: string };

    return {
      remoteRuleId: data.rule_id ?? data.id,
      status: remoteRuleId ? "drift" : "deployed",
    };
  }

  async deleteRule(remoteRuleId: string): Promise<void> {
    const response = await fetch(
      `${this.kibanaUrl}/api/detection_engine/rules?rule_id=${encodeURIComponent(remoteRuleId)}`,
      {
        method: "DELETE",
        headers: this.headers(),
      }
    );

    if (!response.ok && response.status !== 404) {
      const text = await response.text();
      throw new Error(`Elastic rule delete failed (${response.status}): ${text.slice(0, 500)}`);
    }
  }

  async getTriggerCounts(remoteRuleIds: string[], since: Date): Promise<TriggerCountResult[]> {
    const results: TriggerCountResult[] = [];

    for (const remoteRuleId of remoteRuleIds) {
      const response = await fetch(
        `${this.kibanaUrl}/api/detection_engine/rules/_find?filter=alert.attributes.params.ruleId:"${remoteRuleId}"`,
        { headers: this.headers() }
      );

      if (!response.ok) continue;

      const data = (await response.json()) as {
        data: { execution_summary?: { last_execution?: { status: string } } }[];
      };

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
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "low";
  }
}

function mapRiskScore(severity: IntegrationRuleContext["severity"]): number {
  switch (severity) {
    case "critical":
      return 90;
    case "high":
      return 73;
    case "medium":
      return 47;
    case "low":
      return 21;
    default:
      return 5;
  }
}
