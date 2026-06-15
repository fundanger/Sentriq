import type {
  ConnectionTestResult,
  IntegrationCredentials,
  IntegrationRuleContext,
  PlatformIntegrationAdapter,
  PushRuleResult,
  TriggerCountResult,
} from "../types";

const ARM_BASE = "https://management.azure.com";
const ARM_SCOPE = "https://management.azure.com/.default";
const LOGS_API_BASE = "https://api.loganalytics.io";
const LOGS_SCOPE = "https://api.loganalytics.io/.default";

export class SentinelAdapter implements PlatformIntegrationAdapter {
  readonly platform = "sentinel" as const;

  private tenantId: string;
  private clientId: string;
  private clientSecret: string;
  private subscriptionId: string;
  private resourceGroup: string;
  private workspaceName: string;

  constructor(credentials: IntegrationCredentials) {
    this.tenantId = credentials.tenantId ?? "";
    this.clientId = credentials.clientId ?? "";
    this.clientSecret = credentials.clientSecret ?? "";
    this.subscriptionId = credentials.subscriptionId ?? "";
    this.resourceGroup = credentials.resourceGroup ?? "";
    this.workspaceName = credentials.workspaceName ?? "";
  }

  private async getAccessToken(scope: string = ARM_SCOPE): Promise<string> {
    const response = await fetch(
      `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: this.clientId,
          client_secret: this.clientSecret,
          scope,
        }),
      }
    );

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Azure AD token request failed (${response.status}): ${text}`);
    }

    const data = (await response.json()) as { access_token: string };
    return data.access_token;
  }

  /** Looks up the Log Analytics workspace's customer ID (GUID), required by the query API. */
  private async getWorkspaceCustomerId(token: string): Promise<string> {
    const url = `${ARM_BASE}${this.workspaceResourceId()}?api-version=2022-10-01`;
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Workspace lookup failed (${response.status}): ${text.slice(0, 300)}`);
    }

    const data = (await response.json()) as { properties?: { customerId?: string } };
    const customerId = data.properties?.customerId;
    if (!customerId) {
      throw new Error("Workspace response did not include a customer ID.");
    }

    return customerId;
  }

  private workspaceResourceId(): string {
    return `/subscriptions/${this.subscriptionId}/resourceGroups/${this.resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.workspaceName}`;
  }

  async testConnection(): Promise<ConnectionTestResult> {
    try {
      const token = await this.getAccessToken();
      const url = `${ARM_BASE}${this.workspaceResourceId()}?api-version=2022-10-01`;
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        const text = await response.text();
        return {
          success: false,
          message: `Workspace lookup failed (${response.status}): ${text.slice(0, 300)}`,
        };
      }

      return { success: true, message: `Connected to workspace "${this.workspaceName}".` };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : "Unknown error testing connection.",
      };
    }
  }

  async pushRule(rule: IntegrationRuleContext, remoteRuleId?: string | null): Promise<PushRuleResult> {
    const token = await this.getAccessToken();
    const ruleId = remoteRuleId || crypto.randomUUID();
    const url = `${ARM_BASE}${this.workspaceResourceId()}/providers/Microsoft.SecurityInsights/alertRules/${ruleId}?api-version=2023-02-01`;

    const body = {
      kind: "Scheduled",
      properties: {
        displayName: rule.title,
        description: rule.descriptionSummary,
        severity: mapSeverity(rule.severity),
        enabled: true,
        query: rule.ruleBody,
        queryFrequency: "PT1H",
        queryPeriod: "PT1H",
        triggerOperator: "GreaterThan",
        triggerThreshold: 0,
        suppressionEnabled: false,
        tactics: [],
      },
    };

    const response = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Sentinel rule push failed (${response.status}): ${text.slice(0, 500)}`);
    }

    return {
      remoteRuleId: ruleId,
      status: remoteRuleId ? "drift" : "deployed",
    };
  }

  async deleteRule(remoteRuleId: string): Promise<void> {
    const token = await this.getAccessToken();
    const url = `${ARM_BASE}${this.workspaceResourceId()}/providers/Microsoft.SecurityInsights/alertRules/${remoteRuleId}?api-version=2023-02-01`;

    const response = await fetch(url, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok && response.status !== 404) {
      const text = await response.text();
      throw new Error(`Sentinel rule delete failed (${response.status}): ${text.slice(0, 500)}`);
    }
  }

  async getTriggerCounts(remoteRuleIds: string[], since: Date): Promise<TriggerCountResult[]> {
    if (remoteRuleIds.length === 0) return [];

    const armToken = await this.getAccessToken(ARM_SCOPE);
    const customerId = await this.getWorkspaceCustomerId(armToken);
    const logsToken = await this.getAccessToken(LOGS_SCOPE);

    const timespan = `${since.toISOString()}/${new Date().toISOString()}`;
    const results: TriggerCountResult[] = [];

    for (const remoteRuleId of remoteRuleIds) {
      const query = `SecurityIncident
| where TimeGenerated >= datetime(${since.toISOString()})
| where RelatedAnalyticRuleIds has "${remoteRuleId}"
| summarize count()`;

      const response = await fetch(
        `${LOGS_API_BASE}/v1/workspaces/${customerId}/query`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${logsToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ query, timespan }),
        }
      );

      if (!response.ok) continue;

      const data = (await response.json()) as {
        tables?: { rows?: number[][] }[];
      };

      const count = data.tables?.[0]?.rows?.[0]?.[0] ?? 0;

      results.push({ remoteRuleId, bucketStart: since, count });
    }

    return results;
  }
}

function mapSeverity(severity: IntegrationRuleContext["severity"]): string {
  switch (severity) {
    case "critical":
      return "High";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return "Informational";
  }
}
