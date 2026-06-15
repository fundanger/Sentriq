"use client";

import { useTransition, useState } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { deployRuleAction, removeDeploymentAction } from "@/actions/integrations";
import { Loader2, Rocket, Trash2 } from "lucide-react";

const STATUS_BADGE_VARIANTS: Record<string, string> = {
  pending: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  deployed: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  drift: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  failed: "bg-red-500/15 text-red-400 border-red-500/30",
  removed: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

export interface DeploymentSummary {
  id: string;
  integrationId: string;
  integrationName: string;
  status: string;
  statusMessage: string | null;
  remoteRuleId: string | null;
  lastSyncedAt: Date | null;
}

export interface AvailableIntegration {
  id: string;
  name: string;
}

export function DeploymentsCard({
  ruleId,
  deployments,
  availableIntegrations,
  canDeploy,
}: {
  ruleId: string;
  deployments: DeploymentSummary[];
  availableIntegrations: AvailableIntegration[];
  canDeploy: boolean;
}) {
  const deployedIntegrationIds = new Set(deployments.map((d) => d.integrationId));
  const deployTargets = availableIntegrations.filter((i) => !deployedIntegrationIds.has(i.id));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Platform deployments</CardTitle>
        <CardDescription>
          Push this rule to a connected SIEM, EDR, or WAF platform and track
          its deployment status.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {deployments.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            This rule has not been deployed to any platform yet.
          </p>
        ) : (
          <div className="flex flex-col divide-y divide-border">
            {deployments.map((deployment) => (
              <DeploymentRow
                key={deployment.id}
                ruleId={ruleId}
                deployment={deployment}
                canDeploy={canDeploy}
              />
            ))}
          </div>
        )}

        {canDeploy && deployTargets.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {deployTargets.map((integration) => (
              <DeployButton key={integration.id} ruleId={ruleId} integration={integration} />
            ))}
          </div>
        )}

        {canDeploy && availableIntegrations.length === 0 && (
          <p className="text-xs text-muted-foreground">
            No platform integrations support this rule&apos;s language yet.
            Configure one in Settings &rarr; Integrations.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function DeploymentRow({
  ruleId,
  deployment,
  canDeploy,
}: {
  ruleId: string;
  deployment: DeploymentSummary;
  canDeploy: boolean;
}) {
  const [isRedeploying, startRedeploy] = useTransition();
  const [isRemoving, startRemove] = useTransition();
  const [message, setMessage] = useState<string | null>(null);

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">{deployment.integrationName}</span>
          <Badge variant="outline" className={STATUS_BADGE_VARIANTS[deployment.status]}>
            {deployment.status}
          </Badge>
        </div>
        {deployment.remoteRuleId && (
          <span className="font-mono text-xs text-muted-foreground">
            {deployment.remoteRuleId}
          </span>
        )}
        {deployment.lastSyncedAt && (
          <span className="text-xs text-muted-foreground">
            Last synced {deployment.lastSyncedAt.toLocaleString()}
          </span>
        )}
        {deployment.statusMessage && (
          <span className="text-xs text-muted-foreground">{deployment.statusMessage}</span>
        )}
        {message && <span className="text-xs text-muted-foreground">{message}</span>}
      </div>
      {canDeploy && (
        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={isRedeploying}
            onClick={() =>
              startRedeploy(async () => {
                const result = await deployRuleAction(ruleId, deployment.integrationId);
                setMessage(result.success ?? result.error ?? null);
              })
            }
          >
            {isRedeploying ? <Loader2 className="animate-spin" /> : <Rocket />}
            Re-deploy
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            disabled={isRemoving}
            onClick={() =>
              startRemove(async () => {
                const result = await removeDeploymentAction(deployment.id);
                setMessage(result.success ?? result.error ?? null);
              })
            }
          >
            {isRemoving ? <Loader2 className="animate-spin" /> : <Trash2 />}
            Remove
          </Button>
        </div>
      )}
    </div>
  );
}

function DeployButton({
  ruleId,
  integration,
}: {
  ruleId: string;
  integration: AvailableIntegration;
}) {
  const [isDeploying, startDeploy] = useTransition();
  const [message, setMessage] = useState<string | null>(null);

  return (
    <div className="flex flex-col gap-1">
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={isDeploying}
        onClick={() =>
          startDeploy(async () => {
            const result = await deployRuleAction(ruleId, integration.id);
            setMessage(result.success ?? result.error ?? null);
          })
        }
      >
        {isDeploying ? <Loader2 className="animate-spin" /> : <Rocket />}
        Deploy to {integration.name}
      </Button>
      {message && <span className="text-xs text-muted-foreground">{message}</span>}
    </div>
  );
}
