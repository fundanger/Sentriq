"use client";

import { useTransition, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  deleteIntegrationAction,
  toggleIntegrationActiveAction,
  testIntegrationConnectionAction,
  syncTriggerCountsAction,
} from "@/actions/integrations";
import { Loader2, Trash2, Plug, Power, RefreshCw } from "lucide-react";

export function IntegrationActions({
  integrationId,
  isActive,
  supportsTriggerCounts,
}: {
  integrationId: string;
  isActive: boolean;
  supportsTriggerCounts: boolean;
}) {
  const [isTesting, startTest] = useTransition();
  const [isToggling, startToggle] = useTransition();
  const [isDeleting, startDelete] = useTransition();
  const [isSyncing, startSync] = useTransition();
  const [testMessage, setTestMessage] = useState<string | null>(null);

  return (
    <div className="flex flex-col items-end gap-1.5">
      <div className="flex items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={isTesting}
          onClick={() =>
            startTest(async () => {
              const result = await testIntegrationConnectionAction(integrationId);
              setTestMessage(result.success ?? result.error ?? null);
            })
          }
        >
          {isTesting ? <Loader2 className="animate-spin" /> : <Plug />}
          Test
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={isToggling}
          onClick={() => startToggle(() => toggleIntegrationActiveAction(integrationId, !isActive))}
        >
          {isToggling ? <Loader2 className="animate-spin" /> : <Power />}
          {isActive ? "Disable" : "Enable"}
        </Button>
        {supportsTriggerCounts && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={isSyncing}
            onClick={() =>
              startSync(async () => {
                const result = await syncTriggerCountsAction(integrationId);
                setTestMessage(result.success ?? result.error ?? null);
              })
            }
          >
            {isSyncing ? <Loader2 className="animate-spin" /> : <RefreshCw />}
            Sync trigger counts
          </Button>
        )}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={isDeleting}
          onClick={() => startDelete(() => deleteIntegrationAction(integrationId))}
        >
          {isDeleting ? <Loader2 className="animate-spin" /> : <Trash2 />}
          Remove
        </Button>
      </div>
      {testMessage && (
        <p className="max-w-md text-right text-xs text-muted-foreground">{testMessage}</p>
      )}
    </div>
  );
}
