"use client";

import { useTransition } from "react";
import { Button } from "@/components/ui/button";
import {
  setActiveLlmProviderAction,
  deleteLlmProviderConfigAction,
} from "@/actions/ai-settings";
import { Loader2, Trash2 } from "lucide-react";

export function ProviderConfigActions({
  configId,
  isActive,
}: {
  configId: string;
  isActive: boolean;
}) {
  const [isActivating, startActivate] = useTransition();
  const [isDeleting, startDelete] = useTransition();

  return (
    <div className="flex items-center gap-2">
      {!isActive && (
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={isActivating}
          onClick={() => startActivate(() => setActiveLlmProviderAction(configId))}
        >
          {isActivating && <Loader2 className="animate-spin" />}
          Set active
        </Button>
      )}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        disabled={isDeleting}
        onClick={() => startDelete(() => deleteLlmProviderConfigAction(configId))}
      >
        {isDeleting ? <Loader2 className="animate-spin" /> : <Trash2 />}
        Remove
      </Button>
    </div>
  );
}
