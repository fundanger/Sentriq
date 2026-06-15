"use client";

import { useTransition } from "react";
import { Button } from "@/components/ui/button";
import { deleteSsoConfigAction, toggleSsoConfigAction } from "@/actions/sso";
import { Loader2, Trash2, Power } from "lucide-react";

export function SsoActions({
  configId,
  enabled,
}: {
  configId: string;
  enabled: boolean;
}) {
  const [isToggling, startToggle] = useTransition();
  const [isDeleting, startDelete] = useTransition();

  return (
    <div className="flex items-center gap-2">
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={isToggling}
        onClick={() => startToggle(() => toggleSsoConfigAction(configId, !enabled))}
      >
        {isToggling ? <Loader2 className="animate-spin" /> : <Power />}
        {enabled ? "Disable" : "Enable"}
      </Button>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        disabled={isDeleting}
        onClick={() => startDelete(() => deleteSsoConfigAction(configId))}
      >
        {isDeleting ? <Loader2 className="animate-spin" /> : <Trash2 />}
        Remove
      </Button>
    </div>
  );
}
