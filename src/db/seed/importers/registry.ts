import type { RuleImporter } from "./types";
import { sigmaImporter } from "./sigma";

/**
 * All registered rule importers, keyed by their `id` (the CLI argument for
 * `npm run db:import -- <id>`). To add a new rule source, implement
 * `RuleImporter` in a new module and add it here — no other framework
 * changes are required.
 */
export const importerRegistry: Record<string, RuleImporter> = {
  [sigmaImporter.id]: sigmaImporter,
};
