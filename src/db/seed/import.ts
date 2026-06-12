import { importerRegistry } from "./importers/registry";
import { runImporter } from "./importers/runner";
import type { ImporterOptions } from "./importers/types";

async function main() {
  const [importerId, ...rest] = process.argv.slice(2);

  if (!importerId) {
    console.error("Usage: npm run db:import -- <importer-id> [--flags]");
    console.error(`Available importers: ${Object.keys(importerRegistry).join(", ")}`);
    process.exit(1);
  }

  const importer = importerRegistry[importerId];
  if (!importer) {
    console.error(`Unknown importer "${importerId}".`);
    console.error(`Available importers: ${Object.keys(importerRegistry).join(", ")}`);
    process.exit(1);
  }

  const options: ImporterOptions = {
    flags: new Set(rest.filter((arg) => arg.startsWith("--"))),
  };

  await runImporter(importer, options);
}

main()
  .catch((err) => {
    console.error("Import failed:", err);
    process.exit(1);
  })
  .finally(() => {
    process.exit(0);
  });
