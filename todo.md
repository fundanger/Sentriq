# Sentriq — Future Work / Ideas

A running list of features and improvements identified during the Phase 2 build
that are out of scope for now but worth revisiting. Not prioritized.

## Additional rule sources

- **Elastic detection rules** (`elastic/detection-rules`, Elastic License 2.0 /
  partially Apache-2.0 depending on file) — implement as a new importer module
  registered in `src/db/seed/importers/registry.ts`, following the Sigma
  importer's shape. Check per-file license headers before import.
- **Splunk security content** (`splunk/security_content`, mostly
  Apache-2.0/Splunk specific) — same pattern.
- **YARA rules** (e.g. `Yara-Rules/rules`, mixed licenses — verify per-repo
  before import) — would need a new `language: yara` rule shape; most YARA
  rule sets target malware family detection rather than the
  category/MITRE-tactic taxonomy used here, so category-mapping heuristics
  will need their own pass.
- Re-import cadence: Sigma's `rules-emerging-threats/`/`rules-compliance/`
  (imported via `--include-emerging`) update frequently upstream. Consider a
  periodic re-import job or at least a documented manual cadence, plus a
  "what changed since last import" digest (diff on `rule_sources.sourceUrl` +
  content hash) so updates can be reviewed before overwriting local edits to
  imported rules.

## Search & performance

- SQLite FTS5 for rule title/description search if `LIKE`-based search on
  `/rules` feels slow at the current ~3,300-rule scale (hasn't been an issue
  yet, but worth tracking as the library grows with additional sources above).
- Re-check `/rules` pagination performance once Elastic/Splunk/YARA imports
  are added on top of the existing Sigma set.

## Rule management

- Rule versioning / changelog — track edits to `detection_rules` over time
  (who changed what, when), especially important once rules can be edited
  after import from an upstream source.
- Bulk operations on `/rules` — multi-select for bulk category/tag
  reassignment, bulk status changes (e.g. mark a batch as `deprecated`).
- Saved search/filter presets — let analysts save a language+category+tag
  filter combination for quick recall.
- Export rules to deployable platform formats (Sentinel/Elastic/Splunk/
  SentinelOne/Cloudflare) — ties directly into the already-deferred Phase 2
  integrations plan (`integrations`, `deployments`, `rule_trigger_stats`
  tables).

## Platform & admin

- Audit log — record auth events, rule create/edit/delete, settings changes
  (especially `/settings/ai`, `/settings/users`, `/settings/branding`) for
  super-admins to review.
- Multi-tenancy — if Sentriq is ever offered beyond a single self-hosted
  instance per org, the schema (especially `llm_provider_configs`,
  `platform_settings`, `dashboard_layouts`) would need an `org_id` scoping
  layer.
- Accessibility pass — keyboard navigation through the dnd-kit dashboard
  customize mode, ARIA labeling on chart widgets (recharts), focus management
  in the AI chat drawer and dialogs.

## Known issues

- Sidebar Languages/Categories nav sections compare
  `pathname === "/rules?language=..."` / `"/rules?category=..."`, which never
  matches because `usePathname()` excludes the query string — these nav items
  never show as "active". Low priority cosmetic fix in
  `src/components/layout/app-sidebar.tsx`.

## Deferred (Phase 2 / out of this build)

- Platform integrations: deploy rules to Sentinel/Elastic/Splunk/SentinelOne/
  Cloudflare + a trigger-count dashboard (`integrations`, `deployments`,
  `rule_trigger_stats` tables) — see prior planning notes.
