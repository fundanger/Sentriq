# Sentriq — Future Work / Ideas

A running list of features and improvements identified during the Phase 2 build
that are out of scope for now but worth revisiting. Not prioritized.

## Additional rule sources

**Licensing policy**: only import from sources that are ethically licensed,
open, and free for commercial use with redistribution-with-attribution
(e.g. Apache-2.0, MIT, DRL-1.1). The `rule_sources` table + per-rule
"Source & attribution" card on the detail page exist specifically to satisfy
attribution requirements for these licenses.

- **DONE — Splunk security content** (`splunk/security_content`,
  Apache-2.0) — imported via `src/db/seed/importers/splunk.ts`
  (`npm run db:import -- splunk`), 2,056 rules from `detections/` across
  application/cloud/endpoint/network/web. Category mapped via MITRE
  tactic-of-technique lookup (falls back to `security_domain`/`category`).
  All rules default to `medium` severity (upstream schema has no
  severity/risk field) — revisit if a better signal is found later.
- **DONE — Azure/Azure-Sentinel Analytic Rules** (`Azure/Azure-Sentinel`,
  MIT) — imported via `src/db/seed/importers/azure-sentinel.ts`
  (`npm run db:import -- azure-sentinel`), 2,001 KQL rules (`kql` count went
  from 14 to 2,015). Discovered all 2,116 `Solutions/*/Analytic
  Rules/*.yaml` files via the GitHub git-trees recursive API (repo itself is
  ~14.6GB, too large to clone; fetched each file individually via
  `raw.githubusercontent.com`, cached under `tmp/azure-sentinel/`). Category
  mapped from `tactics` (ATT&CK tactic names) directly; MITRE IDs from
  `relevantTechniques`; severity from the rule's own `severity` field
  (varied distribution, unlike Splunk).
- **EXCLUDED — Elastic detection rules** (`elastic/detection-rules`, Elastic
  License 2.0) — ELv2's anti-managed-service clause conflicts with the
  "free for commercial use" policy above. Not importing.
- **EXCLUDED — YARA rule corpora** (e.g. `Yara-Rules/rules`, GPLv2;
  `elastic/protections-artifacts`, NOASSERTION; most other YARA repos are
  tooling/generators, not corpora, or have no clear license) — no
  permissively-licensed YARA rule corpus of meaningful scale was found.
  Revisit if one surfaces later.
- **EXCLUDED — Suricata/OSSEC rule corpora** (`OISF/suricata`, GPL-2.0;
  `ossec/ossec-hids`, GPL-2.0; `wazuh/wazuh-ruleset`, no license) — copyleft
  or unlicensed, conflicts with policy. Not importing.
- **DONE — Falco rules** (`falcosecurity/rules`, Apache-2.0) — added new
  `falco` value to the `language` enum (`src/db/schema/rules.ts`,
  `src/db/seed/types.ts`, `DETECTION_LANGUAGES` in
  `src/lib/constants.ts`, Shiki map in `src/lib/code-highlight.ts` — no DB
  migration needed, SQLite `language` column has no CHECK constraint).
  Imported via `src/db/seed/importers/falco.ts`
  (`npm run db:import -- falco`), 93 runtime container/cloud security rules
  from `rules/falco_rules.yaml` + `falco-incubating_rules.yaml` +
  `falco-sandbox_rules.yaml`. Category from `mitre_<tactic>` tags (fallback
  to context tags like `network`/`filesystem`/`container`); MITRE IDs from
  `T####`/`T####.###` tags; severity from `priority`
  (CRITICAL/ERROR/WARNING/NOTICE/INFO → critical/high/medium/low/informational);
  `enabled: false` rules marked `experimental`.
- **DONE — Cloudflare WAF rules** (`mintyYuki/cf-waf-ruleset`, MIT) — small
  (4 rules) but real corpus of monolithic WAF custom-rule expressions.
  Imported via `src/db/seed/importers/cloudflare.ts`
  (`npm run db:import -- cloudflare`), `cloudflare` count went from 4 to 8.
  Each non-empty file (`BasicSecurity.txt`, `AntiExploit.txt`,
  `AdvancedSecurity-1.txt`, `AdvancedSecurity-2.txt` — `-3` is empty,
  skipped) becomes one rule; category/severity/description hand-mapped per
  file in `RULE_DEFS` since the upstream files carry no metadata beyond the
  raw Wirefilter expression.
- **DONE — YARA rules** (`0xN0n4m3d3v/kit-shell`, CC0-1.0/public domain) — 53
  well-formed YARA rules (webshells, hacktools, infostealers, ransomware,
  generic malware) with `meta.description`/`severity`/`mitre` fields.
  Imported via `src/db/seed/importers/yara.ts` (`npm run db:import -- yara`),
  `yara` count went from 4 to 57. Parser splits each `.yar` file into
  top-level `rule NAME { ... }` blocks via brace-matching (no YAML/JSON
  structure to lean on). Category mapped from filename (hacktool ->
  defense-evasion, infostealers -> credential-access, ransomware/
  malware_generic -> ransomware, webshells -> persistence); MITRE ID from
  `meta.mitre` (single technique per rule, when present).
- **DONE — Hand-authored Elastic + SentinelOne rules** — both languages had
  only 3 first-party rules with no compliant import source found (Elastic:
  ELv2 repo-wide; SentinelOne: no official corpus, community repos are
  GPL/LGPL/unlicensed). Added 2 new variants each as siblings to existing
  rule families (no `rule_sources` row — first-party Sentriq content):
  - `rule-password-spray-s1` (SentinelOne STAR/Singularity Identity) added
    to `fam-password-spray` in `credentialAccess.ts`.
  - `rule-mfa-fatigue-s1` (SentinelOne STAR/Singularity Identity) added to
    `fam-mfa-fatigue` in `cloudSaas.ts`.
  - `rule-dns-tunneling-elastic` (Elastic ES|QL) added to
    `fam-dns-tunneling` in `reconAndC2.ts`.
  - `rule-generic-sqli-elastic` (Elastic ES|QL) added to `fam-generic-sqli`
    in `webAttacks.ts`.
  Elastic and SentinelOne both went from 3 to 5 rules. Re-run
  `npm run db:seed` (idempotent) to apply.
- **Reference-only, not importable as rules — MITRE CAR**
  (`mitre-attack/car`, Apache-2.0) and **Atomic Red Team**
  (`redcanaryco/atomic-red-team`, MIT) — CAR is "analytics" (pseudocode +
  references to Sigma/Splunk/EQL implementations we likely already have);
  Atomic Red Team is attack *tests*, not detections. Both could enrich
  existing rule families later (e.g. "Test this detection" links on the
  rule detail page mapping MITRE technique → Atomic Red Team test), but
  aren't a new importer source.
- Sigma category-mapping heuristic is heavily skewed: ~1,440 of ~3,300
  imported rules landed in "Insider Threat & Anomalous Behavior" (the
  fallback bucket) and "Initial Access" has zero rules. Revisit the
  ATT&CK-tactic-tag → category lookup table in the Sigma importer to better
  distribute rules tagged with tactics like `attack.initial_access`,
  `attack.discovery`, etc.
- Re-import cadence: Sigma's `rules-emerging-threats/`/`rules-compliance/`
  (imported via `--include-emerging`) update frequently upstream. Consider a
  periodic re-import job or at least a documented manual cadence, plus a
  "what changed since last import" digest (diff on `rule_sources.sourceUrl` +
  content hash) so updates can be reviewed before overwriting local edits to
  imported rules. Same applies to Splunk's `develop` branch and any future
  Azure-Sentinel import.

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
