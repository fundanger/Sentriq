# Sentriq

Sentriq is an enterprise-grade threat detection and prevention rule library. It gives security teams a searchable, richly documented catalog of ~7,500 detection rules across eight SIEM/EDR/WAF/runtime languages, paired with an AI assistant for explaining, tuning, and drafting new rules — plus direct deployment and trigger-tracking integrations with major security platforms.

## Features

- **Multi-language rule library** — ~7,500 rules across KQL, Sigma, Splunk, YARA, Elastic, SentinelOne, Cloudflare, and Falco, browsable and filterable by language and category, with saved filter presets and full-text search.
- **14 MITRE ATT&CK-aligned categories** spanning recon through exfiltration, plus cloud/SaaS, insider threat, and CVE-driven coverage, covering 608 MITRE techniques and 13 CVEs.
- **Deeply documented rules** — each rule includes an attack-technique explanation, a walkthrough of the detection logic, false-positive/tuning guidance, MITRE ATT&CK technique mappings, and CVE/CVSS context where relevant.
- **Customizable dashboard** — drag-and-drop widgets (language/category/severity breakdowns, MITRE coverage, recent and recently-viewed rules, top-triggering rules, quick actions) with per-user layout persistence.
- **AI assistant (BYO LLM key)** — a context-aware chat drawer that knows the rule you're viewing, RAG-based search across the whole library, rule explanation/tuning suggestions, and one-click "Generate with AI" drafting for new rules.
- **Supported AI providers** — Anthropic, OpenAI, Google Gemini, DeepSeek, or any OpenAI-compatible endpoint. API keys are encrypted at rest (AES-256-GCM) and only decrypted server-side.
- **Platform integrations** — connect Microsoft Sentinel, Elastic Security, Splunk, SentinelOne, and Cloudflare to deploy rules directly from the library, track per-rule deployment status, and sync real-world trigger counts back into the dashboard.
- **Auth, roles & SSO** — Auth.js v5 session-based auth (local Credentials provider, plus OIDC SSO providers configured per-instance) with a 4-tier role model (`super_admin`, `admin`, `analyst`, `viewer`). Only `super_admin` can manage AI provider credentials, integrations, users, branding, and SSO.
- **Whitelabel branding** — super-admins can customize the site name, accent color, and logo at runtime.
- **Productivity tools** — keyboard shortcuts (`/` to search, `g r` to jump to the rule library, `Esc` to clear filters), saved filter presets, recently-viewed rules, and one-click rule body downloads.
- **Dark/light themes** with smooth, Motion-powered animations throughout.

## Tech stack

- [Next.js 16](https://nextjs.org) (App Router) + React 19 + TypeScript
- [Drizzle ORM](https://orm.drizzle.team) on SQLite (`better-sqlite3`), designed for a clean swap to Postgres later
- [shadcn/ui](https://ui.shadcn.com) (Base UI primitives) + Tailwind CSS v4
- [Auth.js v5](https://authjs.dev) (Credentials provider + dynamic OIDC SSO providers + Drizzle adapter)
- [Motion](https://motion.dev) for animation, [Zod](https://zod.dev) for validation, [recharts](https://recharts.org) for dashboard charts, [@dnd-kit](https://dndkit.com) for dashboard drag-reorder
- AES-256-GCM encryption for stored LLM API keys and platform integration credentials

## Getting started

### Prerequisites

- Node.js 20+
- npm

### Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create your local environment file:

   ```bash
   cp .env.example .env.local
   ```

   Then fill in `.env.local`:
   - `DATABASE_PATH` — defaults to `./data/sentriq.db` (SQLite, gitignored)
   - `ENCRYPTION_KEY` — 32-byte hex key for encrypting stored LLM API keys and integration credentials. Generate with:
     ```bash
     node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
     ```
   - `AUTH_SECRET` — Auth.js session secret. Generate the same way.

3. Push the database schema and seed initial data (categories, MITRE techniques, CVEs, and the seed rule library):

   ```bash
   npm run db:push
   npm run db:seed
   ```

4. Start the dev server:

   ```bash
   npm run dev
   ```

   Open [http://localhost:3000](http://localhost:3000).

### First login

The seed script creates a break-glass admin account:

- **Email:** `admin@sentriq.local`
- **Password:** `password`

You'll be forced to set a new password on first login. This account is `super_admin` and can manage AI providers, platform integrations, users, SSO, and branding.

### Importing additional rule sources

Beyond the seeded rule library, Sentriq can bulk-import rules from third-party repositories via a pluggable importer framework (`src/db/seed/importers/`). Each importer is registered under an id and run via:

```bash
npm run db:import -- <id>
```

| id | Source | License | Imported rules |
| --- | --- | --- | --- |
| `sigma` | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (`rules/` + `rules-threat-hunting/`) | DRL-1.1 | ~3,268 |
| `splunk` | [splunk/security_content](https://github.com/splunk/security_content) | Apache-2.0 | ~2,056 |
| `azure-sentinel` | [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) (KQL analytic rules) | MIT | ~2,001 |
| `falco` | [falcosecurity/rules](https://github.com/falcosecurity/rules) | Apache-2.0 | ~93 |
| `yara` | [0xN0n4m3d3v/kit-shell](https://github.com/0xN0n4m3d3v/kit-shell) (YARA core rules) | CC0-1.0 | ~53 |
| `cloudflare` | [mintyYuki/cf-waf-ruleset](https://github.com/mintyYuki/cf-waf-ruleset) | MIT | ~4 |

For `sigma`, pass `--include-emerging` to also import `rules-emerging-threats/` and `rules-compliance/` (these update frequently upstream — re-run periodically to pick up changes). All imports are idempotent: re-running skips rules already present. Imported rules show a "Source & attribution" block on their detail page crediting the upstream project, original author, and license.

For a Docker deployment, run the import inside the container against the persistent volume:

```bash
docker compose exec sentriq npm run db:import -- sigma
```

To add a new rule source, implement the `RuleImporter` interface in a new module under `src/db/seed/importers/` and register it in `registry.ts` — the shared runner handles idempotent inserts, MITRE technique pre-seeding, and attribution tracking.

### AI features

AI chat, rule explanation/tuning, generation, and RAG search require an LLM provider key. Configure one under **Settings → AI** with any supported provider (Anthropic, OpenAI, Gemini, DeepSeek, or an OpenAI-compatible endpoint). After saving a key, run:

```bash
npm run db:embed
```

to generate embeddings for the rule library so RAG search returns results immediately. The script runs with bounded concurrency and retries on rate limits, and is resumable — it only embeds rules that don't yet have an embedding. With the full rule library (~7,500 rules), this will take a while and consume API credits; RAG search degrades gracefully (falls back to fewer/no matches) for rules that aren't yet embedded. Pass `--force` to re-embed every rule (e.g. after switching embedding models).

> **Note:** DeepSeek has no embeddings API, so RAG/library-search context is unavailable when DeepSeek is the configured provider — chat and generation still work.

### Platform integrations

Super admins can connect external platforms under **Settings → Integrations**:

- **Microsoft Sentinel**, **Elastic Security**, **Splunk**, **SentinelOne**, **Cloudflare**

Once connected, each rule's detail page gets a **Deployments** tab for deploying, redeploying, or removing that rule on any connected, language-compatible integration. **Settings → Integrations** also lets you sync trigger counts (how often each deployed rule has fired) — Sentinel pulls from a Log Analytics query against `SecurityIncident`, Cloudflare via its GraphQL Analytics API — which then power the dashboard's "Top triggering rules" widget.

### Single sign-on (SSO)

Super admins can register OIDC identity providers under **Settings → SSO** (`/settings/sso`): display name, issuer URL, client ID/secret (encrypted), an optional groups claim with a `group = role` mapping, and a default role for unmapped users. New providers start disabled so you can verify the callback URL (`/api/auth/callback/sso-<id>`) with your IdP before enabling. Once enabled, the provider appears as a login option alongside local email/password.

## Deploying to production

### Option 1: Standalone build (no Docker)

`build.sh` (Linux/macOS) / `build.bat` (Windows) install dependencies, generate `.env.local` with random secrets if missing, push/seed the database on first run, and produce a Next.js `output: standalone` build with `public/` and static assets copied into `.next/standalone/`:

```bash
./build.sh      # or build.bat on Windows
./start.sh      # or start.bat on Windows
```

`start.sh`/`start.bat` load `.env.local` into the process environment and run `node .next/standalone/server.js` directly (plain `next start` is not supported with `output: standalone`). Re-run the build script after pulling new code or changing the schema.

### Option 2: Docker

Sentriq ships with a multi-stage `Dockerfile` and `docker-compose.yml` for running as a single self-contained container — suitable for local hosting or a public-facing deployment on a VPS, Fly.io, Railway, etc. The SQLite database lives on a persistent volume (`sentriq-data`).

1. Create `.env.local` from `.env.example` and fill in `ENCRYPTION_KEY` and `AUTH_SECRET` (see above). For a public deployment, also set `AUTH_URL` to your public URL (e.g. `https://sentriq.example.com`).

2. Build and start the container:

   ```bash
   docker compose --env-file .env.local up -d --build
   ```

3. Initialize the database (first run only — runs inside the container against the persistent volume):

   ```bash
   docker compose exec sentriq npm run db:push
   docker compose exec sentriq npm run db:seed
   ```

4. Open [http://localhost:3000](http://localhost:3000) (or your configured `AUTH_URL`).

### Production hardening notes

- **Change the break-glass admin password immediately** — the forced first-run flow handles this, but don't leave a freshly seeded instance reachable on the public internet before logging in.
- **Put the deployment behind HTTPS** (a reverse proxy like Caddy, Traefik, or nginx, or your hosting platform's built-in TLS termination). `trustHost` is enabled so Auth.js will trust the proxy's forwarded host/protocol headers.
- **Back up the database** (`data/sentriq.db`, or the `sentriq-data` volume in Docker) — it contains rules, users, and encrypted API keys/integration credentials.
- Login and AI chat endpoints are rate-limited per-IP/per-user out of the box (in-memory, suitable for a single instance).

## Scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Start the development server |
| `npm run build` | Build for production |
| `npm run start` | Start the production server (`next start`; for `output: standalone` use `start.sh`/`start.bat` instead) |
| `npm run lint` | Run ESLint |
| `npm run db:generate` | Generate Drizzle migrations from schema changes |
| `npm run db:push` | Push the current schema to the SQLite database |
| `npm run db:seed` | Seed categories, MITRE techniques, CVEs, and the rule library |
| `npm run db:import -- <id>` | Bulk-import rules from a registered source (e.g. `sigma`) |
| `npm run db:embed` | Generate RAG embeddings for rules missing one (requires a configured AI provider; `--force` re-embeds all) |

## Project structure

```
src/
  app/            Next.js App Router pages (auth, dashboard, rules, settings)
  actions/        Server Actions (rule CRUD, AI generation, integrations, SSO, settings, auth)
  components/     UI components (rules, dashboard, AI chat, layout, shadcn/ui primitives)
  lib/            Auth config, crypto helpers, AI provider adapters, RAG, platform integration adapters
  db/             Drizzle schema and seed/import data
```
