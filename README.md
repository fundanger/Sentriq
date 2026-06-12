# Sentriq

Sentriq is an enterprise-grade threat detection and prevention rule library. It gives security teams a searchable, richly documented catalog of detection rules across seven SIEM/EDR/WAF languages, paired with an AI assistant for explaining, tuning, and drafting new rules.

## Features

- **Multi-language rule library** — KQL, Sigma, SentinelOne, Cloudflare, Splunk, YARA, and Elastic, browsable and filterable by language and category.
- **14 MITRE ATT&CK-aligned categories** spanning recon through exfiltration, plus cloud/SaaS, insider threat, and CVE-driven coverage.
- **Deeply documented rules** — each rule includes an attack-technique explanation, a walkthrough of the detection logic, false-positive/tuning guidance, MITRE ATT&CK technique mappings, and CVE/CVSS context where relevant.
- **AI assistant (BYO LLM key)** — context-aware chat that knows the rule you're viewing, RAG-based search across the whole library, rule explanation/tuning suggestions, and one-click "Generate with AI" drafting for new rules.
- **Supported AI providers** — Anthropic, OpenAI, Google Gemini, DeepSeek, or any OpenAI-compatible endpoint. API keys are encrypted at rest (AES-256-GCM) and only decrypted server-side.
- **Auth & roles** — session-based local auth (Auth.js Credentials provider) with `admin`, `analyst`, and `viewer` roles, plus an SSO scaffold for future OIDC/SAML integration.
- **Dark/light themes** with smooth, Motion-powered animations throughout.

## Tech stack

- [Next.js 16](https://nextjs.org) (App Router) + React 19 + TypeScript
- [Drizzle ORM](https://orm.drizzle.team) on SQLite (`better-sqlite3`), designed for a clean swap to Postgres later
- [shadcn/ui](https://ui.shadcn.com) (Base UI primitives) + Tailwind CSS v4
- [Auth.js v5](https://authjs.dev) (Credentials provider + Drizzle adapter)
- [Motion](https://motion.dev) for animation, [Zod](https://zod.dev) for validation
- AES-256-GCM encryption for stored LLM API keys

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
   - `ENCRYPTION_KEY` — 32-byte hex key for encrypting stored LLM API keys. Generate with:
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

You'll be forced to set a new password on first login.

### Importing additional rule sources

Beyond the seeded rule library, Sentriq can bulk-import rules from third-party repositories via a pluggable importer framework (`src/db/seed/importers/`). The first importer pulls the full [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) ruleset (~3,000+ rules, `rules/` + `rules-threat-hunting/`):

```bash
npm run db:import -- sigma
```

Pass `--include-emerging` to also import `rules-emerging-threats/` and `rules-compliance/` (these update frequently upstream — re-run periodically to pick up changes). The import is idempotent: re-running it skips rules already present. Imported rules show a "Source & attribution" block on their detail page crediting the upstream project, original author, and license (Sigma rules are under SigmaHQ's Detection Rule License 1.1).

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

to generate embeddings for the rule library so RAG search returns results immediately. The script runs with bounded concurrency and retries on rate limits, and is resumable — it only embeds rules that don't yet have an embedding. With the full Sigma import (~3,300 rules total), this will take a while and consume API credits; RAG search degrades gracefully (falls back to fewer/no matches) for rules that aren't yet embedded. Pass `--force` to re-embed every rule (e.g. after switching embedding models).

## Deploying with Docker

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
- **Put the container behind HTTPS** (a reverse proxy like Caddy, Traefik, or nginx, or your hosting platform's built-in TLS termination). `trustHost` is enabled so Auth.js will trust the proxy's forwarded host/protocol headers.
- **Back up the `sentriq-data` volume** — it contains the SQLite database (rules, users, encrypted API keys).
- Login and AI chat endpoints are rate-limited per-IP/per-user out of the box (in-memory, suitable for a single instance).

## Scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Start the development server |
| `npm run build` | Build for production |
| `npm run start` | Start the production server |
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
  actions/        Server Actions (rule CRUD, AI generation, settings, auth)
  components/     UI components (rules, AI chat, layout, shadcn/ui primitives)
  lib/            Auth config, crypto helpers, AI provider adapters, RAG
  db/             Drizzle schema and seed data
```
