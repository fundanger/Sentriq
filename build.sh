#!/usr/bin/env bash
# Builds Sentriq for production: installs dependencies, prepares the local
# environment/database, and runs the Next.js production build.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f ".env.local" ]; then
  echo "No .env.local found - creating one from .env.example"
  cp .env.example .env.local

  if grep -q '^ENCRYPTION_KEY=$' .env.local; then
    KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    sed -i.bak "s/^ENCRYPTION_KEY=$/ENCRYPTION_KEY=$KEY/" .env.local && rm -f .env.local.bak
  fi

  if grep -q '^AUTH_SECRET=$' .env.local; then
    SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    sed -i.bak "s/^AUTH_SECRET=$/AUTH_SECRET=$SECRET/" .env.local && rm -f .env.local.bak
  fi

  echo "Generated .env.local with random ENCRYPTION_KEY and AUTH_SECRET."
fi

echo "Installing dependencies..."
npm install

NEEDS_SEED=0
if [ ! -f "data/sentriq.db" ]; then
  NEEDS_SEED=1
fi

echo "Applying database schema..."
npm run db:push

if [ "$NEEDS_SEED" -eq 1 ]; then
  echo "Seeding database..."
  npm run db:seed
fi

echo "Building Sentriq..."
npm run build

echo "Build complete. Run ./start.sh to launch Sentriq."
