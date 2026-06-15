#!/usr/bin/env bash
# Starts Sentriq's production server. Run ./build.sh first if you haven't
# built the app yet (this script will offer to do so if .next/ is missing).
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f ".env.local" ]; then
  echo "No .env.local found - run ./build.sh first."
  exit 1
fi

if [ ! -d ".next" ]; then
  echo "No production build found - running ./build.sh first."
  ./build.sh
fi

npm run start
