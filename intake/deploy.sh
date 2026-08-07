#!/usr/bin/env bash
# =============================================================================
# ScanGuard Intake — one-shot Cloudflare Worker deployment
#
# Prerequisites:
#   1. A Cloudflare account (free)
#   2. A GitHub fine-grained PAT with Contents: Read&write on the target repo
#
# Usage:
#   GITHUB_TOKEN=*** bash deploy.sh
#
# Or it will prompt for the token if not set.
# =============================================================================
set -euo pipefail

c_green=$'\033[0;32m'; c_yellow=$'\033[0;33m'; c_red=$'\033[0;31m'; c_off=$'\033[0m'
info()  { printf "%s[+]%s %s\n" "$c_green" "$c_off" "$*"; }
warn()  { printf "%s[!]%s %s\n" "$c_yellow" "$c_off" "$*"; }
error() { printf "%s[x]%s %s\n" "$c_red" "$c_off" "$*" >&2; }
die()   { error "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── 1. Check Node + npm ────────────────────────────────────────────────────
command -v node >/dev/null 2>&1 || die "Node.js is required (v18+). Install from https://nodejs.org"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[[ "$NODE_MAJOR" -ge 18 ]] || die "Node.js v18+ required, got v$(node -p 'process.versions.node')"
info "Node $(node -p 'process.versions.node') found"

# ── 2. Install wrangler ────────────────────────────────────────────────────
if ! command -v npx >/dev/null 2>&1; then
  die "npx not found. Install Node.js from https://nodejs.org"
fi
info "Installing wrangler..."
npm install --silent 2>/dev/null || npm install
WRANGLER="npx wrangler"

# ── 3. Cloudflare login ────────────────────────────────────────────────────
info "Checking Cloudflare authentication..."
if ! $WRANGLER whoami >/dev/null 2>&1; then
  echo ""
  echo "  A browser window will open for Cloudflare login."
  echo "  If this is a headless server, run locally instead and copy wrangler.toml + KV id."
  echo ""
  $WRANGLER login
fi
$WRANGLER whoami

# ── 4. Create KV namespace ─────────────────────────────────────────────────
info "Creating KV namespace (idempotent)..."
KV_OUTPUT=$($WRANGLER kv:namespace create EVENTS 2>&1) || true
KV_ID=""
if echo "$KV_OUTPUT" | grep -q 'id = "'; then
  KV_ID="$(echo "$KV_OUTPUT" | grep -oP 'id = "\K[^"]+')"
  info "KV namespace created: $KV_ID"
else
  # May already exist — try to list and find it
  KV_ID="$($WRANGLER kv:namespace list 2>/dev/null | python3 -c "
import json,sys
for ns in json.load(sys.stdin):
    if ns['title'] == 'scanguard-intake-EVENTS':
        print(ns['id']); break
" 2>/dev/null || true)"
  if [[ -n "$KV_ID" ]]; then
    info "KV namespace already exists: $KV_ID"
  else
    die "Could not create or find KV namespace. Output:\n$KV_OUTPUT"
  fi
fi

# Update wrangler.toml with the real KV id
sed -i "s/REPLACE_WITH_KV_NAMESPACE_ID/$KV_ID/" wrangler.toml
info "wrangler.toml updated with KV id"

# ── 5. Set GitHub token secret ─────────────────────────────────────────────
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  printf "%s[?]%s Paste your GitHub fine-grained PAT (Contents: Read&write): " "$c_yellow" "$c_off"
  read -rs GITHUB_TOKEN
  echo
  [[ -n "$GITHUB_TOKEN" ]] || die "No token provided."
fi
info "Setting GITHUB_TOKEN as a Worker secret..."
echo "$GITHUB_TOKEN" | $WRANGLER secret put GITHUB_TOKEN

# ── 6. Deploy ──────────────────────────────────────────────────────────────
info "Deploying Worker..."
DEPLOY_OUT=$($WRANGLER deploy 2>&1)
echo "$DEPLOY_OUT"
WORKER_URL=$(echo "$DEPLOY_OUT" | grep -oP 'https://[a-z0-9-]+\.workers\.dev' | head -1 || true)

# ── 7. Test ────────────────────────────────────────────────────────────────
if [[ -n "$WORKER_URL" ]]; then
  info "Worker deployed at: $WORKER_URL"
  echo ""
  info "Testing healthz..."
  sleep 2
  curl -fsSL "$WORKER_URL/healthz" && echo ""
  echo ""
  info "Done! The Worker flushes buffered events to GitHub every minute (cron trigger)."
  info "Submit test event manually:"
  echo "    curl -X POST $WORKER_URL/report -H 'content-type: application/json' \\"
  echo "      -d '{\"ip\":\"203.0.113.99\",\"rule\":\"nginx-php-scanner\",\"node_id\":\"test\",\"node_name\":\"Test Node\",\"hits\":20}'"
  info "Dashboard: https://dash.cloudflare.com → Workers & Pages → scanguard-intake"
else
  warn "Could not auto-detect Worker URL. Check deployment output above."
fi
