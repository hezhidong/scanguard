# ScanGuard Intake — Cloudflare Worker Deployment Guide

This guide is for the **operator of the public community feed** (currently
`hezhidong/scanguard`). End users installing the agent do **not** need to do any
of this — they just run `install.sh` and events flow automatically.

## Architecture

```
Agent (anyone's VPS, no token)
   │  POST /report  (JSON event)
   ▼
Cloudflare Worker (scanguard-intake)
   ├── validate public IP / fields
   ├── rate-limit by source IP (60/min, 2000/day)
   ├── buffer events in KV
   └── cron every 1 min → append to reports/community.jsonl via GitHub API
                    │
                    ▼
           hezhidong/scanguard repo
           (GitHub Actions → blocklist + dashboard)
```

---

## Step 1: Create a GitHub bot account

Why a separate account: if your main account is ever compromised or you lose
access, the bot token can be revoked independently. It also keeps the commit
history clean ("scanguard-bot appended N events" vs. your personal account).

1. Open a private/incognito window and go to https://github.com/signup
2. Create a new account, e.g. **`scanguard-bot`**
   - Use an email you control (can be an alias)
   - No need for a paid plan
3. Verify the email address
4. Log in as the bot account
5. Go to your main repo → **Settings → Collaborators** → **Add people**
6. Invite `scanguard-bot` with **Write** permission
7. Accept the invitation from the bot's email

## Step 2: Create a fine-grained PAT as the bot

1. While logged in as `scanguard-bot`, go to:
   **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**
2. Fill in:
   - **Token name:** `scanguard-intake-worker`
   - **Expiration:** 90 days (set a calendar reminder to rotate)
   - **Resource owner:** `scanguard-bot`
   - **Only select repositories** → `hezhidong/scanguard` (must first accept the invite above)
3. Under **Repository permissions**, set:
   - **Contents:** Read and write
   - (Leave everything else as "No access")
4. Click **Generate token** and copy the token immediately — it starts with
   `github_pat_...` and you won't see it again.

> ⚠️ This token lives inside the Cloudflare Worker as a secret. It can only
> read/write files in the one repo and nothing else. Rotate every 90 days.

## Step 3: Install Wrangler and deploy

You can run these steps on any machine with Node.js 18+ (your laptop, the
ai-agent server, etc. — only needed once for deploy, not for runtime).

```bash
# 1. Clone (or update) this repo
git clone https://github.com/hezhidong/scanguard.git
cd scanguard/intake

# 2. Install Wrangler (Cloudflare CLI)
npm install

# 3. Log in to Cloudflare (opens a browser)
npx wrangler login

# 4. Run the deploy script — it will:
#    - create the KV namespace
#    - ask for the GitHub PAT and set it as a Worker secret
#    - deploy the Worker
GITHUB_TOKEN=*** npx wrangler deploy
# ...follow the prompt to paste your PAT (input is hidden)
```

The script prints the Worker URL at the end, e.g.:

```
https://scanguard-intake.<your-subdomain>.workers.dev
```

### Manual alternative (if the script fails)

```bash
npx wrangler kv:namespace create EVENTS
# → copy the returned namespace_id into wrangler.toml

echo "github_pat_..." | npx wrangler secret put GITHUB_TOKEN
npx wrangler deploy
```

## Step 4: Test the endpoint

```bash
WORKER_URL="https://scanguard-intake.hezhidong.workers.dev"

# Health check
curl -s $WORKER_URL/healthz
# {"ok":true,"ts":"..."}

# Submit a test event
curl -s -X POST $WORKER_URL/report \
  -H 'content-type: application/json' \
  -d '{
    "ip": "203.0.113.42",
    "rule": "nginx-php-scanner",
    "severity": "high",
    "hits": 25,
    "node_id": "test-node",
    "node_name": "Test Node",
    "country": "US",
    "city": "Testville",
    "isp": "Test ISP"
  }'
# {"ok":true,"accepted":1,"rejected":0}
```

Wait ~60 seconds for the cron trigger, then check the repo:

```bash
curl -s "https://raw.githubusercontent.com/hezhidong/scanguard/master/reports/community.jsonl" | tail
```

The event should appear. Once the GitHub Actions workflow runs (every 10 min or
on push), the dashboard at https://hezhidong.github.io/scanguard/ updates.

## Step 5: Update the agent default endpoint

After confirming the Worker URL, update the default `community.endpoint` in:

1. `agent/scanguard/config.py` — `CommunityConfig.endpoint`
2. `install.sh` — `COMMUNITY_ENDPOINT` variable
3. This file (`docs/INTAKE_DEPLOY.md`)
4. Both READMEs

Then commit and push.

---

## Operations

### View logs

```bash
npx wrangler tail
```

### Rotate the GitHub token

1. Create a new PAT as the bot (Step 2)
2. Revoke the old one
3. Update the Worker secret:
   ```bash
   echo "github_pat_NEW..." | npx wrangler secret put GITHUB_TOKEN
   ```
   No redeploy needed.

### Update the Worker code

```bash
cd intake
# edit src/index.js
npx wrangler deploy
```

### KV storage

Buffered events are stored under two key prefixes:
- `buf:idx:<minute-bucket>` — array of event keys
- `buf:evt:<uuid>` — individual event JSON

Both have a 1-hour TTL. If the GitHub API is down for an extended period, events
buffer in KV (up to its size limit) and flush when the next scheduled run
succeeds.

### Rate limits

| Scope | Limit |
|---|---|
| Requests per source IP per minute | 60 |
| Events per source IP per day | 2,000 |
| Events per request body | 100 |
| Body size | 256 KB |

These can be changed at the top of `src/index.js`.

---

## Anti-poisoning safeguards

1. **Private/reserved IPs rejected** — 10.x, 172.16-31.x, 192.168.x, 127.x,
   169.254.x, CGNAT, multicast, ULA v6, etc.
2. **Field validation** — type/length checks on every field
3. **Rate limiting** — per source IP, minute and day
4. **2-node confirmation** — `scripts/aggregate.py` only adds community-sourced
   IPs to the public blocklist after **at least 2 distinct node_ids** report
   them. Single-node reports appear in `threats.json` as "pending" but are not
   distributed via `blocklist.*`. Reports from the operator's own nodes (where
   `source != "community"`, i.e. direct GitHub push) bypass this rule.
5. **Dedup** — same ip+rule from multiple events are merged: hits are summed,
   max severity is kept, distinct node count tracked.

---

## Troubleshooting

**Events aren't appearing in community.jsonl**
- Check `npx wrangler tail` for errors during the scheduled flush
- Confirm the token hasn't expired: `curl -H "Authorization: Bearer ***" https://api.github.com/user`
- Check KV has data: `npx wrangler kv:key list --binding EVENTS --prefix "buf:"`

**"rate limit exceeded" from the Worker**
- Your agent is posting too frequently. Check systemd timer isn't running every
  minute (it should be every 30 min). The rate limit is 60 requests/min per IP.

**403 from GitHub API in Worker logs**
- Bot was removed as collaborator, or token expired/revoked. Repeat Step 2 and
  update the secret.
