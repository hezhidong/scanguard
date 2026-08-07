# 🛡️ ScanGuard

**English** | [简体中文](README.zh-CN.md)


ScanGuard is a self-hosted, **open-source scanner detection & threat-intel
platform**. It watches your web/auth logs for scanners and brute-forcers, blocks
them at the firewall, and optionally reports every attacker to a **public GitHub
repository** that aggregates malicious IPs into a community blocklist served
over GitHub Pages — no central server required.

## Architecture

```
┌─────────────┐    commits events     ┌──────────────────────┐
│ Agent (VPS) │ ─────────────────────▶│ GitHub repo          │
│  - scan logs│   Contents API + PAT  │  reports/<node>.jsonl│
│  - block IP │                       │                      │
└─────────────┘                       │  GitHub Actions:     │
┌─────────────┐    commits events     │   aggregate.py       │
│ Agent (VPS) │ ─────────────────────▶│         ↓            │
└─────────────┘                       │  blocklist.{txt,     │
                                      │    iptables,nft}     │
                                      │  stats.json          │
                                      │  threats.json        │
                                      └──────────┬───────────┘
                                                 │ GitHub Pages
                                                 ▼
                          https://hezhidong.github.io/scanguard/
                          ├─ /             (dashboard)
                          ├─ /blocklist.txt
                          ├─ /blocklist.iptables
                          └─ /blocklist.nftables
```

Any machine can consume the blocklist:
```bash
curl -s https://hezhidong.github.io/scanguard/blocklist.iptables | sudo iptables-restore
```

## Repository layout

```
scanguard/
├── agent/        # ScanGuard Agent — log detection + auto-block (runs on each host)
├── api/          # Optional self-hosted FastAPI central (legacy, not needed for GitHub mode)
├── web/          # Static dashboard (built to repo root by Actions, served via Pages)
├── scripts/      # aggregate.py (CI: reports/* → blocklist + stats)
├── reports/      # Per-node jsonl event files (committed by agents)
├── install.sh    # One-shot agent installer (see Quick Start below)
└── .github/workflows/aggregate.yml
```

---

## 1. ScanGuard Agent

A single Python package (`scanguard`) that:

- tails **local or remote (SSH)** nginx/apache/auth logs (plain or `.gz`)
- applies configurable regex **detection rules** with threshold + sliding window
- blocks offenders through a pluggable firewall backend:
  **iptables · nftables · ufw · firewalld** (local or over SSH)
- enriches IPs with **geolocation** (ip-api, cached)
- keeps persistent state (never double-blocks), writes a notify file for chat bots
- optionally **reports every block to a public GitHub repo** (the new default)
  or to a self-hosted HTTP API

### Quick start (one command)

The install script downloads the agent, installs Python deps, generates
`/etc/scanguard/config.yaml`, saves your GitHub token, and installs a systemd
timer that runs every 30 minutes — all in one shot:

```bash
github_pat=your…_XX  # fine-grained PAT, see note below

curl -fsSL https://raw.githubusercontent.com/hezhidong/scanguard/master/install.sh \
  | sudo SG_GITHUB_TOKEN=*** bash
```

That's it. The timer starts immediately. Verify:

```bash
systemctl status scanguard.timer
sudo journalctl -u scanguard.service -n 50
```

**Custom node id / firewall backend / log paths:**

```bash
curl -fsSL https://raw.githubusercontent.com/hezhidong/scanguard/master/install.sh \
  | sudo SG_GITHUB_TOKEN=*** \
       SG_NODE_ID=web-01 SG_NODE_NAME="Web Server 01" \
       SG_FIREWALL=nftables \
       SG_WHITELIST=127.0.0.1,::1,203.0.113.10 \
       bash
```

| Variable | Default | Purpose |
|---|---|---|
| `SG_GITHUB_TOKEN` | _prompts_ | Fine-grained PAT with Contents: Read&write on this repo |
| `SG_NODE_ID` | `$(hostname)` | Unique id → `reports/<node_id>.jsonl` |
| `SG_NODE_NAME` | same as node id | Human-readable node label shown in dashboard |
| `SG_FIREWALL` | `iptables` | `iptables` / `nftables` / `ufw` / `firewalld` |
| `SG_LOG_PATHS` | `/var/log/nginx/access.log,/var/log/nginx/access.log.1` | Comma-separated nginx access logs |
| `SG_WHITELIST` | `127.0.0.1,::1` | Comma-separated IPs/CIDRs that must never be blocked |
| `SG_INSTALL_DIR` | `/opt/scanguard` | Where the agent code lives |
| `SG_SKIP_SYSTEMD` | `0` | Set `1` in containers / non-systemd hosts |

> **No token on the command line?** Just run `sudo bash install.sh` and it will
> prompt for the token interactively (input hidden).

#### How to create the GitHub token

1. GitHub → **Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. **Only select repositories** → `scanguard`
3. Repository permissions → **Contents: Read and write**
4. Expiration: 90 days (rotate periodically)

> **Privacy:** reports contain only IP / rule / severity / hit count / geo /
> node metadata. No full URLs, query strings, or request evidence are uploaded.

### Manual install (if you prefer to do it by hand)

```bash
cd agent
pip install -r requirements.txt
sudo mkdir -p /etc/scanguard /var/lib/scanguard
sudo cp ../examples/config.example.yaml /etc/scanguard/config.yaml
sudo $EDITOR /etc/scanguard/config.yaml
```

Save the token to `/etc/scanguard/github_token` (chmod 600), then enable the
timer:

```bash
sudo cp agent/packaging/scanguard.service agent/packaging/scanguard.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scanguard.timer
```

### Firewall backends

| Backend    | Persistence             | Notes                                   |
|------------|-------------------------|-----------------------------------------|
| iptables   | netfilter-persistent    | default; works on most Linux hosts      |
| nftables   | /etc/nftables.conf      | uses a `scanguard_blocklist` inet set   |
| ufw        | —                       | `ufw deny/reject from <ip>`             |
| firewalld  | permanent ipset         | `firewall-cmd --ipset` + reload         |

Each backend can act **locally** or **on a remote host over SSH** (set
`firewall.host/user/key`), so one agent can block at a perimeter/gateway box.

---

## 2. Central aggregation (GitHub Actions)

The workflow `.github/workflows/aggregate.yml` runs every 10 minutes (and on
every push to `reports/`). It calls `scripts/aggregate.py`, which:

1. reads every `reports/*.jsonl`
2. aggregates events by IP (takes max severity, sums hits, collects nodes/rules)
3. writes:
   - `blocklist.txt` / `blocklist.iptables` / `blocklist.nftables`
   - `stats.json` (top counters for the dashboard)
   - `threats.json` (full aggregated IP list)
   - copies `web/index.html` to repo root
4. commits the result back to the repo

The blocklist includes only IPs with severity **high or critical**.

### Enable GitHub Pages

After the first Actions run completes:

1. Repo **Settings → Pages**
2. Source: **Deploy from a branch**
3. Branch: **master** / **/ (root)**
4. Save. The dashboard goes live at
   `https://hezhidong.github.io/scanguard/` in ~1 minute.

---

## 3. Web dashboard

A single static HTML page (`web/index.html`) that loads `stats.json` +
`threats.json` and renders:

- global counters (IPs, severity breakdown, reporting nodes, events)
- top countries / rules bar charts
- searchable, sortable table
- per-IP detail modal with recent activity timeline
- one-click `iptables` block command copy

No backend, no JS frameworks, works on GitHub Pages directly.

---

## 4. Blocklist subscription

```bash
# plain list (one IP per line)
curl https://hezhidong.github.io/scanguard/blocklist.txt

# iptables-restore format
curl https://hezhidong.github.io/scanguard/blocklist.iptables | sudo iptables-restore

# nftables
curl https://hezhidong.github.io/scanguard/blocklist.nftables | sudo nft -f -
```

Cron it every few hours and you've got a community-powered firewall.

---

## Detection rules (examples)

```yaml
rules:
  - name: php-scanner
    pattern: '\.(php|asp|aspx|env|git|jsp|cgi)(\?|$| )'
    threshold: 20
    window_minutes: 30
    severity: high
  - name: path-traversal
    pattern: '(\.\./|/etc/passwd|phpMyAdmin|/\.aws/credentials)'
    threshold: 5
    window_minutes: 30
    severity: critical
  - name: ssh-bruteforce
    pattern: 'Failed password|Invalid user|authentication failure'
    threshold: 5
    window_minutes: 10
    severity: high
```

---

## Optional: self-hosted central API (legacy)

If you'd rather not use GitHub, a FastAPI service in `api/` accepts reports and
serves the blocklist. See `api/README` in the source for setup. The agent
supports it via `backend: http`.

---

## Security notes

- **Whitelist your own IPs and monitoring ranges.** A misconfigured rule can block you.
- Run the agent as root (it needs firewall access); the API needs no root.
- Use SSH keys for remote log/firewall targets; password auth needs `sshpass`.
- The GitHub PAT only needs **Contents: Read and write** on the single repo.
  Rotate it regularly. Revoke immediately if a host is compromised.
- `ip-api` free tier is non-commercial and rate-limited; swap the `geo`
  provider for a paid one at scale.

## License

MIT — see [LICENSE](LICENSE).
