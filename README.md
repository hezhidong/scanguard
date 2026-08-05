# 🛡️ ScanGuard

ScanGuard is a self-hosted, **open-source scanner detection & threat-intel
platform**. It watches your web/auth logs for scanners and brute-forcers, blocks
them at the firewall, and optionally reports every attacker to a central API that
aggregates malicious IPs into a public, subscriptable blocklist.

It has four parts:

```
scanguard/
├── agent/        # ScanGuard Agent — log detection + auto-block (runs on each host)
├── api/          # Central Threat Intel API — ingest, dedup, aggregate (FastAPI)
├── web/          # Web UI — public malicious-IP profiles + search
└── blocklist/    # blocklist subscription (served by the API: txt/iptables/nftables)
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
- optionally **reports every block** to the Central Threat Intel API

### Install & run

```bash
cd agent
pip install -r requirements.txt
sudo mkdir -p /etc/scanguard /var/lib/scanguard
sudo cp ../examples/config.example.yaml /etc/scanguard/config.yaml
sudo $EDITOR /etc/scanguard/config.yaml          # add servers, rules, whitelist
sudo python3 -m scanguard -c /etc/scanguard/config.yaml --dry-run --print
sudo python3 -m scanguard -c /etc/scanguard/config.yaml --print
```

### Schedule (systemd timer, every 30 min)

```bash
sudo cp packaging/scanguard.service packaging/scanguard.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scanguard.timer
```

### Firewall backends

| Backend    | Persistence | Notes                                         |
|------------|-------------|-----------------------------------------------|
| iptables   | ✅ netfilter-persistent | default; works on most Linux hosts            |
| nftables   | ✅ /etc/nftables.conf    | uses a `scanguard_blocklist` inet set         |
| ufw        | —           | `ufw deny/reject from <ip>`                   |
| firewalld  | ✅ permanent ipset       | `firewall-cmd --ipset` + reload               |

Each backend can act **locally** or **on a remote host over SSH** (set
`firewall.host/user/key`), so one agent can block at a perimeter/gateway box.

---

## 2. Central Threat Intel API

A FastAPI service that receives blocks from every agent, de-duplicates by IP,
and aggregates evidence across nodes.

```bash
cd api
pip install -r requirements.txt
export SCANGUARD_DB=/var/lib/scanguard-api/threats.db
export SCANGUARD_API_TOKEN=changeme       # bearer token agents must send
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Endpoints:

| Method | Path                         | Purpose                            |
|--------|------------------------------|------------------------------------|
| POST   | `/api/report`                | Agent reports one blocked IP       |
| POST   | `/api/report/batch`          | Batch ingest                       |
| GET    | `/api/threats`               | Search/list (q, severity, country) |
| GET    | `/api/threats/{ip}`          | Full profile: events + nodes       |
| GET    | `/api/stats`                 | Summary counters                   |
| GET    | `/blocklist.txt`             | Plain-IP subscription              |
| GET    | `/blocklist.iptables`        | iptables-restore format            |
| GET    | `/blocklist.nftables`        | nftables ruleset                   |

Set `min_severity=high|critical` on blocklist URLs to tune aggressiveness.

---

## 3. Web UI

Served automatically at `/` by the API (static files in `web/`). Shows:

- global stats (IPs, severity breakdown, reporting nodes)
- searchable table of malicious IPs with country/ISP/hit count/nodes/rules
- a per-IP detail modal: geolocation, attack timeline, reporting nodes, evidence

### Point a node at the API

In each agent's `config.yaml`:

```yaml
central:
  enabled: true
  url: https://threat.example.com
  node_id: web-nyc-01
  node_name: NYC Web 01
  token: changeme
```

---

## 4. Blocklist subscription

Users who don't run the agent can still consume the aggregated blocklist:

```bash
# plain list
curl https://threat.example.com/blocklist.txt?min_severity=high

# iptables-restore format
curl https://threat.example.com/blocklist.iptables?min_severity=high | sudo iptables-restore

# nftables
curl https://threat.example.com/blocklist.nftables?min_severity=high | sudo nft -f -
```

Cron it to pull every few hours and you've got a community-powered firewall.

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
  - name: ssh-bruteforce      # for kind: auth sources
    pattern: 'Failed password|Invalid user'
    threshold: 5
    window_minutes: 10
    severity: high
```

---

## Security notes

- **Whitelist your own IPs and monitoring ranges.** A misconfigured rule can block you.
- Run the agent as root (it needs firewall access); the API needs no root.
- Use SSH keys for remote log/firewall targets; password auth needs `sshpass`.
- `ip-api` free tier is HTTP-only, non-commercial, and rate-limited; swap the
  `geo` provider for a paid one if you run at scale.

## License

MIT — see [LICENSE](LICENSE).
