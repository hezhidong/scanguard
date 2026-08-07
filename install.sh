#!/usr/bin/env bash
# =============================================================================
# ScanGuard Agent - one-shot installer
#
# Quick start (community reporting, zero config):
#   curl -fsSL https://raw.githubusercontent.com/hezhidong/scanguard/master/install.sh | sudo bash
#
# With a custom node id:
#   curl -fsSL https://raw.githubusercontent.com/hezhidong/scanguard/master/install.sh \
#     | sudo SG_NODE_ID=web-01 SG_NODE_NAME="Web Server 01" bash
#
# To also run your own dashboard on a personal fork:
#   curl -fsSL https://raw.githubusercontent.com/hezhidong/scanguard/master/install.sh \
#     | sudo SG_NODE_ID=web-01 \
#       SG_REPO=yourname/scanguard \
#       SG_GITHUB_TOKEN=*** bash
#
# To opt out of community reporting (local blocking only):
#   curl -fsSL .../install.sh | sudo SG_COMMUNITY_ENABLED=0 bash
#
# All env vars are optional.
# =============================================================================

set -euo pipefail

REPO="${SG_REPO:-hezhidong/scanguard}"
BRANCH="${SG_BRANCH:-master}"
NODE_ID="${SG_NODE_ID:-$(hostname)}"
NODE_NAME="${SG_NODE_NAME:-$NODE_ID}"

# Community endpoint (public intake, no token required)
COMMUNITY_ENABLED="${SG_COMMUNITY_ENABLED:-1}"
COMMUNITY_ENDPOINT="${SG_COMMUNITY_ENDPOINT:-https://scanguard-intake.hezhidong.workers.dev/report}"

# Optional GitHub PAT (only needed if user wants to push to their own fork)
GITHUB_TOKEN="${SG_G…N:-}"

FIREWALL_BACKEND="${SG_FIREWALL:-iptables}"
LOG_PATHS_CSV="${SG_LOG_PATHS:-/var/log/nginx/access.log,/var/log/nginx/access.log.1}"
WHITELIST_CSV="${SG_WHITELIST:-127.0.0.1,::1}"
INSTALL_DIR="${SG_INSTALL_DIR:-/opt/scanguard}"
SKIP_SYSTEMD="${SG_SKIP_SYSTEMD:-0}"

CONFIG_DIR=/etc/scanguard
STATE_DIR=/var/lib/scanguard
TOKEN_FILE="$CONFIG_DIR/github_token"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
SERVICE_FILE=/etc/systemd/system/scanguard.service
TIMER_FILE=/etc/systemd/system/scanguard.timer

c_green=$'\033[0;32m'; c_yellow=$'\033[0;33m'; c_red=$'\033[0;31m'; c_cyan=$'\033[0;36m'; c_off=$'\033[0m'
info()  { printf "%s[+]%s %s\n" "$c_green" "$c_off" "$*"; }
warn()  { printf "%s[!]%s %s\n" "$c_yellow" "$c_off" "$*"; }
error() { printf "%s[x]%s %s\n" "$c_red" "$c_off" "$*" >&2; }
die()   { error "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Please run as root (use sudo)."

for cmd in python3 curl tar; do
  command -v "$cmd" >/dev/null 2>&1 || die "Missing dependency: $cmd"
done

PIP=""
for candidate in pip3 pip; do
  if command -v "$candidate" >/dev/null 2>&1; then PIP="$candidate"; break; fi
done
if [[ -z "$PIP" ]]; then
  if python3 -m pip --version >/dev/null 2>&1; then
    PIP="python3 -m pip"
  else
    die "pip is required. Install it first (e.g. apt install python3-pip)."
  fi
fi

command -v systemctl >/dev/null 2>&1 || SKIP_SYSTEMD=1

# ── 1. Download agent code ────────────────────────────────────────────────
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
TARBALL="$TMPDIR/scanguard.tar.gz"
URL="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"
info "Downloading $URL ..."
curl -fsSL --max-time 60 -o "$TARBALL" "$URL"

mkdir -p "$INSTALL_DIR"
tar -xzf "$TARBALL" -C "$TMPDIR"
SRC_DIR="$(find "$TMPDIR" -maxdepth 2 -type d -name agent | head -1)"
[[ -n "$SRC_DIR" ]] || die "Archive layout unexpected (no agent/ dir)."
rm -rf "$INSTALL_DIR/scanguard" "$INSTALL_DIR/packaging" "$INSTALL_DIR/requirements.txt"
cp -r "$SRC_DIR"/* "$INSTALL_DIR"/
chmod -R a+rX "$INSTALL_DIR"

# ── 2. Python dependencies ────────────────────────────────────────────────
info "Installing Python dependencies..."
$PIP install -q -r "$INSTALL_DIR/requirements.txt"

# ── 3. Config dir + optional token ────────────────────────────────────────
info "Creating $CONFIG_DIR and $STATE_DIR ..."
mkdir -p "$CONFIG_DIR" "$STATE_DIR"
chmod 700 "$CONFIG_DIR"

# GitHub token is OPTIONAL — only needed when central.enabled=true (self-hosted fork).
# If SG_GITHUB_TOKEN was provided, save it. If an existing token file exists, reuse it.
# Otherwise central reporting is disabled and only community reporting is used.
if [[ -n "$GITHUB_TOKEN" ]]; then
  printf '%s' "$GITHUB_TOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  info "GitHub token saved to $TOKEN_FILE (for self-hosted fork reporting)"
elif [[ -f "$TOKEN_FILE" && -s "$TOKEN_FILE" ]]; then
  info "Reusing existing token from $TOKEN_FILE"
  GITHUB_TOKEN="$(cat "$TOKEN_FILE")"
else
  info "No GitHub token provided — community reporting is enabled, self-hosted fork is off."
  info "  (Set SG_GITHUB_TOKEN later if you want your own dashboard.)"
fi

# ── 4. Generate config.yaml ───────────────────────────────────────────────
csv_to_yaml_list() {
  local csv="$1" indent="$2"
  local IFS=','
  for item in $csv; do
    item="${item// /}"
    [[ -n "$item" ]] && printf '%s- %s\n' "$indent" "$item"
  done
}
LOG_LIST="$(csv_to_yaml_list "$LOG_PATHS_CSV" '      ')"
WHITE_LIST="$(csv_to_yaml_list "$WHITELIST_CSV" '  ')"

if [[ "$COMMUNITY_ENABLED" == "1" ]]; then
  COMMUNITY_BLOCK="community:
  enabled: true
  endpoint: $COMMUNITY_ENDPOINT
  node_id: $NODE_ID
  node_name: $NODE_NAME"
else
  COMMUNITY_BLOCK="community:
  enabled: false"
fi

if [[ -n "$GITHUB_TOKEN" ]]; then
  CENTRAL_BLOCK="central:
  enabled: true
  backend: github
  repo: $REPO
  branch: $BRANCH
  node_id: $NODE_ID
  node_name: $NODE_NAME"
else
  CENTRAL_BLOCK="central:
  enabled: false"
fi

info "Writing $CONFIG_FILE ..."
cat > "$CONFIG_FILE" <<YAML
# ScanGuard agent configuration - generated by install.sh
state_dir: $STATE_DIR
notify_file: $STATE_DIR/notify.txt
dry_run: false

whitelist:
$WHITE_LIST

geo:
  provider: ip-api
  cache_ttl_days: 7

log_sources:
  - name: local-nginx
    kind: nginx
    paths:
$LOG_LIST

rules:
  - name: php-scanner
    pattern: '\.(php|asp|aspx|env|git|jsp|cgi)(\?|$| )'
    threshold: 20
    window_minutes: 30
    severity: high
  - name: path-traversal
    pattern: '(\.\./|/etc/passwd|phpMyAdmin|xmlrpc\.php|/\.aws/credentials)'
    threshold: 5
    window_minutes: 30
    severity: critical
  - name: xss-probe
    pattern: '(<script|bxss\.me|union\s+select|onerror=)'
    threshold: 10
    window_minutes: 30
    severity: high

firewall:
  backend: $FIREWALL_BACKEND
  policy: drop
  chain: INPUT
  persistent: true

$COMMUNITY_BLOCK

$CENTRAL_BLOCK
YAML
chmod 640 "$CONFIG_FILE"

# ── 5. systemd service + timer ────────────────────────────────────────────
if [[ "$SKIP_SYSTEMD" != "1" ]]; then
  info "Installing systemd service + timer..."
  cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=ScanGuard Agent scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 -m scanguard -c $CONFIG_FILE --print
Nice=10
UNIT

  cat > "$TIMER_FILE" <<TIMER
[Unit]
Description=Run ScanGuard Agent scan every 30 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=30min
Persistent=true
Unit=scanguard.service

[Install]
WantedBy=timers.target
TIMER

  systemctl daemon-reload
  systemctl enable --now scanguard.timer
  info "Timer enabled. Upcoming runs:"
  systemctl list-timers --no-pager scanguard.timer 2>/dev/null | head -3 || true
else
  warn "Skipping systemd. For periodic runs, add a cron entry:"
  echo "  */30 * * * * root cd $INSTALL_DIR && /usr/bin/python3 -m scanguard -c $CONFIG_FILE"
fi

# ── 6. Dry-run validation ─────────────────────────────────────────────────
info "Running a dry-run to validate the setup..."
if ( cd "$INSTALL_DIR" && /usr/bin/python3 -m scanguard -c "$CONFIG_FILE" --dry-run --print 2>&1 | tail -20 ); then
  info "Dry-run OK."
else
  warn "Dry-run returned non-zero (common if /var/log/nginx/access.log does not exist yet)."
  warn "Edit $CONFIG_FILE to match your actual log paths."
fi

OWNER="${REPO%%/*}"
SHORT_REPO="${REPO#*/}"
cat <<EOF

${c_green}========================================================${c_off}
${c_green} ScanGuard agent installed successfully.${c_off}

  Install dir : $INSTALL_DIR
  Config      : $CONFIG_FILE
  State       : $STATE_DIR
  Node ID     : $NODE_ID  ($NODE_NAME)

  ${c_cyan}Community reporting${c_off}: $([[ "$COMMUNITY_ENABLED" == "1" ]] && echo "${c_green}ON${c_off}  -> $COMMUNITY_ENDPOINT" || echo "${c_yellow}OFF${c_off}")
  ${c_cyan}Self-hosted fork${c_off}:    $([[ -n "$GITHUB_TOKEN" ]] && echo "${c_green}ON${c_off}  -> $REPO" || echo "${c_yellow}OFF (no token)${c_off}")

 Useful commands:
   systemctl status scanguard.timer
   systemctl list-timers scanguard.timer
   sudo journalctl -u scanguard.service -n 50
   cd $INSTALL_DIR && sudo python3 -m scanguard -c $CONFIG_FILE --dry-run --print
   cd $INSTALL_DIR && sudo python3 -m scanguard -c $CONFIG_FILE --print

 Community dashboard: https://${OWNER}.github.io/${SHORT_REPO}/
${c_green}========================================================${c_off}
EOF
