#!/usr/bin/env bash
# Install ScanGuard Agent on a Linux host (run as root).
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/scanguard}"
ETC_DIR=/etc/scanguard
STATE_DIR=/var/lib/scanguard

if [[ $EUID -ne 0 ]]; then
  echo "run as root" >&2; exit 1
fi

echo "==> installing Python deps"
pip3 install --quiet pyyaml

echo "==> copying agent to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$ETC_DIR" "$STATE_DIR"
cp -a "$(dirname "$0")/../agent/scanguard" "$INSTALL_DIR/"

if [[ ! -f "$ETC_DIR/config.yaml" ]]; then
  cp "$(dirname "$0")/../examples/config.example.yaml" "$ETC_DIR/config.yaml"
  echo "==> edit $ETC_DIR/config.yaml now (add whitelist + servers)"
fi

SITE=$(python3 -c "import site; print(site.getsitepackages()[0])")
ln -sf "$INSTALL_DIR/scanguard" "$SITE/scanguard"

echo "==> installing systemd timer"
cp "$(dirname "$0")/../agent/packaging/scanguard.service" /etc/systemd/system/
cp "$(dirname "$0")/../agent/packaging/scanguard.timer" /etc/systemd/system/
systemctl daemon-reload

cat <<EOF

Installed. Next steps:
  1. Edit $ETC_DIR/config.yaml (whitelist your IP!)
  2. Test:   scanguard --dry-run -c $ETC_DIR/config.yaml --print
  3. Enable: systemctl enable --now scanguard.timer
  4. Status: systemctl list-timers scanguard.timer
EOF
