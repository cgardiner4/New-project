#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="powder-paint.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
RUN_USER="${SUDO_USER:-$(whoami)}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/install_rpi_autostart.sh"
  exit 1
fi

cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=Powder Paint Stock Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/scripts/run_production.sh
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

echo "Installed and started ${SERVICE_NAME}."
echo "Check status: systemctl status ${SERVICE_NAME}"
echo "View logs: journalctl -u ${SERVICE_NAME} -f"
