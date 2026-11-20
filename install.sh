#!/usr/bin/env bash
# XRay One installer: installs the panel only. It never installs, replaces or
# reconfigures Xray itself; the panel can install Xray later from its UI.
set -euo pipefail
REPO="sahandfarshad/xray-one"
BIN=/usr/local/bin/xray-one
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac
VER="${1:-latest}"
if [ "$VER" = "latest" ]; then
  URL="https://github.com/$REPO/releases/latest/download/xray-one-linux-$ARCH"
else
  URL="https://github.com/$REPO/releases/download/$VER/xray-one-linux-$ARCH"
fi
echo "Downloading $URL"
curl -fL "$URL" -o "$BIN.tmp"
chmod +x "$BIN.tmp" && mv "$BIN.tmp" "$BIN"

cat > /etc/systemd/system/xray-one.service <<'UNIT'
[Unit]
Description=XRay One panel (separate from xray.service)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/xray-one serve
Restart=on-failure
RestartSec=3
Environment=XRAY_ONE_DIR=/etc/xray-one

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
if [ ! -f /etc/xray-one/panel.json ] || ! grep -q passHash /etc/xray-one/panel.json; then
  "$BIN" setup
fi
systemctl enable --now xray-one
systemctl restart xray-one
echo
"$BIN" detect || true
echo "XRay One is running. Check: systemctl status xray-one"
