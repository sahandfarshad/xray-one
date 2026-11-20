#!/usr/bin/env bash
# XRay One installer. Asks nothing: it installs the panel with a free random
# port, a secret path and a random password, then opens the SSH menu.
# It never installs, replaces or reconfigures Xray itself.
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
if [ "$VER" = "latest" ]; then BASE="https://github.com/$REPO/releases/latest/download"
else BASE="https://github.com/$REPO/releases/download/$VER"; fi

TMP=$(mktemp -d)
curl -fsSL "$BASE/xray-one-linux-$ARCH" -o "$TMP/xray-one-linux-$ARCH"
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
(cd "$TMP" && grep " xray-one-linux-$ARCH\$" SHA256SUMS | sha256sum -c --quiet -) || { echo "Checksum mismatch"; exit 1; }
install -m 755 "$TMP/xray-one-linux-$ARCH" "$BIN"
rm -rf "$TMP"

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
"$BIN" init
systemctl enable xray-one >/dev/null 2>&1
systemctl restart xray-one
sleep 1
if [ -t 0 ] || [ -e /dev/tty ]; then
  "$BIN" menu </dev/tty || true
fi
