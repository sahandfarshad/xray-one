#!/usr/bin/env bash
# XRay One installer: installs the panel with a free random port, a secret
# path and a random password, then opens the SSH menu. When Xray is missing
# it asks whether to install it; an Xray already on the server is left as is.
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
if "$BIN" detect 2>/dev/null | grep -q "installed=true"; then
  echo "Xray is already installed ($("$BIN" detect | sed -n 's/.*version=\([^ ]*\).*/\1/p')); it is left as it is."
elif { : </dev/tty; } 2>/dev/null; then
  read -r -p "Xray is not installed. Install the latest Xray now? [Y/n] " ans </dev/tty || ans=n
  case "$ans" in
    n|N|no|No|NO) echo "Skipped. Install it later from the menu: 6) Install / update Xray." ;;
    *) "$BIN" install-xray </dev/tty || echo "Xray install failed; try again from the menu (6)."
       systemctl restart xray-one ;;
  esac
else
  echo "Xray is not installed. Install it from the menu: 6) Install / update Xray."
fi
if { : </dev/tty; } 2>/dev/null; then
  "$BIN" menu </dev/tty || true
fi
