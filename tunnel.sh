#!/usr/bin/env bash
# XRay One tunnel agent: turns this server into a middle (relay) server.
#   bash <(curl -fsSL https://raw.githubusercontent.com/sahandfarshad/xray-one/main/tunnel.sh) <join-code>
# The join code comes from the Tunnel tab of the main panel.
set -euo pipefail
REPO="sahandfarshad/xray-one"
BIN=/usr/local/bin/xray-one
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
[ -n "${1:-}" ] || { echo "usage: tunnel.sh <join-code>"; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac
BASE="https://github.com/$REPO/releases/latest/download"
TMP=$(mktemp -d)
echo "Downloading XRay One agent..."
curl -fL --progress-bar "$BASE/xray-one-linux-$ARCH" -o "$TMP/xray-one-linux-$ARCH"
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
(cd "$TMP" && grep " xray-one-linux-$ARCH\$" SHA256SUMS | sha256sum -c --quiet -) || { echo "Checksum mismatch"; exit 1; }
install -m 755 "$TMP/xray-one-linux-$ARCH" "$BIN"
rm -rf "$TMP"
"$BIN" agent install "$1"
