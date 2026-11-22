#!/usr/bin/env bash
# XRay One tunnel agent: turns this server into a middle (relay) server.
#   bash tunnel.sh <join-code> [main-server-mirror-url]
# Copy the full command from the Tunnels tab of the main panel: it fetches this
# script from GitHub (with retries), then from the main server, then GitHub again.
# Downloads follow the same order. GitHub always comes first; the main server
# is only a backup, and every agent download is checked against SHA256SUMS.
set -euo pipefail
REPO="sahandfarshad/xray-one"
BIN=/usr/local/bin/xray-one
GH="${XO_GH_BASE:-https://github.com/$REPO/releases/latest/download}"
MIRROR="${2:-}"
GH_TRIES="${XO_GH_TRIES:-3}"
[ "$(id -u)" -eq 0 ] || [ -n "${XO_TEST_DL:-}" ] || { echo "Run as root"; exit 1; }
[ -n "${1:-}" ] || { echo "usage: tunnel.sh <join-code> [mirror]"; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac
NAME="xray-one-linux-$ARCH"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# no hangs: give up on a dead connection after 10 s and on a stalled
# transfer (under 1 KB/s for 20 s)
CURL=(curl -fL --connect-timeout 10 --speed-limit 1024 --speed-time 20 --retry 0)
PROG=(-sS)
[ -t 2 ] && PROG=(--progress-bar)

# fetch_pair <label> <base>: agent binary + SHA256SUMS from one source, checked
fetch_pair() {
  echo "      $1: $NAME"
  rm -f "$TMP/$NAME" "$TMP/SHA256SUMS"
  "${CURL[@]}" "${PROG[@]}" -m 900 "$2/$NAME" -o "$TMP/$NAME" || { echo "      $1: download failed"; return 1; }
  "${CURL[@]}" -sS -m 60 "$2/SHA256SUMS" -o "$TMP/SHA256SUMS" || { echo "      $1: SHA256SUMS failed"; return 1; }
  (cd "$TMP" && grep " $NAME\$" SHA256SUMS | sha256sum -c --quiet - >/dev/null 2>&1) || { echo "      $1: checksum mismatch"; return 1; }
  echo "      $1: OK, checksum verified"
}

echo "Downloading XRay One agent..."
ok=""
for i in $(seq "$GH_TRIES"); do
  [ "$i" -gt 1 ] && { echo "      waiting 3 s..."; sleep 3; }
  if fetch_pair "GitHub (try $i/$GH_TRIES)" "$GH"; then ok=1; break; fi
done
if [ -z "$ok" ] && [ -n "$MIRROR" ]; then
  echo "      GitHub did not answer; trying the main server (backup)..."
  fetch_pair "main server" "$MIRROR" && ok=1
fi
if [ -z "$ok" ]; then
  echo "      trying GitHub again..."
  fetch_pair "GitHub again" "$GH" && ok=1
fi
[ -n "$ok" ] || { echo "Could not download the agent from GitHub or the main server. Check this server's internet and try again."; exit 1; }
if [ -n "${XO_TEST_DL:-}" ]; then cp "$TMP/$NAME" "$XO_TEST_DL"; exit 0; fi
install -m 755 "$TMP/$NAME" "$BIN"
XO_MIRROR="$MIRROR" "$BIN" agent install "$1"
