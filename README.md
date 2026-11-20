# XRay One

A light, minimal panel that sits **beside** a headless Xray core. It never replaces the binary or `xray.service`, and `config.json` stays the only source of truth, so Xray (and tools like Muse99) keep working exactly as before. Remove the panel and nothing about Xray changes.

پنل سبک و مینیمال که **کنار** هسته‌ی XRay می‌نشیند، نه روی آن. باینری و سرویس `xray` دست نمی‌خورند و `config.json` تنها منبع حقیقت می‌ماند؛ پس کار Headless و Muse99 مثل قبل ادامه دارد. اگر پنل را پاک کنید، XRay هیچ تغییری نمی‌کند.

## What it does / امکانات

- Detects Xray on connect: binary, version, systemd status and the real config path (read from the unit's `ExecStart`, `-config` or `-confdir`).
- Installs Xray if missing, and updates it to the latest or a chosen version, with the official [XTLS/Xray-install](https://github.com/XTLS/Xray-install) script. Updating swaps only the binary; the config is untouched.
- Inbounds: list all (including ones made by hand or by Muse99), create VLESS / VMess / Trojan / Shadowsocks 2022 over TCP, WS, gRPC, XHTTP, HTTPUpgrade with REALITY, TLS or none, and delete.
- Clients: add / remove, expiry (days), traffic limit (GB), reset, re-enable; share link, QR code and a subscription URL per client (`/sub/<token>` with `Subscription-Userinfo`).
- Traffic stats: one optional click adds the stats API on `127.0.0.1` (only what is missing).
- Safety: every write is backed up, validated with `xray run -test`, and rolled back if Xray rejects it. Key order and unknown fields are preserved, so hand edits survive. Backups can be restored from the UI.
- Panel login (bcrypt, lockout), optional secret base path, SSL by automatic Let's Encrypt or your own certificate files. Persian and English UI, light and dark.

## Install / نصب

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sahandfarshad/xray-one/main/install.sh)
```

The installer asks for a username, password, listen address, secret path, the server address for links, and optional SSL. Change them later with `xray-one setup`.

نصب‌کننده نام کاربری، رمز، آدرس شنود، مسیر مخفی، آدرس سرور برای لینک‌ها و SSL را می‌پرسد. بعداً با `xray-one setup` عوض می‌شوند.

- Keep it private: listen on `127.0.0.1:2096` and open it with `ssh -L 2096:127.0.0.1:2096 root@server`.
- Or public with SSL: listen on `0.0.0.0:2096` and set a domain (port 80 must be free for Let's Encrypt).

## Files

| Path | What |
|---|---|
| `/usr/local/bin/xray-one` | the panel binary |
| `/etc/xray-one/panel.json` | panel settings and login hash |
| `/etc/xray-one/state.json` | panel-only data: expiry, limits, usage, subscription tokens |
| `/etc/xray-one/backups/` | config backups (last 40) |

Xray never reads these. Uninstall: `systemctl disable --now xray-one && rm -rf /usr/local/bin/xray-one /etc/xray-one /etc/systemd/system/xray-one.service`.

## Notes

- Expiry and traffic limits are enforced by the panel (it pauses the client by moving it out of the config and restores it on re-enable). If the panel is stopped, Xray keeps serving and nobody is cut off.
- Changes apply by restarting `xray` (a second or two). Configs with comments are shown read-only.
- Build: `CGO_ENABLED=0 go build -o xray-one .` (Go 1.23+). Releases are built by GitHub Actions on `v*` tags.
