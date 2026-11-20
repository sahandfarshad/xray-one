# XRay One

A light, minimal panel that sits **beside** a headless Xray core. It never replaces the binary or `xray.service`, and `config.json` stays the only source of truth, so Xray (and tools like Muse99) keep working exactly as before. Remove the panel and nothing about Xray changes.

پنل سبک و مینیمال که **کنار** هسته‌ی XRay می‌نشیند، نه روی آن. باینری و سرویس `xray` دست نمی‌خورند و `config.json` تنها منبع حقیقت می‌ماند؛ پس کار Headless و Muse99 مثل قبل ادامه دارد. اگر پنل را پاک کنید، XRay هیچ تغییری نمی‌کند.

## What it does / امکانات

- Detects Xray on connect: binary, version, systemd status and the real config path (from the running xray process, or the unit's `ExecStart`). Inbounds made by hand or by Muse99 show up as-is.
- Installs Xray if missing, and updates it to the latest or a chosen version, with the official [XTLS/Xray-install](https://github.com/XTLS/Xray-install) script. Updating swaps only the binary; the config is untouched.
- Inbounds: list all (including ones made by hand or by Muse99), create VLESS / VMess / Trojan / Shadowsocks 2022 over TCP, WS, gRPC, XHTTP, HTTPUpgrade with REALITY, TLS or none, and delete.
- Clients: add / remove, expiry (days), traffic limit (GB), reset, re-enable; share link, QR code and a subscription URL per client (`/sub/<token>` with `Subscription-Userinfo`).
- Traffic stats: one optional click adds the stats API on `127.0.0.1` (only what is missing).
- Safety: every write is backed up, validated with `xray run -test`, and rolled back if Xray rejects it. Key order and unknown fields are preserved, so hand edits survive. Backups can be restored from the UI.
- Panel login (bcrypt, lockout), secret base path, SSL from the SSH menu. New inbounds get a free port suggested and checked; TLS inbounds can pick a certificate already on the server. Persian and English UI, light and dark.

## v0.3
- One subscription link with every config on the server (shown at the top of the panel; "New link" rotates it). Per-client subscriptions still work.
- Quick setup: tick any of 20 ready-made types (REALITY, TLS, plain); each gets a free port and one shared client.
- Relays: add a relay / CDN IP (and optional port) to one inbound or to all selected ones; links and subscriptions get an extra copy per relay, while SNI / REALITY stay those of the real server.

## Install / نصب

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/sahandfarshad/xray-one/main/install.sh)
```

No questions. It picks a free random port, a secret path and a random password, prints the panel URL and login, then opens the SSH menu.

بدون سؤال نصب می‌شود: یک پورت آزاد تصادفی، مسیر مخفی و رمز تصادفی می‌سازد، آدرس پنل و رمز را نشان می‌دهد و بعد منوی SSH باز می‌شود.

## SSH menu / منوی SSH

Run `xray-one` on the server any time:

1. Change username / password
2. Change panel port (checks the port is free and suggests one)
3. Change secret path
4. SSL: get a new Let's Encrypt certificate (auto-renewed), reuse a certificate already on the server (certbot, Muse99, acme.sh; reloaded automatically after their renewals), or turn SSL off
5. Server address used in client links
6. Install / update Xray core
7. Restart panel · 8. Logs · 9. Update XRay One · 10. Uninstall XRay One

Also: `xray-one update`, `xray-one uninstall`, `xray-one detect`.

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
