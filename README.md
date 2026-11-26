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

## v0.8
- One tunnel system: WireGuard and mKCP are now methods of the rotating tunnel, next to WS, XHTTP and REALITY. A middle server uses one method and searches the others when it can't reach the main server; dedicated (pinned) tunnels are gone and old pins go back to rotation automatically.
- "In rotation" tick on every method card: untick a method to keep a middle server from rotating to it (the active method always stays in).
- mKCP is VLESS over mKCP with VLESS Encryption and the mkcp-legacy mask; WireGuard carries VLESS inside it. Both need the main server's UDP address (Tunnels tab), and mKCP needs Xray 26.6.1+ on both servers.

یک سیستم تانل: WireGuard و mKCP حالا روش‌های تانل چرخشی‌اند، کنار WS و XHTTP و REALITY. تیک «در چرخش» روی هر کارت روش، آن روش را از چرخش آن سرور میانی بیرون می‌برد.

- 0.8.2: Scan and Check buttons beside the tunnel's REALITY site (Check tests it from this server and from every connected middle server, since the reverse path uses it there too); "?" notes for single-user links, the middle server domain and the REALITY site; a certificate error for a middle server's old domain no longer shows after the domain changes; the panel's files are never served from an old browser cache.

۰.۸.۲: دکمه‌های اسکن و بررسی کنار سایت REALITY تانل (بررسی از این سرور و همه‌ی سرورهای میانی)، علامت «?» با توضیح کوتاه، و حذف اروِر SSL دامنه‌ی قبلی سرور میانی.

## v0.9
- Four more methods in the same rotating tunnel: **GRE** (a kernel GRE link between the two servers' IPs, VLESS inside), **FRP** (frps on the middle server, frpc here dials it; protocol tcp, kcp, quic or websocket), **Backhaul** (server there, client here; tcpmux, tcp, wsmux or ws) and **SSH** (an SSH server built into the agent; this server logs in with its key and opens a remote forward; looks like plain SSH). FRP and Backhaul can run over the GRE link. Each has its card, port (opened on the middle servers), protocol and "In rotation" tick.
- They carry VLESS like WireGuard and land on the same local inbound. FRP, Backhaul and SSH are dialed by this server (like the reverse path), so they still work when the middle server cannot reach out. The middle server gets the FRP and Backhaul programs from this server through its tunnel.
- Middle servers need agent 0.9.0 (run the install command once more). GRE needs public IPs on both servers (no NAT) and protocol 47 allowed.

چهار روش تازه در همان تانل چرخشی: GRE، FRP (با انتخاب پروتکل)، Backhaul (با انتخاب پروتکل) و SSH. FRP و Backhaul می‌توانند روی GRE هم بروند.

- 0.9.1: rotation judges a way by real traffic, not only by heartbeats: every 5 minutes (and on every new way) the middle server downloads 256 KB from this server over it; two failures in a row and it moves to the next way. "TLS fragment" switch on the WS and XHTTP cards. A middle server on the reverse path tries the direct path again every 10 minutes, and a method switch is allowed there too. Needs agent 0.9.1.

۰.۹.۱: چرخش با ترافیک واقعی قضاوت می‌کند نه فقط با پینگ (هر ۵ دقیقه یک دانلود ۲۵۶ کیلوبایتی)؛ گزینه‌ی «تکه‌تکه کردن TLS» برای WS و XHTTP؛ سرور میانی روی مسیر برگشت هر ۱۰ دقیقه مسیر مستقیم را دوباره امتحان می‌کند و عوض کردن روش آنجا هم ممکن است.

## v0.16.0

- Live speed per inbound and per client on Overview (download and upload, every 2 s, busiest first, idle hidden). It runs only while Overview is open. Per-inbound counters are turned on in Xray once (one core restart).
- Settings has a switch to turn it off; when off, the panel never reads these counters.
- سرعت زندهٔ هر اینباند و هر کلاینت در صفحهٔ اول (دانلود و آپلود، هر ۲ ثانیه، پرمصرف‌ترین بالا). فقط وقتی صفحهٔ اول باز است کار می‌کند. شمارنده‌های اینباند یک بار در اکس‌ری روشن می‌شوند (یک بار ری‌استارت هسته).
- در تنظیمات کلید خاموش کردنش هست؛ وقتی خاموش است پنل این شمارنده‌ها را اصلاً نمی‌خواند.

## v0.15.4

- New app icon (X1) as the panel favicon, beside the panel name, and on the subscription page.
- آیکون تازهٔ برنامه (X1) به‌عنوان نشانک مرورگر، کنار نام پنل و در صفحهٔ اشتراک.

## v0.15.3

- The Xray update card (current version, newest version, "Check now", and the update button that appears only when a newer one exists) moved from Settings to the bottom of the Overview page.
- "Alt address" is now called "Personal tunnel address" (same feature: put your own tunnel's middle-server IP and the links use it with the same ports).
- «آدرس جایگزین» حالا «آدرس تانل شخصی» نام دارد (همان قابلیت).
- کارت به‌روزرسانی اکس‌ری (نسخه‌ی فعلی، آخرین نسخه، «بررسی الان» و دکمه‌ی به‌روزرسانی) از تنظیمات به پایین صفحه‌ی اول آمد.

## v0.15.2

- Removed the "all configs" subscription link (and its bar above the tabs); its old link now returns 404. For your own access to everything, make a client for yourself and give it the inbound folders you want.
- لینک اشتراکِ «همه‌ی کانفیگ‌ها» حذف شد؛ برای دسترسی خودتان یک کلاینت بسازید و پوشه‌های دلخواه را به آن بدهید.

## v0.15.1

- "Select all" on the inbound list now picks only what you can see: inbounds outside folders and those in open folders. Each inbound folder has its own checkbox to select everything inside it, open or closed.
- «انتخاب همه» فقط اینباندهای قابل‌دیدن (بیرون پوشه یا داخل پوشه‌ی باز) را انتخاب می‌کند؛ هر پوشه هم تیک جدا برای انتخاب همه‌ی محتوایش دارد.

## v0.15.0

- Folders for inbounds and clients: create, rename and delete them with the "New folder" button; folders start closed and open as a tree. Pick a folder when creating or editing an inbound or a client, or move selected inbounds at once.
- A client can take a whole inbound folder: it is put on every inbound in it, including inbounds added to the folder later.
- پوشه برای اینباندها و کلاینت‌ها: پوشه‌ها بسته‌اند و با زدن به‌صورت درختی باز می‌شوند. هنگام ساخت کلاینت می‌شود کل یک پوشه را انتخاب کرد و اینباندهای بعدی آن پوشه هم خودکار اضافه می‌شوند.

## v0.14.1

- Unblocker traffic now counts against the subscription that activated the address (main and middle servers); every address activated with one subscription uses that subscription's data.
- ترافیک تحریم‌شکن از حجم اشتراکی که آی‌پی را فعال کرده کم می‌شود؛ همه‌ی آی‌پی‌های یک اشتراک از همان حجم مصرف می‌کنند.

## v0.14.0
- The panel, the subscription page and the unblocker activation page now open in English and have a language picker (globe button) with 15 languages: English, فارسی, العربية, اردو, Türkçe, Türkmençe, Русский, Беларуская, 中文, 조선어, မြန်မာ, Tiếng Việt, Español, አማርኛ, ትግርኛ. The choice is saved in the browser; Persian, Arabic and Urdu are right to left. The SSH menu stays English.
- پنل، صفحه‌ی اشتراک و صفحه‌ی فعال‌سازی تحریم‌شکن حالا پیش‌فرض انگلیسی‌اند و دکمه‌ی انتخاب زبان (۱۵ زبان) دارند؛ انتخاب در مرورگر ذخیره می‌شود.
- Translations live in `i18n/<code>.json`; run `python3 i18n/build.py` after editing them (it writes `web/i18n.js` and `i18n_gen.go`).

## v0.13.1

- Unblocker names: next to "+ domain" there is "+ only this" to add just that name (for example challenges.cloudflare.com, not all of cloudflare.com).
- Method cards keep the port and options at the bottom, just above the test, so every card lines up; each "?" sits right after its words.
- New ready list "Speed test" (speed.cloudflare.com) to measure the unblocker path in a browser.
- Epic list adds hcaptcha.com, challenges.cloudflare.com, statsigapi.net and featureassets.org (its sign-in captcha failed without them).

## v0.13.0

- The game unblocker has its own tab, in four parts: domains, entry servers (main or middle, with the DNS address of each), active addresses (IP, user, entry, until when, with a Remove button) and the names active devices asked for, with a one-tap Add for names not in the list.
- Middle servers report their active addresses and names with agent 0.13.0 (run a new install command on them).
- Tunnel method cards share one layout: title, words, port, then one row per option (box, words, its own ?), then state and test.

## v0.12.0

- Game unblocker (Tunnels tab): a DNS + SNI entry on the main server or any middle server, for games and sites that refuse Iranian addresses. Only listed domains pass (DNS and proxy), only addresses a user activated from their subscription page may use it; on a middle server traffic goes through the tunnel to the main server. Needs ports 53, 80, 443 free on the entry. Not a filter bypass.
- Subscription page: apps and WireGuard now come before the config list.
- Hidden "?" notes no longer make windows scroll sideways.

## v0.11.0

- New starting methods for a middle server: besides WS, XHTTP and REALITY, the first connection can now go over WireGuard, mKCP (both UDP) or GRE, for networks where all three TCP methods are blocked. The keys travel inside the install command. GRE needs the middle server's public IPv4 address (taken from the SSH field when it is an IP, or a field shown only for GRE). FRP, Backhaul and SSH still join after the server connects. A method this server cannot offer yet is refused with a clear message.

## v0.10.0

- Subscription page: opening a user's subscription link in a browser shows usage, remaining data, days left, status, every config with copy and QR, WireGuard files with QR, "Add to app" buttons and download links (v2rayNG, Hiddify, Streisand, V2Box, WireGuard). Persian/English, dark/light. VPN apps still get the normal subscription. Add `?raw` to force the plain list.
- Traffic stats are turned on automatically, so every user's usage is counted and data limits work.
- WireGuard users' traffic is counted too (needs Xray 26.6.27 or newer).

## v0.9.3

- Fixed missing labels on the Xray core card, reverse path ports and the starting method (they showed internal key names).
- Inbounds are numbered in list order (numbers are only a visual help and shift when one is deleted).
- Cleaner SSH menu (`xray-one`): framed header, options in one numbered column grouped as Panel and System.

## v0.9.2
- Dark / light switch in the top bar. / دکمه‌ی تاریک و روشن.
- Xray core card: checks GitHub daily, shows this server and outdated middle servers; updates only on the button, after testing the config (a failed test only warns). / بررسی روزانه‌ی نسخه‌ی Xray؛ آپدیت فقط با دکمه.
- Reverse path ports on the middle server follow this server's tunnel ports and can be set per middle server. / پورت‌های مسیر برگشتی هم‌سان و قابل ویرایش.
- Select-all per group in quick inbounds; "?" notes for backups, raw config, starting method; backup times in local time.

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
