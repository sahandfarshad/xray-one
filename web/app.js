"use strict";
const T = {
  fa: {
    loginHint: "برای مدیریت هسته‌ی XRay وارد شوید.", user: "نام کاربری", pass: "رمز عبور", signIn: "ورود",
    overview: "نمای کلی", inbounds: "اینباندها", settings: "تنظیمات", logout: "خروج",
    coreStatus: "وضعیت هسته", coreVersion: "نسخه‌ی هسته", clients: "کلاینت‌ها", traffic: "ترافیک کل",
    coreTitle: "هسته‌ی XRay", restart: "ری‌استارت", enableApi: "فعال‌سازی آمار ترافیک",
    install: "نصب XRay", update: "آپدیت به آخرین نسخه", updateTo: "نصب این نسخه",
    notInstalled: "نصب نیست", running: "در حال اجرا", stopped: "متوقف",
    hintMissing: "هسته روی این سرور پیدا نشد. با اسکریپت رسمی XTLS نصب می‌شود؛ مسیرها و سرویس استاندارد می‌مانند.",
    hintOk: "آپدیت فقط باینری را عوض می‌کند و کانفیگ دست نمی‌خورد.",
    apiOn: "آمار ترافیک فعال", apiOff: "آمار ترافیک غیرفعال",
    addInbound: "اینباند جدید", addClient: "کلاینت جدید", del: "حذف", save: "ذخیره", cancel: "انصراف", create: "ساختن",
    protocol: "پروتکل", port: "پورت", tag: "تگ (اختیاری)", network: "شبکه", security: "امنیت",
    path: "مسیر (path)", serviceName: "serviceName", serverName: "SNI / serverName", dest: "مقصد REALITY",
    certFile: "فایل گواهی", keyFile: "فایل کلید", pickCert: "گواهی موجود روی سرور",
    name: "نام (ایمیل)", expiryDays: "اعتبار (روز، ۰ = نامحدود)", limitGB: "حجم (GB، ۰ = نامحدود)",
    unlimited: "نامحدود", never: "بدون انقضا", daysLeft: "روز مانده", expired: "منقضی", overLimit: "حجم تمام",
    paused: "متوقف شده", link: "لینک", sub: "سابسکریپشن", copy: "کپی", copied: "کپی شد",
    resetTraffic: "صفر کردن ترافیک", enable: "فعال‌سازی دوباره", details: "جزئیات",
    noInbounds: "هنوز اینباندی نیست.", noClients: "کلاینتی ندارد.", system: "سیستمی", unmanaged: "بدون کلاینت",
    confirmDelInbound: "این اینباند و همه‌ی کلاینت‌هایش حذف شود؟", confirmDelClient: "این کلاینت حذف شود؟",
    confirmApi: "یک اینباند API روی 127.0.0.1 و قانون روتینگش به کانفیگ اضافه می‌شود. ادامه؟",
    confirmRestore: "کانفیگ فعلی با این بکاپ جایگزین شود؟ (از فعلی هم بکاپ گرفته می‌شود)",
    linksTitle: "آدرس لینک‌ها", publicHost: "دامنه یا IP سرور برای لینک‌ها", subBase: "آدرس پایه‌ی سابسکریپشن (اختیاری)",
    sslHint: "SSL پنل و سابسکریپشن از منوی SSH تنظیم می‌شود: دستور xray-one و گزینه‌ی ۴.",
    backups: "بکاپ‌ها", restore: "بازگردانی", rawConfig: "کانفیگ خام (فقط خواندنی)", show: "نمایش",
    saved: "ذخیره شد", done: "انجام شد", jobRunning: "در حال اجرا…", jobOk: "با موفقیت تمام شد", jobFail: "خطا خورد",
    up: "آپلود", down: "دانلود", edit: "ویرایش", setExpiry: "تغییر اعتبار", setLimit: "تغییر حجم",
    allSub: "سابسکریپشن همه‌ی کانفیگ‌ها", newLink: "لینک جدید", confirmNewLink: "لینک فعلی سابسکریپشن از کار می‌افتد و لینک تازه ساخته می‌شود. ادامه؟",
    quick: "ساخت خودکار", quickTitle: "ساخت خودکار کانفیگ‌ها", quickHint: "هر نوعی که تیک بزنی روی یک پورت آزاد ساخته می‌شود و یک کلاینت مشترک می‌گیرد، پس سابسکریپشن همان کلاینت همه را دارد.",
    gReality: "REALITY (بدون دامنه و گواهی)", gTls: "TLS (با گواهی دامنه)", gPlain: "بدون TLS (برای relay یا CDN روی HTTP)",
    needCert: "اول SSL را از منوی SSH تنظیم کن", exists: "داری", all: "همه", none: "هیچ", clientName: "نام کلاینت مشترک",
    createN: "ساختن", relay: "آدرس جایگزین", addRelay: "افزودن آدرس جایگزین", relaySel: "آدرس جایگزین برای انتخاب‌شده‌ها", relayAddr: "IP یا دامنه‌ی جایگزین",
    relayPort: "پورت (خالی = همان پورت اینباند)", relayName: "اسم (اختیاری)", relayHint: "هر کلاینت یک لینک اضافه با این آدرس می‌گیرد (در QR و سابسکریپشن هم). SNI، کلید و بقیه‌ی تنظیمات همان می‌ماند. پنل مسیر را نمی‌سازد؛ این آدرس باید خودش به این سرور برسد.",
    relayEx: "مثال‌ها: یک ساب‌دامنه‌ی دیگر که به همین IP اشاره می‌کند (اگر دامنه‌ی اول فیلتر شد) · ساب‌دامنه یا IP تمیز Cloudflare برای اینباندهای WS/XHTTP با TLS · IP سروری که خودت با iptables/HAProxy به اینجا فوروارد کرده‌ای.",
    relayBefore: "لینک فعلی", relayAfter: "لینک اضافه با این آدرس", relayNoClient: "این اینباند هنوز کلاینتی ندارد که نمونه‌ی لینک نشان داده شود.",
    delSel: "حذف", selAll: "انتخاب همه", selNone: "هیچ‌کدام", editInbound: "ویرایش اینباند", editIbNote: "پروتکل، تگ و کلاینت‌ها همین‌طور می‌مانند. با عوض کردن پورت یا تنظیمات، لینک‌ها و ساب عوض می‌شوند و کاربرها باید ساب را آپدیت کنند.", rsCheck: "بررسی", rCommas: "با کاما جدا کنید", rNew: "ساخت دوباره", rNewKeys: "کلید جدید", rClear: "پاک کردن", rsFind: "پیدا کردن", rsTitle: "اسکنر مقصد REALITY", rsHint: "از روی همین سرور چک می‌کند کدام سایت برای REALITY مناسب است (TLS 1.3، h2، X25519 و گواهی معتبر). خالی بگذارید تا سایت‌های معروف چک شوند، یا یک دامنه، IP یا رنج مثل 1.2.3.0/24 بدهید.",
    rsPh: "دامنه، IP یا رنج — خالی = سایت‌های معروف", rsScan: "اسکن", rsStatus: "وضعیت", rsCert: "گواهی", rsLatency: "تأخیر", rsOk: "مناسب", rsNo: "نامناسب", rsUse: "استفاده", rsWait: "در حال اسکن… (تا یک دقیقه)", rsCount: "{a} مناسب از {b} مورد", close: "بستن", tunSel: "⇄ تانل", tbTitle: "تانل گروهی", tbHint: "اینباندهای انتخاب‌شده با همان پورت خودشان روی سرور میانی باز می‌شوند. پورت‌هایی که آنجا اشغال باشند رد می‌شوند و اینجا نشان داده می‌شوند.",
    tbAdd: "تانل کن", tbRemove: "برداشتن از این سرور", tbSkipped: "رد شدند", tbDone: "{n} اینباند انجام شد", tbProgress: "{a} از {b} روی سرور میانی آماده شد", tbSlow: "سرور میانی جواب نداد. آنلاین بودنش را در تب تانل چک کنید.",
    stOk: "باز", stBusy: "اشغال روی سرور میانی", stDown: "باز نشد", stOffline: "سرور میانی آفلاین", stUnknown: "ایجنت قدیمی؛ دستور نصب را دوباره اجرا کنید", stPending: "در حال بررسی…", confirmDelSel: "{n} اینباند انتخاب‌شده حذف شود؟ کلاینت‌های داخلشان هم حذف می‌شوند.",
    usersTab: "کلاینت‌ها", addUser: "کلاینت جدید", usersHint: "هر کلاینت یک اسم است که روی چند اینباند می‌نشیند، با یک محدودیت حجم و زمان و یک لینک سابسکریپشن برای همه.",
    noUsers: "هنوز کلاینتی نیست.", pickInbounds: "اینباندهای این کلاینت", editUser: "ویرایش", noInboundsYet: "بدون اینباند", confirmDelUser: "این کلاینت از همه‌ی اینباندها حذف شود؟",
    tunnels: "تانل", addTunnel: "سرور میانی جدید", tnName: "نام", tnHost: "IP یا دامنه‌ی سرور میانی (برای SSH)", tnSshPort: "پورت SSH", tnSshUser: "کاربر SSH",
    tnMethod: "روش", tnDeploy: "Deploy با SSH", tnPass: "پسورد SSH (فقط یک بار؛ ذخیره نمی‌شود)", tnPassKey: "کلید پنل نصب شده؛ پسورد لازم نیست",
    tnOnline: "متصل", tnOffline: "قطع", tnNever: "هنوز وصل نشده", tnAgo: "پیش", tnQuick: "نصب سریع بدون پسورد: این دستور را روی سرور میانی (با root) بزنید. تا ۲۴ ساعت معتبر است و بعد از اتصال باطل می‌شود.",
    tnNewCmd: "دستور نصب جدید", tnNoSrv: "هنوز سرور میانی اضافه نشده.", tnInfo: "روش WSS: سرور میانی با WebSocket+TLS به پورت {port} روی {domain} وصل می‌شود. کاربر ← سرور میانی ← این سرور ← اینترنت.",
    tnNeedSSL: "برای تانل WSS اول باید دامنه و SSL را از منوی SSH تنظیم کنید.", tnUse: "تانل", tnPick: "این اینباند از کدام سرورهای میانی استفاده کند؟ برای هر کدام یک لینک جدا ساخته می‌شود.",
    tnTest: "تست اتصال", tnTesting: "در حال تست…", tnTestOk: "وصل است · {ms} میلی‌ثانیه", tnTestBad: "پاسخی از سرور میانی نیامد",
    tnLastFail: "آخرین قطعی", tnFails: "{n} تلاش ناموفق",
    tnInbounds: "اینباندها", tnSshOpt: "Deploy با SSH (اختیاری)", tnPortHere: "پورت روی سرور میانی", tnBusy: "اشغال روی سرور میانی",
    tnRemove: "حذف relay از سرور میانی (روی همان سرور بزنید):", tnCmdTitle: "دستور نصب سرور میانی",
    tnInbounds: "اینباندها", tnDeploying: "در حال نصب روی سرور میانی… (تا چند دقیقه)", tnConfirmDel: "این سرور میانی حذف شود؟ اینباندها دیگر از آن استفاده نمی‌کنند.", tnXrayErr: "خطای relay",
    selectAll: "انتخاب همه", ports: "پورت‌ها", portsTitle: "پورت‌های استفاده‌شده", portsHint: "همه‌ی پورت‌های این‌باندها، جدا با کاما؛ برای ساخت relay و تانل.", gSS: "Shadowsocks", gProxy: "پراکسی ساده (SOCKS / HTTP، با یوزر و پسورد جدا)", relayLinks: "لینک‌های relay", singleUser: "تک‌کاربره", confirmDelRelay: "این relay حذف شود؟",
  },
  en: {
    loginHint: "Sign in to manage the Xray core.", user: "Username", pass: "Password", signIn: "Sign in",
    overview: "Overview", inbounds: "Inbounds", settings: "Settings", logout: "Log out",
    coreStatus: "Core status", coreVersion: "Core version", clients: "Clients", traffic: "Total traffic",
    coreTitle: "Xray core", restart: "Restart", enableApi: "Enable traffic stats",
    install: "Install Xray", update: "Update to latest", updateTo: "Install this version",
    notInstalled: "Not installed", running: "Running", stopped: "Stopped",
    hintMissing: "No core found on this server. It installs with the official XTLS script, keeping standard paths and service.",
    hintOk: "Updating only swaps the binary; your config is untouched.",
    apiOn: "Traffic stats on", apiOff: "Traffic stats off",
    addInbound: "New inbound", addClient: "New client", del: "Delete", save: "Save", cancel: "Cancel", create: "Create",
    protocol: "Protocol", port: "Port", tag: "Tag (optional)", network: "Network", security: "Security",
    path: "Path", serviceName: "serviceName", serverName: "SNI / serverName", dest: "REALITY dest",
    certFile: "Certificate file", keyFile: "Key file", pickCert: "Certificate on this server",
    name: "Name (email)", expiryDays: "Valid for (days, 0 = forever)", limitGB: "Traffic (GB, 0 = unlimited)",
    unlimited: "Unlimited", never: "No expiry", daysLeft: "days left", expired: "Expired", overLimit: "Out of traffic",
    paused: "Paused", link: "Link", sub: "Subscription", copy: "Copy", copied: "Copied",
    resetTraffic: "Reset traffic", enable: "Re-enable", details: "Details",
    noInbounds: "No inbounds yet.", noClients: "No clients.", system: "system", unmanaged: "no clients",
    confirmDelInbound: "Delete this inbound and all its clients?", confirmDelClient: "Delete this client?",
    confirmApi: "This adds an API inbound on 127.0.0.1 and its routing rule to the config. Continue?",
    confirmRestore: "Replace the current config with this backup? (the current one is backed up too)",
    linksTitle: "Link address", publicHost: "Server domain or IP for links", subBase: "Subscription base URL (optional)",
    sslHint: "Panel and subscription SSL are set in the SSH menu: run xray-one, option 4.",
    backups: "Backups", restore: "Restore", rawConfig: "Raw config (read-only)", show: "Show",
    saved: "Saved", done: "Done", jobRunning: "Running…", jobOk: "Finished successfully", jobFail: "Failed",
    up: "Up", down: "Down", edit: "Edit", setExpiry: "Change validity", setLimit: "Change traffic",
    allSub: "Subscription with every config", newLink: "New link", confirmNewLink: "The current subscription link stops working and a new one is made. Continue?",
    quick: "Quick setup", quickTitle: "Create configs automatically", quickHint: "Every type you tick gets its own free port and one shared client, so that client's subscription carries them all.",
    gReality: "REALITY (no domain or certificate needed)", gTls: "TLS (uses your domain certificate)", gPlain: "No TLS (for relays or CDN over HTTP)",
    needCert: "Set SSL in the SSH menu first", exists: "have it", all: "All", none: "None", clientName: "Shared client name",
    createN: "Create", relay: "Alt address", addRelay: "Add alt address", relaySel: "Alt address for selected", relayAddr: "Alternative IP or domain",
    relayPort: "Port (empty = inbound port)", relayName: "Name (optional)", relayHint: "Every client gets an extra link with this address (also in QR and subscription). SNI, keys and other settings stay the same. The panel does not build the route; this address must already reach this server.",
    relayEx: "Examples: a second subdomain pointing to this IP (if the first gets blocked) · a Cloudflare subdomain or clean IP for WS/XHTTP+TLS inbounds · the IP of a server you forward here yourself with iptables/HAProxy.",
    relayBefore: "Current link", relayAfter: "Extra link with this address", relayNoClient: "This inbound has no client yet to preview a link.",
    delSel: "Delete", selAll: "Select all", selNone: "Select none", editInbound: "Edit inbound", editIbNote: "Protocol, tag and clients stay. Changing the port or settings changes links and the subscription; users must update their sub.", rsCheck: "Check", rCommas: "comma separated", rNew: "Regenerate", rNewKeys: "New keys", rClear: "Clear", rsFind: "Find", rsTitle: "REALITY target scanner", rsHint: "Checks from this server which sites work as a REALITY target (TLS 1.3, h2, X25519, valid certificate). Leave empty for common sites, or enter a domain, an IP or a range like 1.2.3.0/24.",
    rsPh: "domain, IP or range — empty = common sites", rsScan: "Scan", rsStatus: "Status", rsCert: "Certificate", rsLatency: "Latency", rsOk: "Feasible", rsNo: "Not usable", rsUse: "Use", rsWait: "Scanning… (up to a minute)", rsCount: "{a} usable of {b}", close: "Close", tunSel: "⇄ Tunnel", tbTitle: "Bulk tunnel", tbHint: "Selected inbounds open on the middle server on their own port. Ports busy there are skipped and shown here.",
    tbAdd: "Tunnel", tbRemove: "Remove from this server", tbSkipped: "Skipped", tbDone: "{n} inbounds done", tbProgress: "{a} of {b} ready on the middle server", tbSlow: "The middle server did not answer. Check it is online in the Tunnels tab.",
    stOk: "open", stBusy: "busy on middle server", stDown: "not listening", stOffline: "middle server offline", stUnknown: "old agent; rerun the install command", stPending: "checking…", confirmDelSel: "Delete {n} selected inbounds? Their clients go too.",
    usersTab: "Clients", addUser: "New client", usersHint: "A client is one name that sits on several inbounds, with one traffic/time limit and one subscription link for all of them.",
    noUsers: "No clients yet.", pickInbounds: "Inbounds of this client", editUser: "Edit", noInboundsYet: "no inbound", confirmDelUser: "Remove this client from every inbound?",
    tunnels: "Tunnel", addTunnel: "New middle server", tnName: "Name", tnHost: "Middle server IP or domain (for SSH)", tnSshPort: "SSH port", tnSshUser: "SSH user",
    tnMethod: "Method", tnDeploy: "Deploy over SSH", tnPass: "SSH password (used once, never stored)", tnPassKey: "Panel key installed; no password needed",
    tnOnline: "Connected", tnOffline: "Down", tnNever: "not connected yet", tnAgo: "ago", tnQuick: "Quick install without a password: run this on the middle server as root. Valid 24 h, void after it connects.",
    tnNewCmd: "New install command", tnNoSrv: "No middle server yet.", tnInfo: "WSS method: the middle server connects with WebSocket+TLS to port {port} on {domain}. User → middle server → this server → internet.",
    tnNeedSSL: "The WSS tunnel needs this server's domain and SSL: set them in the SSH menu first.", tnUse: "Tunnel", tnPick: "Which middle servers should this inbound use? Each one gets its own link.",
    tnTest: "Test connection", tnTesting: "Testing…", tnTestOk: "Connected · {ms} ms", tnTestBad: "No answer from the middle server",
    tnLastFail: "Last drop", tnFails: "{n} failed attempts",
    tnSshOpt: "Deploy over SSH (optional)", tnPortHere: "Port on middle server", tnBusy: "busy on middle server",
    tnRemove: "Remove the relay from the middle server (run there):", tnCmdTitle: "Middle server install command",
    tnInbounds: "Inbounds", tnDeploying: "Installing on the middle server… (a few minutes)", tnConfirmDel: "Remove this middle server? Inbounds stop using it.", tnXrayErr: "Relay error",
    selectAll: "Select all", ports: "Ports", portsTitle: "Used ports", portsHint: "Every inbound port, comma separated, for building relays and tunnels.", gSS: "Shadowsocks", gProxy: "Plain proxies (SOCKS / HTTP, own user and password)", relayLinks: "Relay links", singleUser: "single user", confirmDelRelay: "Remove this relay?",
  },
};
let lang = localStorage.getItem("xo_lang") || "fa";
const t = (k) => (T[lang] && T[lang][k]) || T.en[k] || k;
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let state = { status: null, inbounds: [], host: "", job: null, view: "overview", sel: new Set() };

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
  document.querySelectorAll("[data-t]").forEach((el) => (el.textContent = t(el.dataset.t)));
  $("#langBtn").textContent = lang === "fa" ? "EN" : "فا";
  render();
}

async function api(method, url, body) {
  const r = await fetch(url, {
    method, credentials: "same-origin",
    headers: { "X-XO": "1", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401 && url !== "api/login") { showLogin(); throw new Error("login"); }
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || r.statusText);
  return data;
}

function toast(msg) {
  const el = $("#toast"); el.textContent = msg; el.classList.remove("hidden");
  clearTimeout(toast._t); toast._t = setTimeout(() => el.classList.add("hidden"), 2600);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { if (e.message !== "login") toast(e.message); } };

function fmtBytes(n) {
  n = Number(n || 0); const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n < 10 ? 2 : 1) : n) + " " + u[i];
}

// ---------- login ----------
function showLogin() { $("#app").classList.add("hidden"); $("#login").classList.remove("hidden"); }
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("POST", "api/login", { user: f.get("user"), pass: f.get("pass") });
    $("#loginErr").textContent = ""; e.target.reset(); boot();
  } catch (err) { $("#loginErr").textContent = err.message; }
});
$("#logoutBtn").onclick = guard(async () => { await api("POST", "api/logout"); showLogin(); });
$("#langBtn").onclick = () => { lang = lang === "fa" ? "en" : "fa"; localStorage.setItem("xo_lang", lang); applyLang(); };

// ---------- navigation ----------
document.querySelectorAll("#tabs button").forEach((b) => (b.onclick = () => { state.view = b.dataset.view; render(); if (state.view === "settings") loadSettings(); if (state.view === "tunnels") loadTunnels(); if (state.view === "users") loadUsers(); }));

async function boot() {
  try {
    state.status = await api("GET", "api/status");
  } catch { return; }
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
  await refreshInbounds();
  render();
  pollJob();
}

async function refreshStatus() { state.status = await api("GET", "api/status"); render(); }
async function refreshInbounds() {
  try {
    const r = await api("GET", "api/inbounds"); state.inbounds = r.inbounds; state.host = r.host;
    const ids = new Set(r.inbounds.map((i) => i.id)); [...state.sel].forEach((x) => ids.has(x) || state.sel.delete(x));
  }
  catch (e) { state.inbounds = []; }
  render();
  // a middle server is still applying a change: check again shortly
  clearTimeout(refreshInbounds.timer);
  if (state.inbounds.some((ib) => (ib.tunnels || []).some((x) => x.state === "pending")))
    refreshInbounds.timer = setTimeout(() => state.view === "inbounds" && refreshInbounds(), 3000);
}

// ---------- render ----------
function render() {
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.view === state.view));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("hidden", v.id !== "view-" + state.view));
  if (!state.status) return;
  renderSubBar(); renderOverview(); renderInbounds();
}

function baseURL() {
  const s = state.status.settings;
  return (s.subBase || s.panelURL || (location.origin + location.pathname.replace(/[^/]*$/, ""))).replace(/\/$/, "");
}
function allSubURL() { return baseURL() + "/sub/" + state.status.allToken; }
function renderSubBar() {
  const ok = state.status.allToken && state.inbounds.some((i) => !i.system);
  $("#subBar").classList.toggle("hidden", !ok);
  if (ok) $("#allSubUrl").textContent = allSubURL();
  const n = state.sel.size;
  $("#relaySelBtn").textContent = t("relaySel") + (n ? " (" + n + ")" : "");
  $("#relaySelBtn").disabled = !n;
  $("#tunSelBtn").textContent = t("tunSel") + (n ? " (" + n + ")" : "");
  $("#tunSelBtn").disabled = !n;
  $("#delSelBtn").textContent = t("delSel") + (n ? " (" + n + ")" : "");
  $("#delSelBtn").disabled = !n;
  const all = state.inbounds.filter((i) => !i.system);
  $("#selAll").checked = all.length > 0 && n === all.length;
  $("#selAll").indeterminate = n > 0 && n < all.length;
}
async function copyText(v) {
  try { await navigator.clipboard.writeText(v); }
  catch { const i = document.createElement("textarea"); i.value = v; document.body.appendChild(i); i.select(); document.execCommand("copy"); i.remove(); }
  toast(t("copied"));
}
$("#allSubCopy").onclick = () => copyText(allSubURL());
$("#allSubQr").onclick = () => openModal(`<h3>${t("allSub")}</h3>${copyRow(allSubURL())}<img class="qr" alt="QR" src="api/qr?text=${encodeURIComponent(allSubURL())}"><div class="actions"><button class="btn" data-close>${t("cancel")}</button></div>`);
$("#allSubReset").onclick = guard(async () => {
  if (!confirm(t("confirmNewLink"))) return;
  const r = await api("POST", "api/allsub/reset"); state.status.allToken = r.allToken; renderSubBar(); toast(t("done"));
});

function renderOverview() {
  const c = state.status.core;
  const active = c.active === "active";
  $("#sStatus").textContent = !c.installed ? t("notInstalled") : active ? t("running") : t("stopped");
  $("#sStatus").style.color = c.installed && active ? "var(--ok)" : "var(--warn)";
  $("#sService").textContent = c.installed ? "systemd: " + (c.active || "?") : "";
  $("#sVersion").textContent = c.version || "—";
  $("#panelVer").textContent = state.status.version ? "v" + state.status.version : "";
  const dot = $("#coreDot");
  dot.classList.toggle("bad", !(c.installed && active));
  dot.title = "Xray: " + (!c.installed ? t("notInstalled") : active ? t("running") : t("stopped"));
  $("#sPath").textContent = c.configPath || "";
  let n = 0, up = 0, down = 0;
  const users = state.inbounds.filter((i) => !i.system);
  const seen = new Set();
  users.forEach((i) => i.clients.forEach((cl) => {
    n++;
    if (cl.meta && !seen.has(cl.email)) { seen.add(cl.email); up += cl.meta.up; down += cl.meta.down; }
  }));
  $("#sClients").textContent = n;
  $("#sInbounds").textContent = users.length + " " + t("inbounds");
  $("#sTraffic").textContent = fmtBytes(up + down);
  $("#sApi").textContent = c.apiAddr ? t("apiOn") + " · " + c.apiAddr : t("apiOff");
  $("#coreHint").textContent = c.installed ? t("hintOk") : t("hintMissing");
  const ver = $("#verInput").value.trim();
  $("#installBtn").textContent = !c.installed ? t("install") : ver ? t("updateTo") : t("update");
  $("#installBtn").disabled = !!(state.job && state.job.running);
  $("#restartBtn").classList.toggle("hidden", !c.installed);
  $("#apiBtn").classList.toggle("hidden", !c.installed || !c.configOk || !!c.apiAddr);
}
$("#verInput").oninput = renderOverview;

function clientStatus(cl) {
  const m = cl.meta || {};
  if (cl.disabled) return `<span class="pill warn">${esc(m.reason === "traffic" ? t("overLimit") : m.reason === "expired" ? t("expired") : t("paused"))}</span>`;
  if (!m.expiry) return `<span class="pill gray">${t("never")}</span>`;
  const d = Math.ceil((m.expiry * 1000 - Date.now()) / 86400000);
  return d <= 0 ? `<span class="pill warn">${t("expired")}</span>` : `<span class="pill ${d <= 3 ? "warn" : ""}">${d} ${t("daysLeft")}</span>`;
}

function renderInbounds() {
  const list = $("#inboundList");
  if (!state.status.core.installed) { list.innerHTML = `<div class="card empty">${esc(t("hintMissing"))}</div>`; return; }
  const ibs = state.inbounds;
  if (!ibs.length) { list.innerHTML = `<div class="card empty">${t("noInbounds")}</div>`; return; }
  list.innerHTML = ibs.map((ib, idx) => {
    const pills = [ib.protocol, ib.network, ib.security].filter(Boolean).map((p) => `<span class="pill gray">${esc(p)}</span>`).join("");
    const clients = "";
    return `<div class="card">
      <div class="ib-head">
        <div class="ib-title">${ib.system ? "" : `<input type="checkbox" data-sel="${esc(ib.id)}" ${state.sel.has(ib.id) ? "checked" : ""}>`}<b>${esc(ib.tag || ib.id)}</b>${pills}<span class="pill">:${esc(ib.port)}</span>
          ${ib.system ? `<span class="pill gray">${t("system")}</span>` : !ib.managed ? `<span class="pill gray">${t("unmanaged")}</span>` : ""}</div>
        <div class="actions">
          ${ib.system ? "" : `<button class="btn small" data-act="relay" data-i="${idx}">+ ${t("relay")}</button>`}
          ${ib.system ? "" : `<button class="btn small" data-act="tunnel" data-i="${idx}">⇄ ${t("tnUse")}</button>`}
          ${ib.system ? "" : `<button class="btn small" data-act="editInbound" data-i="${idx}">✎ ${t("edit")}</button>`}
          ${ib.system ? "" : `<button class="btn small danger" data-act="delInbound" data-i="${idx}">${t("del")}</button>`}
        </div>
      </div>
      ${(ib.relays || []).some((r) => !r.tunnel) ? `<div class="relays"><span class="muted">${t("relay")}:</span>${ib.relays.map((r, ri) => r.tunnel ? "" :
        `<span class="chip">${esc((r.name ? r.name + " · " : "") + r.address + (r.port ? ":" + r.port : ""))}<button title="${t("del")}" data-act="delRelay" data-i="${idx}" data-r="${ri}">×</button></span>`).join("")}</div>` : ""}
      ${ib.tunnels && ib.tunnels.length ? `<div class="relays"><span class="muted">${t("tunnels")}:</span>${ib.tunnels.map((x) => {
        const cls = x.state === "ok" ? "ok" : ["busy", "down", "offline"].includes(x.state) ? "bad" : "tun";
        const label = { ok: t("stOk"), busy: t("stBusy"), down: t("stDown"), offline: t("stOffline"), unknown: t("stUnknown"), pending: t("stPending") }[x.state] || x.state;
        return `<span class="chip ${cls}" title="${esc(label)}">⇄ ${esc(x.name + " · " + (x.address || "?") + ":" + x.port)} <small>${esc(label)}</small></span>`;
      }).join("")}</div>` : ""}
      ${ib.singleLink ? `<div class="clients"><p class="muted">${t("singleUser")}</p>${copyRow(ib.singleLink)}</div>` : ""}
      ${clients}</div>`;
  }).join("");
}

$("#inboundList").addEventListener("change", (e) => {
  const id = e.target.dataset.sel; if (id === undefined) return;
  e.target.checked ? state.sel.add(id) : state.sel.delete(id); renderSubBar();
});
$("#inboundList").addEventListener("click", guard(async (e) => {
  const cp = e.target.closest("[data-copy]"); if (cp) { copyText(cp.dataset.copy); return; }
  const b = e.target.closest("button[data-act]"); if (!b) return;
  const ib = state.inbounds[+b.dataset.i];
  if (b.dataset.act === "delInbound") {
    if (!confirm(t("confirmDelInbound"))) return;
    await api("DELETE", "api/inbounds?id=" + encodeURIComponent(ib.id)); toast(t("done")); refreshInbounds();
  } else if (b.dataset.act === "editInbound") {
    const ed = await api("GET", "api/inbounds/detail?id=" + encodeURIComponent(ib.id));
    await openInboundForm(ed);
  } else if (b.dataset.act === "addClient") openAddClient(ib);
  else if (b.dataset.act === "client") openClient(ib, ib.clients[+b.dataset.c]);
  else if (b.dataset.act === "relay") openRelay([ib.id]);
  else if (b.dataset.act === "tunnel") openTunnelPick(ib);
  else if (b.dataset.act === "delRelay") {
    const r = ib.relays[+b.dataset.r];
    if (!confirm(t("confirmDelRelay"))) return;
    await api("DELETE", `api/relays?tag=${encodeURIComponent(ib.id)}&address=${encodeURIComponent(r.address)}&port=${r.port || 0}`);
    toast(t("done")); refreshInbounds();
  }
}));

// ---------- modals ----------
function openModal(html, wide) { $("#modalBody").innerHTML = html; $("#modalBody").classList.toggle("wide", !!wide); $("#modal").classList.remove("hidden"); }
function closeModal() { $("#modal").classList.add("hidden"); $("#modalBody").innerHTML = ""; }
$("#modal").addEventListener("click", (e) => {
  const cp = e.target.closest("[data-copy]"); if (cp) { copyText(cp.dataset.copy); return; }
  if (e.target.id === "modal" || e.target.dataset.close !== undefined) closeModal();
});

$("#addInboundBtn").onclick = guard(() => openInboundForm(null));
async function openInboundForm(ed) {
  const [fp, certs] = await Promise.all([ed ? { port: ed.form.port } : api("GET", "api/freeport"), api("GET", "api/certs")]);
  const certOpts = certs.map((c, i) => `<option value="${i}">${esc(c.domain)} · ${esc(c.source)}</option>`).join("");
  openModal(`<h3>${ed ? t("editInbound") + ` · <span class="mono">${esc(ed.id)}</span>` : t("addInbound")}</h3>
  <form id="ibForm" class="form">
    <label>${t("protocol")}<select name="protocol"><option>vless</option><option>vmess</option><option>trojan</option><option value="shadowsocks">shadowsocks 2022</option><option value="hysteria">hysteria2</option><option>socks</option><option>http</option></select></label>
    <label>${t("port")}<input name="port" type="number" min="1" max="65535" value="${fp.port || ""}" required></label>
    <label>${t("network")}<select name="network"><option>tcp</option><option>ws</option><option>grpc</option><option>xhttp</option><option>httpupgrade</option><option>kcp</option></select></label>
    <label>${t("security")}<select name="security"><option>reality</option><option>tls</option><option>none</option></select></label>
    <label>${t("tag")}<input name="tag"></label>
    <label data-show="path">${t("path")}<input name="path" placeholder="/"></label>
    <label data-show="grpc">${t("serviceName")}<input name="serviceName"></label>
    <label data-show="tls">${t("serverName")}<input name="serverName" placeholder="www.microsoft.com"></label>
    <div data-show="reality" class="rgrid">
      <label class="rck"><input type="checkbox" name="r_show"> Show</label>
      <label>Xver<input name="r_xver" type="number" min="0" max="2" value="0"></label>
      <label>uTLS<select name="r_fp">${["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"].map((x) => `<option>${x}</option>`).join("")}</select></label>
      <label class="wide">Target<span class="inrow"><input name="r_target" value="www.microsoft.com:443" dir="ltr"><button type="button" class="btn small" id="rCheck">${t("rsCheck")}</button><button type="button" class="btn small" id="ibScan">🔍 ${t("rsFind")}</button></span><small id="rCheckOut" class="muted"></small></label>
      <label class="wide">SNI <small class="muted">(${t("rCommas")})</small><input name="r_sni" value="www.microsoft.com" dir="ltr"></label>
      <label>Max Time Diff (ms)<input name="r_mtd" type="number" min="0" value="0"></label>
      <label>Min Client Ver<input name="r_minv" placeholder="26.3.27" dir="ltr"></label>
      <label>Max Client Ver<input name="r_maxv" placeholder="x.y.z" dir="ltr"></label>
      <label class="wide">Short IDs <small class="muted">(${t("rCommas")})</small><span class="inrow"><input name="r_sids" dir="ltr"><button type="button" class="btn small" id="rSids" title="${t("rNew")}">↻</button></span></label>
      <label class="wide">SpiderX<span class="inrow"><input name="r_spx" dir="ltr"><button type="button" class="btn small" id="rSpx" title="${t("rNew")}">↻</button></span></label>
      <label class="wide">Public Key<input name="r_pub" readonly dir="ltr" class="mono"></label>
      <label class="wide">Private Key<input name="r_priv" dir="ltr" class="mono"></label>
      <div class="actions wide"><button type="button" class="btn small primary" id="rKeys">${t("rNewKeys")}</button><button type="button" class="btn small danger" id="rClear">${t("rClear")}</button></div>
    </div>
    ${certs.length ? `<label data-show="tls">${t("pickCert")}<select name="certPick"><option value="">—</option>${certOpts}</select></label>` : ""}
    <label data-show="tls">${t("certFile")}<input name="certFile" placeholder="/etc/letsencrypt/live/…/fullchain.pem"></label>
    <label data-show="tls">${t("keyFile")}<input name="keyFile" placeholder="/etc/letsencrypt/live/…/privkey.pem"></label>
  </form>
  <p id="ibErr" class="err"></p>
  ${ed ? `<p class="muted">${t("editIbNote")}</p>` : ""}
  <div class="actions"><button class="btn primary" id="ibCreate">${ed ? t("save") : t("create")}</button><button class="btn" data-close>${t("cancel")}</button></div>`, true);
  const f = $("#ibForm");
  $("#ibScan").onclick = () => openRealityScan((r) => { f.r_target.value = r.target; f.r_sni.value = r.sni; }, true);
  const rhex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const newSids = () => { f.r_sids.value = [8, 2, 1, 3, 4, 7, 5, 6].map(rhex).join(","); };
  const newSpx = () => { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; f.r_spx.value = "/" + [...crypto.getRandomValues(new Uint8Array(15))].map((b) => a[b % a.length]).join(""); };
  const newKeys = async () => { try { const k = await api("GET", "api/reality/keys"); f.r_priv.value = k.privateKey; f.r_pub.value = k.publicKey; } catch (e) { $("#ibErr").textContent = e.message; } };
  if (ed) {
    const v = ed.form, r = v.reality;
    f.protocol.value = v.protocol; f.protocol.disabled = true;
    f.tag.value = v.tag || ""; f.tag.readOnly = true;
    f.network.value = v.network; f.security.value = v.security;
    f.path.value = v.path || ""; f.serviceName.value = v.serviceName || ""; f.serverName.value = v.serverName || "";
    f.certFile.value = v.certFile || ""; f.keyFile.value = v.keyFile || "";
    if (r) {
      f.r_show.checked = !!r.show; f.r_xver.value = r.xver || 0; f.r_fp.value = r.fingerprint || "chrome";
      f.r_target.value = r.target || ""; f.r_sni.value = (r.serverNames || []).join(",");
      f.r_mtd.value = r.maxTimeDiff || 0; f.r_minv.value = r.minClientVer || ""; f.r_maxv.value = r.maxClientVer || "";
      f.r_sids.value = (r.shortIds || []).join(","); f.r_spx.value = r.spiderX || "/";
      f.r_priv.value = r.privateKey || ""; f.r_pub.value = ed.publicKey || "";
    } else { newSids(); newSpx(); newKeys(); }
  } else { newSids(); newSpx(); newKeys(); }
  $("#rSids").onclick = newSids; $("#rSpx").onclick = newSpx; $("#rKeys").onclick = newKeys;
  $("#rClear").onclick = () => { f.r_priv.value = ""; f.r_pub.value = ""; };
  f.r_priv.onchange = async () => {
    const v = f.r_priv.value.trim(); f.r_pub.value = "";
    if (v) try { f.r_pub.value = (await api("GET", "api/reality/keys?priv=" + encodeURIComponent(v))).publicKey; } catch (e) { $("#ibErr").textContent = e.message; }
  };
  $("#rCheck").onclick = async () => {
    const out = $("#rCheckOut"); out.textContent = t("rsWait");
    try {
      const r = (await api("POST", "api/reality/scan", { q: f.r_target.value.trim() })).results[0];
      out.innerHTML = !r ? "—" : r.feasible ? `<span class="pill ok">${t("rsOk")}</span> TLS ${esc(r.tls)} · ${esc(r.alpn)} · ${esc(r.keyEx)} · ${esc(r.cert)} · ${r.latency} ms`
        : `<span class="pill bad">${esc(r.reason || t("rsNo"))}</span>`;
      if (r && r.feasible && !f.r_sni.value.trim()) f.r_sni.value = r.sni;
    } catch (e) { out.textContent = e.message; }
  };
  const sync = () => {
    const net = f.network.value, sec = f.security.value, proto = f.protocol.value;
    const show = { path: ["ws", "xhttp", "httpupgrade"].includes(net), grpc: net === "grpc", sni: sec !== "none", reality: sec === "reality", tls: sec === "tls" };
    f.querySelectorAll("[data-show]").forEach((l) => l.classList.toggle("hidden", !show[l.dataset.show]));
    [...f.security.options].forEach((o) => (o.disabled = o.value === "reality" && !["vless", "trojan"].includes(proto)));
    if (f.security.selectedOptions[0].disabled) f.security.value = "tls";
  };
  f.addEventListener("change", (e) => {
    if (e.target.name === "certPick" && e.target.value !== "") {
      const c = certs[+e.target.value];
      f.certFile.value = c.certFile; f.keyFile.value = c.keyFile; f.serverName.value = c.domain;
    }
    sync();
  });
  sync();
  $("#ibCreate").onclick = async () => {
    const d = Object.fromEntries(new FormData(f)); d.port = +d.port; delete d.certPick;
    const list = (v) => (v || "").split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
    const sidList = (v) => { const a = (v || "").split(",").map((x) => x.trim()); const out = a.filter(Boolean); if (a.length > 1 && a.some((x) => !x)) out.push(""); return out; };
    if (d.security === "reality") d.reality = { show: !!f.r_show.checked, xver: +d.r_xver || 0, fingerprint: d.r_fp, target: (d.r_target || "").trim(),
      serverNames: list(d.r_sni), maxTimeDiff: +d.r_mtd || 0, minClientVer: (d.r_minv || "").trim(), maxClientVer: (d.r_maxv || "").trim(),
      shortIds: sidList(d.r_sids), spiderX: (d.r_spx || "").trim(), privateKey: (d.r_priv || "").trim() };
    Object.keys(d).filter((k) => k.startsWith("r_")).forEach((k) => delete d[k]);
    try {
      if (ed && d.network === ed.form.network) d.headerType = ed.form.headerType;
      if (ed) await api("POST", "api/inbounds/edit", { ...d, id: ed.id }); else await api("POST", "api/inbounds", d);
      closeModal(); toast(ed ? t("saved") : t("done")); refreshInbounds();
    } catch (e) { $("#ibErr").textContent = e.message; }
  };
}

function openAddClient(ib) {
  openModal(`<h3>${t("addClient")} · <span class="mono">${esc(ib.tag || ib.id)}</span></h3>
  <form id="clForm" class="form">
    <label>${t("name")}<input name="email" required pattern="[A-Za-z0-9._@+\\-]{1,64}" placeholder="ali"></label>
    <label>${t("expiryDays")}<input name="expiryDays" type="number" min="0" step="1" value="30"></label>
    <label>${t("limitGB")}<input name="limitGB" type="number" min="0" step="0.5" value="0"></label>
  </form>
  <p id="clErr" class="err"></p>
  <div class="actions"><button class="btn primary" id="clCreate">${t("create")}</button><button class="btn" data-close>${t("cancel")}</button></div>`);
  $("#clCreate").onclick = async () => {
    const d = Object.fromEntries(new FormData($("#clForm")));
    try {
      await api("POST", "api/clients", { inbound: ib.id, email: d.email.trim(), expiryDays: +d.expiryDays, limitGB: +d.limitGB });
      closeModal(); toast(t("done")); refreshInbounds();
    } catch (e) { $("#clErr").textContent = e.message; }
  };
}

function subURL(m) {
  return baseURL() + "/sub/" + m.subToken;
}

function copyRow(val) {
  return `<div class="copy"><input readonly value="${esc(val)}"><button class="btn small" data-copy="${esc(val)}">${t("copy")}</button></div>`;
}

function openClient(ib, cl) {
  const m = cl.meta || {};
  const sub = m.subToken ? subURL(m) : "";
  openModal(`<div class="row-between"><h3 class="mono">${esc(cl.email)}</h3>${clientStatus(cl)}</div>
    <p class="muted">${t("up")} ${fmtBytes(m.up)} · ${t("down")} ${fmtBytes(m.down)} · ${m.limitBytes ? fmtBytes(m.limitBytes) : t("unlimited")}</p>
    <label>${t("link")}</label>${copyRow(cl.link)}
    ${sub ? `<label>${t("sub")}</label>${copyRow(sub)}` : ""}
    ${cl.relayLinks && cl.relayLinks.length ? `<label>${t("relayLinks")}</label><div class="links-list">${cl.relayLinks.map(copyRow).join("")}</div>` : ""}
    <img class="qr" alt="QR" src="api/qr?text=${encodeURIComponent(sub || cl.link)}">
    <form id="edForm" class="form">
      <label>${t("setExpiry")}<input name="expiryDays" type="number" min="0" step="1" placeholder="${t("expiryDays")}"></label>
      <label>${t("setLimit")}<input name="limitGB" type="number" min="0" step="0.5" placeholder="${t("limitGB")}"></label>
    </form>
    <p id="edErr" class="err"></p>
    <div class="actions">
      <button class="btn primary" id="edSave">${cl.disabled ? t("save") + " + " + t("enable") : t("save")}</button>
      <button class="btn" id="edReset">${t("resetTraffic")}</button>
      <button class="btn danger" id="edDel">${t("del")}</button>
      <button class="btn ghost" data-close>${t("cancel")}</button>
    </div>`);
  const upd = async (extra) => {
    const d = Object.fromEntries(new FormData($("#edForm")));
    const body = { email: cl.email, ...extra };
    if (d.expiryDays !== "") { body.setExpiry = true; body.expiryDays = +d.expiryDays; }
    if (d.limitGB !== "") { body.setLimit = true; body.limitGB = +d.limitGB; }
    try { await api("POST", "api/clients/update", body); closeModal(); toast(t("saved")); refreshInbounds(); }
    catch (e) { $("#edErr").textContent = e.message; }
  };
  $("#edSave").onclick = () => upd({ enable: !!cl.disabled });
  $("#edReset").onclick = () => upd({ resetTraffic: true, enable: !!cl.disabled && cl.meta && cl.meta.reason === "traffic" });
  $("#edDel").onclick = guard(async () => {
    if (!confirm(t("confirmDelClient"))) return;
    await api("DELETE", `api/clients?inbound=${encodeURIComponent(ib.id)}&email=${encodeURIComponent(cl.email)}`);
    closeModal(); toast(t("done")); refreshInbounds();
  });
}

function swapAddr(link, addr, port) {
  if (!link) return "";
  if (link.startsWith("vmess://")) {
    try {
      const j = JSON.parse(atob(link.slice(8)));
      if (addr) j.add = addr; if (port) j.port = String(port); j.ps = (j.ps || "") + "-alt";
      return "vmess://" + btoa(JSON.stringify(j));
    } catch { return link; }
  }
  return link.replace(/@(\[[^\]]+\]|[^:/?#@]+):(\d+)/, (m, h, p) => "@" + (addr || h) + ":" + (port || p));
}
function openRelay(ids) {
  const ib = state.inbounds.find((x) => x.id === ids[0]);
  const sample = ib && ib.clients && ib.clients[0] ? ib.clients[0].link : (ib && ib.singleLink) || "";
  openModal(`<h3>${t("addRelay")}</h3>
  <p class="muted">${esc(ids.join(" · "))}</p>
  <p class="muted">${t("relayHint")}</p>
  <p class="muted small">${t("relayEx")}</p>
  <form id="rlForm" class="form">
    <label>${t("relayAddr")}<input name="address" required placeholder="cdn.example.com"></label>
    <label>${t("relayPort")}<input name="port" type="number" min="1" max="65535"></label>
    <label>${t("relayName")}<input name="name" placeholder="cdn"></label>
  </form>
  ${sample ? `<label>${t("relayBefore")}</label><pre class="log mono wrap">${esc(sample)}</pre>
  <label>${t("relayAfter")}</label><pre id="rlPrev" class="log mono wrap">${esc(sample)}</pre>` : `<p class="muted">${t("relayNoClient")}</p>`}
  <p id="rlErr" class="err"></p>
  <div class="actions"><button class="btn primary" id="rlSave">${t("save")}</button><button class="btn" data-close>${t("cancel")}</button></div>`, true);
  const prev = () => {
    if (!sample) return;
    const d = Object.fromEntries(new FormData($("#rlForm")));
    $("#rlPrev").innerHTML = esc(swapAddr(sample, d.address.trim(), +d.port || 0)).replace(/@([^:]+):(\d+)/, '@<mark>$1</mark>:<mark>$2</mark>');
  };
  $("#rlForm").addEventListener("input", prev);
  $("#rlSave").onclick = async () => {
    const d = Object.fromEntries(new FormData($("#rlForm")));
    try {
      await api("POST", "api/relays", { tags: ids, address: d.address.trim(), port: +d.port || 0, name: d.name.trim() });
      closeModal(); toast(t("done")); refreshInbounds();
    } catch (e) { $("#rlErr").textContent = e.message; }
  };
}
$("#tunSelBtn").onclick = guard(async () => {
  const ids = [...state.sel]; if (!ids.length) return;
  const d = await api("GET", "api/tunnels");
  if (!d.servers.length) { toast(d.ready ? t("tnNoSrv") : t("tnNeedSSL")); return; }
  openModal(`<h3>${t("tbTitle")} (${ids.length})</h3>
  <p class="muted">${t("tbHint")}</p>
  <div class="stack" id="tbList">${d.servers.map((s, i) => {
    const busy = ids.filter((id) => { const ib = state.inbounds.find((x) => x.id === id); return ib && (s.busy || []).includes(+ib.port) && !s.inbounds.includes(id); });
    return `<label class="pitem"><input type="radio" name="tbsrv" value="${esc(s.id)}" ${i === 0 ? "checked" : ""}><span class="dot${s.online ? "" : " bad"}"></span><b>${esc(s.name)}</b><small class="mono">${esc(s.publicIP || s.host || "")}</small>${busy.length ? `<small class="err">${esc(busy.join(", "))}: ${t("stBusy")}</small>` : ""}</label>`;
  }).join("")}</div>
  <div id="tbOut"></div>
  <p id="tbErr" class="err"></p>
  <div class="actions"><button class="btn primary" id="tbAdd">${t("tbAdd")}</button><button class="btn" id="tbRm">${t("tbRemove")}</button><button class="btn ghost" data-close>${t("cancel")}</button></div>`, true);
  const go = async (remove) => {
    const server = ($("#tbList").querySelector("input:checked") || {}).value;
    try {
      const r = await api("POST", "api/tunnels/bulk", { ids, server, remove });
      const skipped = r.skipped.length ? `<label>${t("tbSkipped")}</label>` + r.skipped.map((x) => `<p class="err mono">${esc(x.id)}: ${esc(x.reason)}</p>`).join("") : "";
      $("#tbAdd").disabled = $("#tbRm").disabled = true;
      // progress: wait until the middle server reports every port
      const want = ids.filter((id) => !r.skipped.some((x) => x.id === id));
      const t0 = Date.now();
      for (;;) {
        await refreshInbounds();
        let ready = 0;
        want.forEach((id) => {
          const ib = state.inbounds.find((x) => x.id === id);
          const tl = ib && (ib.tunnels || []).find((x) => x.server === server);
          if (remove ? !tl : tl && tl.state !== "pending") ready++;
        });
        const pct = want.length ? Math.round(ready * 100 / want.length) : 100;
        if (!$("#tbOut")) break;
        $("#tbOut").innerHTML = `<p>${t("tbProgress").replace("{a}", ready).replace("{b}", want.length)} · ${pct}%</p><div class="bar"><i style="width:${pct}%"></i></div>` + skipped;
        if (pct >= 100) { toast(t("tbDone").replace("{n}", r.done)); if (!skipped) setTimeout(closeModal, 800); break; }
        if (Date.now() - t0 > 120000) { $("#tbOut").insertAdjacentHTML("afterbegin", `<p class="err">${t("tbSlow")}</p>`); break; }
        await new Promise((ok) => setTimeout(ok, 2000));
      }
    } catch (e) { $("#tbErr").textContent = e.message; }
  };
  $("#tbAdd").onclick = () => go(false);
  $("#tbRm").onclick = () => go(true);
});
$("#delSelBtn").onclick = guard(async () => {
  const ids = [...state.sel]; if (!ids.length) return;
  if (!confirm(t("confirmDelSel").replace("{n}", ids.length))) return;
  await api("POST", "api/inbounds/delete", { ids }); state.sel.clear(); toast(t("done")); refreshInbounds();
});

// ---------- clients tab ----------
let userData = null;
async function loadUsers() {
  try { userData = await api("GET", "api/users"); } catch (e) { $("#userList").innerHTML = `<div class="card empty">${esc(e.message)}</div>`; return; }
  renderUsers();
}
function ibLabel(id) {
  const x = userData.inbounds.find((i) => i.id === id);
  return x ? `${x.tag || x.id} · ${x.protocol}${x.network ? "/" + x.network : ""} · :${x.port}` : id;
}
function renderUsers() {
  const d = userData; if (!d) return;
  if (!d.clients.length) { $("#userList").innerHTML = `<div class="card empty">${t("noUsers")}</div>`; return; }
  $("#userList").innerHTML = d.clients.map((u, i) => {
    const used = (u.up || 0) + (u.down || 0);
    const pct = u.limitBytes ? Math.min(100, (used / u.limitBytes) * 100) : 0;
    const cl = { meta: u, disabled: u.disabled };
    return `<div class="card">
      <div class="ib-head">
        <div class="ib-title"><b class="mono">${esc(u.email)}</b>${clientStatus(cl)}
          <span class="pill gray">${fmtBytes(used)} / ${u.limitBytes ? fmtBytes(u.limitBytes) : t("unlimited")}</span></div>
        <div class="actions">
          <button class="btn small primary" data-u="edit" data-i="${i}">${t("editUser")}</button>
          <button class="btn small" data-u="qr" data-i="${i}">QR</button>
          <button class="btn small danger" data-u="del" data-i="${i}">${t("del")}</button>
        </div>
      </div>
      ${u.limitBytes ? `<div class="bar"><i style="width:${pct}%"></i></div>` : ""}
      <p class="muted">${t("inbounds")}: ${u.inbounds.length ? u.inbounds.map((x) => `<span class="chip">${esc(ibLabel(x))}</span>`).join("") : t("noInboundsYet")}</p>
      ${copyRow(subURL(u))}
    </div>`;
  }).join("");
}
$("#userList").addEventListener("click", guard(async (e) => {
  const cp = e.target.closest("[data-copy]"); if (cp) { copyText(cp.dataset.copy); return; }
  const b = e.target.closest("button[data-u]"); if (!b) return;
  const u = userData.clients[+b.dataset.i];
  if (b.dataset.u === "del") {
    if (!confirm(t("confirmDelUser"))) return;
    await api("DELETE", "api/users?email=" + encodeURIComponent(u.email)); toast(t("done")); loadUsers(); refreshInbounds();
  } else if (b.dataset.u === "qr") {
    openModal(`<h3 class="mono">${esc(u.email)}</h3>${copyRow(subURL(u))}<img class="qr" alt="QR" src="api/qr?text=${encodeURIComponent(subURL(u))}"><div class="actions"><button class="btn" data-close>${t("cancel")}</button></div>`);
  } else openUser(u);
}));
$("#addUserBtn").onclick = guard(async () => { if (!userData) await loadUsers(); openUser(null); });
function openUser(u) {
  const isNew = !u;
  const boxes = userData.inbounds.map((x) => `<label class="pitem"><input type="checkbox" value="${esc(x.id)}" ${u && u.inbounds.includes(x.id) ? "checked" : ""}><span class="mono">${esc(ibLabel(x.id))}</span></label>`).join("");
  openModal(`<h3>${isNew ? t("addUser") : esc(u.email)}</h3>
  <form id="usForm" class="form">
    ${isNew ? `<label>${t("name")}<input name="email" required pattern="[A-Za-z0-9._@+\\-]{1,64}" placeholder="ali"></label>` : ""}
    <label>${isNew ? t("expiryDays") : t("setExpiry")}<input name="expiryDays" type="number" min="0" step="1" ${isNew ? 'value="30"' : `placeholder="${t("expiryDays")}"`}></label>
    <label>${isNew ? t("limitGB") : t("setLimit")}<input name="limitGB" type="number" min="0" step="0.5" ${isNew ? 'value="0"' : `placeholder="${t("limitGB")}"`}></label>
  </form>
  <div class="pickhead"><label>${t("pickInbounds")}</label>${boxes ? `<span><button type="button" class="btn small" id="usAll">${t("selAll")}</button> <button type="button" class="btn small" id="usNone">${t("selNone")}</button></span>` : ""}</div>
  <div class="pgrid" id="usIbs">${boxes || `<p class="muted">${t("noInbounds")}</p>`}</div>
  <p id="usErr" class="err"></p>
  <div class="actions">
    <button class="btn primary" id="usSave">${isNew ? t("create") : u.disabled ? t("save") + " + " + t("enable") : t("save")}</button>
    ${isNew ? "" : `<button class="btn" id="usReset">${t("resetTraffic")}</button>`}
    <button class="btn ghost" data-close>${t("cancel")}</button>
  </div>`, true);
  const collect = (extra) => {
    const d = Object.fromEntries(new FormData($("#usForm")));
    const inbounds = [...$("#usIbs").querySelectorAll("input:checked")].map((x) => x.value);
    if (isNew) return { email: d.email.trim(), expiryDays: +d.expiryDays, limitGB: +d.limitGB, inbounds };
    const body = { email: u.email, inbounds, setInbounds: true, enable: !!u.disabled, ...extra };
    if (d.expiryDays !== "") { body.setExpiry = true; body.expiryDays = +d.expiryDays; }
    if (d.limitGB !== "") { body.setLimit = true; body.limitGB = +d.limitGB; }
    return body;
  };
  const go = async (extra) => {
    try {
      await api("POST", isNew ? "api/users" : "api/users/edit", collect(extra));
      closeModal(); toast(t("saved")); loadUsers(); refreshInbounds();
    } catch (e) { $("#usErr").textContent = e.message; }
  };
  $("#usSave").onclick = () => go({});
  if (boxes) {
    const setAll = (v) => $("#usIbs").querySelectorAll("input[type=checkbox]").forEach((x) => (x.checked = v));
    $("#usAll").onclick = () => setAll(true); $("#usNone").onclick = () => setAll(false);
  }
  if (!isNew) $("#usReset").onclick = () => go({ resetTraffic: true });
}
$("#relaySelBtn").onclick = () => openRelay([...state.sel]);
$("#portsBtn").onclick = () => {
  const ports = [...new Set(state.inbounds.filter((i) => !i.system).flatMap((i) => String(i.port).split(",")).map((p) => p.trim()).filter(Boolean))]
    .sort((a, b) => parseInt(a) - parseInt(b));
  const text = ports.join(",");
  openModal(`<h3>${t("portsTitle")} (${ports.length})</h3>
  <p class="muted">${t("portsHint")}</p>
  <textarea id="portsText" class="mono ports" rows="5" readonly>${esc(text)}</textarea>
  <div class="actions"><button class="btn primary" id="portsCopy">${t("copy")}</button><button class="btn" data-close>${t("cancel")}</button></div>`);
  $("#portsText").onclick = (e) => e.target.select();
  $("#portsCopy").onclick = () => copyText(text);
};
$("#selAll").onchange = (e) => {
  state.sel = new Set(e.target.checked ? state.inbounds.filter((i) => !i.system).map((i) => i.id) : []);
  render();
};

$("#quickBtn").onclick = guard(async () => {
  const r = await api("GET", "api/presets");
  const groups = [["reality", t("gReality")], ["tls", t("gTls") + (r.certDomain ? " · " + r.certDomain : "")], ["plain", t("gPlain")], ["ss", t("gSS")], ["proxy", t("gProxy")]];
  const item = (p) => {
    const dis = !p.available;
    const on = !dis && !p.exists;
    const tag = dis ? t("needCert") : p.exists ? t("exists") : p.note || "";
    return `<label class="pitem ${dis ? "off" : ""}"><input type="checkbox" value="${p.id}" ${on ? "checked" : ""} ${dis ? "disabled" : ""}>${esc(p.label)}<small>${esc(tag)}</small></label>`;
  };
  openModal(`<h3>${t("quickTitle")}</h3>
    <p class="muted">${t("quickHint")}</p>
    <div class="actions"><button class="btn small" id="qAll">${t("all")}</button><button class="btn small" id="qNone">${t("none")}</button></div>
    <div class="presets" id="qList">${groups.map(([g, title]) => `<div class="pgroup"><h4>${esc(title)}</h4><div class="pgrid">${r.presets.filter((p) => p.group === g).map(item).join("")}</div></div>`).join("")}</div>
    <form id="qForm" class="form" style="grid-template-columns:2fr 1fr 1fr">
      <label>${t("clientName")}<input name="client" value="user1" pattern="[A-Za-z0-9._@+\\-]{1,64}"></label>
      <label>${t("expiryDays")}<input name="expiryDays" type="number" min="0" value="30"></label>
      <label>${t("limitGB")}<input name="limitGB" type="number" min="0" step="0.5" value="0"></label>
      <label style="grid-column:1/-1">${t("dest")} (REALITY)<span class="inrow"><input name="dest" placeholder="www.microsoft.com:443"><input name="sni" placeholder="SNI" style="max-width:40%"><button type="button" class="btn small" id="qScan">🔍 ${t("rsFind")}</button></span></label>
    </form>
    <p id="qErr" class="err"></p>
    <div class="actions"><button class="btn primary" id="qCreate"></button><button class="btn" data-close>${t("cancel")}</button></div>`, true);
  const boxes = () => [...$("#qList").querySelectorAll("input:not(:disabled)")];
  const count = () => { $("#qCreate").textContent = t("createN") + " (" + boxes().filter((b) => b.checked).length + ")"; };
  $("#qList").onchange = count; count();
  $("#qScan").onclick = () => openRealityScan((x) => { $("#qForm").dest.value = x.target; $("#qForm").sni.value = x.sni; }, true);
  $("#qAll").onclick = () => { boxes().forEach((b) => (b.checked = true)); count(); };
  $("#qNone").onclick = () => { boxes().forEach((b) => (b.checked = false)); count(); };
  $("#qCreate").onclick = async () => {
    const ids = boxes().filter((b) => b.checked).map((b) => b.value);
    const d = Object.fromEntries(new FormData($("#qForm")));
    $("#qCreate").disabled = true;
    try {
      const res = await api("POST", "api/presets", { ids, client: d.client.trim(), expiryDays: +d.expiryDays, limitGB: +d.limitGB, dest: d.dest.trim(), sni: d.sni.trim() });
      closeModal(); toast(t("done") + " · " + res.created.length); refreshInbounds();
    } catch (e) { $("#qErr").textContent = e.message; $("#qCreate").disabled = false; }
  };
});

// ---------- core actions ----------
$("#installBtn").onclick = guard(async () => {
  const c = state.status.core;
  await api("POST", "api/core/install", { action: c.installed ? "update" : "install", version: $("#verInput").value.trim() });
  pollJob(true);
});
$("#restartBtn").onclick = guard(async () => { await api("POST", "api/core/restart"); toast(t("done")); refreshStatus(); });
$("#apiBtn").onclick = guard(async () => {
  if (!confirm(t("confirmApi"))) return;
  await api("POST", "api/core/enable-api"); toast(t("done")); await refreshStatus(); refreshInbounds();
});

async function pollJob(force) {
  let j;
  try { j = await api("GET", "api/core/job"); } catch { return; }
  state.job = j;
  const log = $("#jobLog");
  if (j.running || force || j.log) {
    log.classList.remove("hidden");
    log.textContent = (j.running ? t("jobRunning") : j.ok ? t("jobOk") : t("jobFail")) + "\n\n" + (j.log || "");
    log.scrollTop = log.scrollHeight;
  }
  renderOverview();
  if (j.running || force) setTimeout(() => pollJob(false), 1200);
  else if (j.action) { await refreshStatus(); refreshInbounds(); }
}

// ---------- settings ----------
async function loadSettings() {
  const s = state.status.settings, f = $("#settingsForm");
  f.publicHost.value = s.publicHost || ""; f.subBase.value = s.subBase || "";
  const list = await api("GET", "api/backups");
  $("#backupList").innerHTML = list.length ? list.map((n) => `<div class="item"><span class="mono">${esc(n)}</span><button class="btn small" data-restore="${esc(n)}">${t("restore")}</button></div>`).join("") : `<p class="muted">—</p>`;
}
$("#settingsForm").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  const d = Object.fromEntries(new FormData(e.target));
  await api("POST", "api/settings", d); toast(t("saved")); await refreshStatus(); refreshInbounds();
}));
$("#backupList").addEventListener("click", guard(async (e) => {
  const b = e.target.closest("[data-restore]"); if (!b) return;
  if (!confirm(t("confirmRestore"))) return;
  await api("POST", "api/backups/restore", { name: b.dataset.restore }); toast(t("done")); loadSettings(); refreshInbounds();
}));
$("#loadRaw").onclick = guard(async () => {
  const pre = $("#rawConfig"); pre.textContent = await api("GET", "api/config"); pre.classList.remove("hidden");
});

applyLang();
boot();
setInterval(async () => {
  if ($("#app").classList.contains("hidden") || !state.status) return;
  try { state.status = await api("GET", "api/status"); renderOverview(); } catch {}
}, 15000);

// ---------- tunnels ----------
let tunnelData = null;
function ago(sec) {
  if (sec < 60) return sec + "s";
  if (sec < 3600) return Math.floor(sec / 60) + "m";
  if (sec < 86400) return Math.floor(sec / 3600) + "h";
  return Math.floor(sec / 86400) + "d";
}
async function loadTunnels() {
  try { tunnelData = await api("GET", "api/tunnels"); } catch (e) { return; }
  renderTunnels();
}
const tnTestRes = {};
function renderTunnels() {
  const d = tunnelData; if (!d) return;
  $("#tunnelInfo").textContent = d.ready ? t("tnInfo").replace("{port}", d.port || "—").replace("{domain}", d.domain) : t("tnNeedSSL");
  $("#addTunnelBtn").disabled = !d.ready;
  if (!d.servers.length) { $("#tunnelList").innerHTML = `<div class="card empty">${t("tnNoSrv")}</div>`; return; }
  const now = Date.now() / 1000;
  $("#tunnelList").innerHTML = d.servers.map((s, i) => {
    const seen = s.lastSeen ? ago(Math.max(0, Math.round(now - s.lastSeen))) + " " + t("tnAgo") : t("tnNever");
    return `<div class="card">
      <div class="ib-head">
        <div class="ib-title"><span class="dot${s.online ? "" : " bad"}"></span><b>${esc(s.name)}</b>
          <span class="pill gray">${esc(s.method)}</span>
          <span class="pill ${s.online ? "" : "warn"}">${s.online ? t("tnOnline") : t("tnOffline")} · ${esc(seen)}</span>
          ${s.publicIP || s.host ? `<span class="pill gray mono">${esc(s.publicIP || s.host)}</span>` : ""}
          ${s.agentVer ? `<span class="pill gray">v${esc(s.agentVer)}</span>` : ""}</div>
        <div class="actions">
          ${s.host ? `<button class="btn small primary" data-tn="deploy" data-i="${i}">${t("tnDeploy")}</button>` : ""}
          <button class="btn small" data-tn="test" data-i="${i}">${t("tnTest")}</button>
          <button class="btn small" data-tn="join" data-i="${i}">${t("tnNewCmd")}</button>
          <button class="btn small danger" data-tn="del" data-i="${i}">${t("del")}</button>
        </div>
      </div>
      <p class="muted">${t("tnInbounds")}: ${s.inbounds.length ? s.inbounds.map((x) => `<span class="chip">${esc(x)}</span>`).join("") : "—"}</p>
      ${tnTestRes[s.id] ? `<p class="${tnTestRes[s.id].ok ? "okmsg" : "err"}">${esc(tnTestRes[s.id].text)}</p>` : ""}
      ${s.lastFail ? `<p class="muted small">${t("tnLastFail")}: ${esc(s.failAt ? ago(Math.max(0, Math.round(now - s.failAt))) + " " + t("tnAgo") : "")} · ${t("tnFails").replace("{n}", s.fails || 0)} · <span class="mono">${esc(s.lastFail)}</span></p>` : ""}
      ${s.xrayErr ? `<p class="err">${t("tnXrayErr")}: ${esc(s.xrayErr)}</p>` : ""}
      ${s.command ? `<div class="clients"><p class="muted">${t("tnQuick")}</p>${copyRow(s.command)}</div>` : ""}
      <details class="muted small-details"><summary>${t("tnRemove").replace(/[:：]$/, "")}</summary>${copyRow(s.remove)}</details>
    </div>`;
  }).join("");
}
$("#tunnelList").addEventListener("click", guard(async (e) => {
  const cp = e.target.closest("[data-copy]"); if (cp) { copyText(cp.dataset.copy); return; }
  const b = e.target.closest("button[data-tn]"); if (!b) return;
  const s = tunnelData.servers[+b.dataset.i];
  if (b.dataset.tn === "del") {
    if (!confirm(t("tnConfirmDel"))) return;
    await api("DELETE", "api/tunnels/" + s.id); toast(t("done")); loadTunnels(); refreshInbounds();
  } else if (b.dataset.tn === "join") {
    await api("POST", "api/tunnels/" + s.id + "/join"); loadTunnels();
  } else if (b.dataset.tn === "deploy") openDeploy(s);
  else if (b.dataset.tn === "test") {
    tnTestRes[s.id] = { ok: true, text: t("tnTesting") }; renderTunnels();
    try {
      const r = await api("POST", "api/tunnels/" + s.id + "/test");
      tnTestRes[s.id] = r.ok ? { ok: r.xrayOk !== false, text: t("tnTestOk").replace("{ms}", r.ms) + (r.xrayErr ? " · " + r.xrayErr : "") }
        : { ok: false, text: t("tnTestBad") + (r.lastFail ? " · " + r.lastFail : "") };
    } catch (err) { tnTestRes[s.id] = { ok: false, text: err.message }; }
    loadTunnels();
  }
}));
function openDeploy(s) {
  openModal(`<h3>${t("tnDeploy")} · ${esc(s.name)}</h3>
  <p class="muted mono">${esc(s.sshUser)}@${esc(s.host)}:${s.sshPort}</p>
  <form id="dpForm" class="form">
    ${s.keyInstalled ? `<p class="muted">${t("tnPassKey")}</p>` : ""}
    <label>${t("tnPass")}<input name="password" type="password" autocomplete="off"></label>
  </form>
  <p id="dpErr" class="err"></p><pre id="dpLog" class="log hidden"></pre>
  <div class="actions"><button class="btn primary" id="dpGo">${t("tnDeploy")}</button><button class="btn" data-close>${t("cancel")}</button></div>`, true);
  $("#dpForm").addEventListener("submit", (e) => { e.preventDefault(); $("#dpGo").click(); });
  $("#dpGo").onclick = async () => {
    const pw = $("#dpForm").password.value;
    $("#dpGo").disabled = true; $("#dpErr").textContent = ""; $("#dpLog").classList.remove("hidden"); $("#dpLog").textContent = t("tnDeploying");
    try {
      const r = await api("POST", "api/tunnels/" + s.id + "/deploy", { password: pw });
      $("#dpLog").textContent = r.log || ""; toast(t("done")); loadTunnels();
    } catch (e) { $("#dpErr").textContent = e.message; $("#dpLog").textContent = ""; }
    $("#dpForm").password.value = ""; $("#dpGo").disabled = false;
  };
}
$("#addTunnelBtn").onclick = () => {
  openModal(`<h3>${t("addTunnel")}</h3>
  <form id="tnForm" class="form">
    <label>${t("tnName")}<input name="name" placeholder="iran-1"></label>
    <label>${t("tnMethod")}<select name="method"><option value="wss">WSS (WebSocket + TLS)</option></select></label>
    <details><summary>${t("tnSshOpt")}</summary>
    <label>${t("tnHost")}<input name="host" placeholder="1.2.3.4"></label>
    <label>${t("tnSshPort")}<input name="sshPort" type="number" min="1" max="65535" value="22"></label>
    <label>${t("tnSshUser")}<input name="sshUser" value="root"></label>
    </details>
  </form>
  <p id="tnErr" class="err"></p>
  <div class="actions"><button class="btn primary" id="tnSave">${t("create")}</button><button class="btn" data-close>${t("cancel")}</button></div>`);
  $("#tnForm").addEventListener("submit", (e) => { e.preventDefault(); $("#tnSave").click(); });
  $("#tnSave").onclick = async () => {
    const d = Object.fromEntries(new FormData($("#tnForm"))); d.sshPort = +d.sshPort || 22;
    try {
      const r = await api("POST", "api/tunnels", d);
      closeModal(); await loadTunnels(); refreshInbounds();
      const s = tunnelData.servers.find((x) => x.id === r.id);
      if (s && s.host) openDeploy(s);
      else if (s && s.command) openModal(`<h3>${t("tnCmdTitle")} · ${esc(s.name)}</h3><p class="muted">${t("tnQuick")}</p>${copyRow(s.command)}<div class="actions"><button class="btn" data-close>${t("cancel")}</button></div>`, true);
    } catch (e) { $("#tnErr").textContent = e.message; }
  };
};
async function openTunnelPick(ib) {
  const d = await api("GET", "api/tunnels"); tunnelData = d;
  if (!d.servers.length) { toast(d.ready ? t("tnNoSrv") : t("tnNeedSSL")); return; }
  const row = (s) => {
    const on = s.inbounds.includes(ib.id);
    const port = on && s.ports[ib.id] ? s.ports[ib.id] : "";
    return `<div class="tnrow" data-id="${esc(s.id)}">
      <label class="pitem"><input type="checkbox" ${on ? "checked" : ""}><span class="dot${s.online ? "" : " bad"}"></span><b>${esc(s.name)}</b><small class="mono">${esc(s.publicIP || s.host || "")}</small></label>
      <label class="tnport">${t("tnPortHere")}<input type="number" min="1" max="65535" placeholder="${esc(ib.port)}" value="${port}"></label>
      <small class="err tnbusy"></small></div>`;
  };
  openModal(`<h3>${t("tnUse")} · <span class="mono">${esc(ib.tag || ib.id)}</span></h3>
  <p class="muted">${t("tnPick")}</p>
  <div class="stack">${d.servers.map(row).join("")}</div>
  <p id="tpErr" class="err"></p>
  <div class="actions"><button class="btn primary" id="tpSave">${t("save")}</button><button class="btn" data-close>${t("cancel")}</button></div>`, true);
  const check = (el) => {
    const s = d.servers.find((x) => x.id === el.dataset.id);
    const inp = el.querySelector(".tnport input");
    const p = +(inp.value || ib.port);
    const mine = s.inbounds.includes(ib.id) && (s.ports[ib.id] || +ib.port) === p;
    el.querySelector(".tnbusy").textContent = !mine && (s.busy || []).includes(p) ? `${p}: ${t("tnBusy")}` : "";
  };
  $("#modalBody").querySelectorAll(".tnrow").forEach((el) => { check(el); el.querySelector(".tnport input").oninput = () => check(el); });
  $("#tpSave").onclick = async () => {
    const uses = [...$("#modalBody").querySelectorAll(".tnrow")].filter((el) => el.querySelector("input[type=checkbox]").checked)
      .map((el) => ({ server: el.dataset.id, port: +el.querySelector(".tnport input").value || 0 }));
    try { await api("POST", "api/tunnels/assign", { id: ib.id, uses }); closeModal(); toast(t("done")); refreshInbounds(); }
    catch (e) { $("#tpErr").textContent = e.message; }
  };
}
setInterval(() => { if (state.view === "tunnels" && !$("#app").classList.contains("hidden")) loadTunnels(); }, 15000);

// ---------- REALITY target scanner ----------
function openRealityScan(use) {
  const box = document.createElement("div");
  box.className = "rsOverlay";
  box.innerHTML = `<div class="card rsCard"><h3>${t("rsTitle")}</h3><p class="muted">${t("rsHint")}</p>
    <div class="inrow"><input id="rsQ" placeholder="${t("rsPh")}" dir="ltr"><button class="btn primary" id="rsGo">${t("rsScan")}</button></div>
    <p id="rsMsg" class="muted"></p>
    <div class="rsWrap"><table class="rsTable"><thead><tr><th>Target</th><th>${t("rsStatus")}</th><th>TLS</th><th>ALPN</th><th>Key</th><th>${t("rsCert")}</th><th>${t("rsLatency")}</th><th></th></tr></thead><tbody id="rsBody"></tbody></table></div>
    <div class="actions"><button class="btn" id="rsClose">${t("close")}</button></div></div>`;
  document.body.appendChild(box);
  const close = () => box.remove();
  box.querySelector("#rsClose").onclick = close;
  box.onclick = (e) => { if (e.target === box) close(); };
  let rows = [];
  const go = async () => {
    const q = box.querySelector("#rsQ").value.trim();
    box.querySelector("#rsGo").disabled = true;
    box.querySelector("#rsMsg").textContent = t("rsWait");
    box.querySelector("#rsBody").innerHTML = "";
    try {
      const r = await api("POST", "api/reality/scan", { q });
      rows = r.results;
      box.querySelector("#rsMsg").textContent = t("rsCount").replace("{a}", rows.filter((x) => x.feasible).length).replace("{b}", r.scanned);
      box.querySelector("#rsBody").innerHTML = rows.map((x, i) => `<tr>
        <td class="mono">${esc(x.sni && !x.target.startsWith(x.sni) ? x.target + " · " + x.sni : x.target)}</td>
        <td>${x.feasible ? `<span class="pill ok">${t("rsOk")}</span>` : `<span class="pill bad" title="${esc(x.reason || "")}">${esc(x.reason || t("rsNo"))}</span>`}</td>
        <td>${esc(x.tls || "—")}</td><td>${esc(x.alpn || "—")}</td><td>${esc(x.keyEx || "—")}</td>
        <td class="mono">${esc(x.cert || "—")}</td><td>${x.latency ? x.latency + " ms" : "—"}</td>
        <td>${x.feasible ? `<button class="btn small" data-use="${i}">${t("rsUse")}</button>` : ""}</td></tr>`).join("");
    } catch (e) { box.querySelector("#rsMsg").textContent = e.message; }
    box.querySelector("#rsGo").disabled = false;
  };
  box.querySelector("#rsGo").onclick = go;
  box.querySelector("#rsQ").onkeydown = (e) => { if (e.key === "Enter") go(); };
  box.querySelector("#rsBody").onclick = (e) => {
    const b = e.target.closest("[data-use]"); if (!b) return;
    use(rows[+b.dataset.use]); close(); toast(t("done"));
  };
  go();
}
