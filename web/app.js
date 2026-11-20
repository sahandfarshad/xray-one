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
    createN: "ساختن", relay: "Relay", addRelay: "افزودن Relay", relaySel: "Relay برای انتخاب‌شده‌ها", relayAddr: "IP یا دامنه‌ی relay",
    relayPort: "پورت relay (خالی = همان پورت اینباند)", relayName: "اسم (اختیاری)", relayHint: "لینک‌ها یک نسخه‌ی اضافه با این آدرس می‌گیرند؛ SNI و REALITY همان سرور اصلی می‌ماند.",
    relayLinks: "لینک‌های relay", singleUser: "تک‌کاربره", confirmDelRelay: "این relay حذف شود؟",
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
    createN: "Create", relay: "Relay", addRelay: "Add relay", relaySel: "Relay for selected", relayAddr: "Relay IP or domain",
    relayPort: "Relay port (empty = inbound port)", relayName: "Name (optional)", relayHint: "Links get an extra copy with this address; SNI and REALITY stay those of the real server.",
    relayLinks: "Relay links", singleUser: "single user", confirmDelRelay: "Remove this relay?",
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
document.querySelectorAll("#tabs button").forEach((b) => (b.onclick = () => { state.view = b.dataset.view; render(); if (state.view === "settings") loadSettings(); }));

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
    const clients = !ib.managed ? "" : ib.clients.length === 0
      ? `<div class="clients"><p class="muted">${t("noClients")}</p></div>`
      : `<div class="clients">${ib.clients.map((cl, ci) => {
          const m = cl.meta || {}; const used = (m.up || 0) + (m.down || 0);
          const pct = m.limitBytes ? Math.min(100, (used / m.limitBytes) * 100) : 0;
          return `<div class="client">
            <div class="name">${esc(cl.email || "—")}</div>
            <div>${clientStatus(cl)}</div>
            <div class="muted">${fmtBytes(used)} / ${m.limitBytes ? fmtBytes(m.limitBytes) : t("unlimited")}
              ${m.limitBytes ? `<div class="bar"><i style="width:${pct}%"></i></div>` : ""}</div>
            <div class="actions"><button class="btn small" data-act="client" data-i="${idx}" data-c="${ci}">${t("details")}</button></div>
          </div>`;
        }).join("")}</div>`;
    return `<div class="card">
      <div class="ib-head">
        <div class="ib-title">${ib.system ? "" : `<input type="checkbox" data-sel="${esc(ib.id)}" ${state.sel.has(ib.id) ? "checked" : ""}>`}<b>${esc(ib.tag || ib.id)}</b>${pills}<span class="pill">:${esc(ib.port)}</span>
          ${ib.system ? `<span class="pill gray">${t("system")}</span>` : !ib.managed ? `<span class="pill gray">${t("unmanaged")}</span>` : ""}</div>
        <div class="actions">
          ${ib.managed ? `<button class="btn small primary" data-act="addClient" data-i="${idx}">${t("addClient")}</button>` : ""}
          ${ib.system ? "" : `<button class="btn small" data-act="relay" data-i="${idx}">+ ${t("relay")}</button>`}
          ${ib.system ? "" : `<button class="btn small danger" data-act="delInbound" data-i="${idx}">${t("del")}</button>`}
        </div>
      </div>
      ${ib.relays && ib.relays.length ? `<div class="relays"><span class="muted">${t("relay")}:</span>${ib.relays.map((r, ri) =>
        `<span class="chip">${esc((r.name ? r.name + " · " : "") + r.address + (r.port ? ":" + r.port : ""))}<button title="${t("del")}" data-act="delRelay" data-i="${idx}" data-r="${ri}">×</button></span>`).join("")}</div>` : ""}
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
  } else if (b.dataset.act === "addClient") openAddClient(ib);
  else if (b.dataset.act === "client") openClient(ib, ib.clients[+b.dataset.c]);
  else if (b.dataset.act === "relay") openRelay([ib.id]);
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

$("#addInboundBtn").onclick = guard(async () => {
  const [fp, certs] = await Promise.all([api("GET", "api/freeport"), api("GET", "api/certs")]);
  const certOpts = certs.map((c, i) => `<option value="${i}">${esc(c.domain)} · ${esc(c.source)}</option>`).join("");
  openModal(`<h3>${t("addInbound")}</h3>
  <form id="ibForm" class="form">
    <label>${t("protocol")}<select name="protocol"><option>vless</option><option>vmess</option><option>trojan</option><option value="shadowsocks">shadowsocks 2022</option></select></label>
    <label>${t("port")}<input name="port" type="number" min="1" max="65535" value="${fp.port || ""}" required></label>
    <label>${t("network")}<select name="network"><option>tcp</option><option>ws</option><option>grpc</option><option>xhttp</option><option>httpupgrade</option></select></label>
    <label>${t("security")}<select name="security"><option>reality</option><option>tls</option><option>none</option></select></label>
    <label>${t("tag")}<input name="tag"></label>
    <label data-show="path">${t("path")}<input name="path" placeholder="/"></label>
    <label data-show="grpc">${t("serviceName")}<input name="serviceName"></label>
    <label data-show="sni">${t("serverName")}<input name="serverName" placeholder="www.microsoft.com"></label>
    <label data-show="reality">${t("dest")}<input name="dest" placeholder="www.microsoft.com:443"></label>
    ${certs.length ? `<label data-show="tls">${t("pickCert")}<select name="certPick"><option value="">—</option>${certOpts}</select></label>` : ""}
    <label data-show="tls">${t("certFile")}<input name="certFile" placeholder="/etc/letsencrypt/live/…/fullchain.pem"></label>
    <label data-show="tls">${t("keyFile")}<input name="keyFile" placeholder="/etc/letsencrypt/live/…/privkey.pem"></label>
  </form>
  <p id="ibErr" class="err"></p>
  <div class="actions"><button class="btn primary" id="ibCreate">${t("create")}</button><button class="btn" data-close>${t("cancel")}</button></div>`);
  const f = $("#ibForm");
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
    try { await api("POST", "api/inbounds", d); closeModal(); toast(t("done")); refreshInbounds(); }
    catch (e) { $("#ibErr").textContent = e.message; }
  };
});

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

function openRelay(ids) {
  openModal(`<h3>${t("addRelay")}</h3>
  <p class="muted">${esc(ids.map((id) => id).join(" · "))}</p>
  <form id="rlForm" class="form">
    <label>${t("relayAddr")}<input name="address" required placeholder="1.2.3.4"></label>
    <label>${t("relayPort")}<input name="port" type="number" min="1" max="65535"></label>
    <label>${t("relayName")}<input name="name" placeholder="iran-relay"></label>
  </form>
  <p class="muted">${t("relayHint")}</p>
  <p id="rlErr" class="err"></p>
  <div class="actions"><button class="btn primary" id="rlSave">${t("save")}</button><button class="btn" data-close>${t("cancel")}</button></div>`);
  $("#rlSave").onclick = async () => {
    const d = Object.fromEntries(new FormData($("#rlForm")));
    try {
      await api("POST", "api/relays", { tags: ids, address: d.address.trim(), port: +d.port || 0, name: d.name.trim() });
      closeModal(); toast(t("done")); refreshInbounds();
    } catch (e) { $("#rlErr").textContent = e.message; }
  };
}
$("#relaySelBtn").onclick = () => openRelay([...state.sel]);

$("#quickBtn").onclick = guard(async () => {
  const r = await api("GET", "api/presets");
  const groups = [["reality", t("gReality")], ["tls", t("gTls") + (r.certDomain ? " · " + r.certDomain : "")], ["plain", t("gPlain")]];
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
    </form>
    <p id="qErr" class="err"></p>
    <div class="actions"><button class="btn primary" id="qCreate"></button><button class="btn" data-close>${t("cancel")}</button></div>`, true);
  const boxes = () => [...$("#qList").querySelectorAll("input:not(:disabled)")];
  const count = () => { $("#qCreate").textContent = t("createN") + " (" + boxes().filter((b) => b.checked).length + ")"; };
  $("#qList").onchange = count; count();
  $("#qAll").onclick = () => { boxes().forEach((b) => (b.checked = true)); count(); };
  $("#qNone").onclick = () => { boxes().forEach((b) => (b.checked = false)); count(); };
  $("#qCreate").onclick = async () => {
    const ids = boxes().filter((b) => b.checked).map((b) => b.value);
    const d = Object.fromEntries(new FormData($("#qForm")));
    $("#qCreate").disabled = true;
    try {
      const res = await api("POST", "api/presets", { ids, client: d.client.trim(), expiryDays: +d.expiryDays, limitGB: +d.limitGB });
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
