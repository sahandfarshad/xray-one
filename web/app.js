try { const th = localStorage.getItem("xo_theme"); if (th) document.documentElement.dataset.theme = th; } catch (e) {}
"use strict";
let lang = localStorage.getItem("xo_lang") || "en";
if (!T[lang]) lang = "en";
const langMeta = (c) => XO_LANGS.find((l) => l[0] === c) || XO_LANGS[0];
const locale = () => ({ fa: "fa-IR", en: "en-GB", zh: "zh-CN" }[lang] || lang);
const sep = () => t("listSep");
const t = (k) => (T[lang] && T[lang][k]) || T.en[k] || k;
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let state = { status: null, inbounds: [], host: "", job: null, view: "overview", sel: new Set() };

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = langMeta(lang)[3] ? "rtl" : "ltr";
  document.querySelectorAll("[data-t]").forEach((el) => (el.textContent = t(el.dataset.t)));
  document.querySelectorAll("[data-qm]").forEach((el) => (el.innerHTML = qm(el.dataset.qm)));
  $("#themeBtn").title = t("themeT");
  langPickers.forEach((p) => p.set(lang, t("langT"), t("langQ")));
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

// a "?" that shows a short explanation on hover or tap
document.addEventListener("click", (e) => { const q = e.target.closest(".qm"); if (q) { e.preventDefault(); q.focus(); } });
function qm(key) { return `<span class="qm" tabindex="0" role="note" aria-label="${esc(t(key))}" data-tip="${esc(t(key))}">?</span>`; }

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
$("#themeBtn").onclick = () => { const d = document.documentElement, cur = d.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); d.dataset.theme = cur === "dark" ? "light" : "dark"; localStorage.setItem("xo_theme", d.dataset.theme); };
const langPickers = [...document.querySelectorAll(".lang-slot")].map((slot) => XOLang.mount(slot, XO_LANGS, lang, (l) => { lang = l; localStorage.setItem("xo_lang", l); applyLang(); }, t("langT")));

// ---------- navigation ----------
// the open tab lives in the address (#tunnels), so a refresh stays on it
const views = ["overview", "inbounds", "users", "tunnels", "unblock", "settings"];
function goView(v) {
  state.view = views.includes(v) ? v : "overview";
  if (location.hash.slice(1) !== state.view) history.replaceState(null, "", state.view === "overview" ? location.pathname + location.search : "#" + state.view);
  render();
  let p;
  if (state.view === "settings") p = loadSettings();
  if (state.view === "tunnels") p = loadTunnels();
  if (state.view === "users") p = loadUsers();
  if (state.view === "unblock") p = loadSni();
  if (state.view === "overview" && daily.loaded) p = loadDaily();
  return Promise.resolve(p).catch(() => {});
}
document.querySelectorAll("#tabs button").forEach((b) => (b.onclick = () => { sessionStorage.removeItem("xoScroll"); goView(b.dataset.view); scrollTo(0, 0); }));
window.addEventListener("hashchange", () => { if (location.hash.slice(1) !== state.view) goView(location.hash.slice(1)); });
// and the scroll position, once the tab's content has loaded
window.addEventListener("beforeunload", () => sessionStorage.setItem("xoScroll", JSON.stringify({ v: state.view, y: scrollY })));
if ("scrollRestoration" in history) history.scrollRestoration = "manual";

async function boot() {
  try {
    state.status = await api("GET", "api/status");
  } catch { return; }
  const v = location.hash.slice(1);
  if (views.includes(v)) state.view = v; // show the tab from the address at once, not the overview first
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
  await refreshInbounds();
  await (views.includes(v) && v !== "overview" ? goView(v) : Promise.resolve(render()));
  try {
    const sc = JSON.parse(sessionStorage.getItem("xoScroll") || "null");
    sessionStorage.removeItem("xoScroll");
    if (sc && sc.v === state.view && sc.y > 0) requestAnimationFrame(() => scrollTo(0, sc.y));
  } catch {}
  pollJob();
  loadXray().catch(() => {});
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
// ---------- live + daily traffic (live stream only while Overview is on screen) ----------
const live = { es: null, pts: [] };
const fmtRate = (n) => fmtBytes(n) + "/s";
function liveWanted() { return state.view === "overview" && document.visibilityState === "visible" && !$("#app").classList.contains("hidden"); }
function liveSync() {
  if (liveWanted() && !live.es) {
    live.es = new EventSource("api/live");
    live.es.onmessage = (e) => {
      const d = JSON.parse(e.data); live.pts.push(d); if (live.pts.length > 90) live.pts.shift();
      $("#liveRx").textContent = fmtRate(d.rx); $("#liveTx").textContent = fmtRate(d.tx); drawLive();
    };
  } else if (!liveWanted() && live.es) { live.es.close(); live.es = null; }
}
document.addEventListener("visibilitychange", liveSync);
// y-axis scale in KB/MB/GB with round steps (1, 2, 2.5, 5 × 10^n), 4 lines
function niceScale(max) {
  const units = [["B", 1], ["KB", 1024], ["MB", 1024 ** 2], ["GB", 1024 ** 3], ["TB", 1024 ** 4]];
  max = Math.max(max, 1024);
  let u = units[0]; for (const x of units) if (max >= x[1]) u = x;
  const v = max / u[1] / 4, p = 10 ** Math.floor(Math.log10(v));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * p).find((m) => m >= v);
  const fmt = (i) => { if (!i) return "0"; const n = step * i; return (Number.isInteger(n) ? n : +n.toFixed(2)) + " " + u[0]; };
  return { top: step * 4 * u[1], ticks: [0, 1, 2, 3, 4].map((i) => ({ v: step * i * u[1], label: fmt(i) })) };
}
const C_DL = "#27ae60", C_UL = "#e5484d";
function drawLive() {
  const c = $("#liveChart"), r = devicePixelRatio, W = c.clientWidth, H = 130;
  c.width = W * r; c.height = H * r; const x = c.getContext("2d"); x.scale(r, r); x.clearRect(0, 0, W, H);
  const padL = 58, padR = 58, padT = 8, padB = 8, w = W - padL - padR, h = H - padT - padB;
  const sc = niceScale(Math.max(0, ...live.pts.map((p) => Math.max(p.rx, p.tx))));
  x.font = "11px sans-serif"; x.textBaseline = "middle";
  for (const tk of sc.ticks) {
    const Y = padT + h - (tk.v / sc.top) * h;
    x.strokeStyle = "rgba(128,128,128,.18)"; x.lineWidth = 1; x.beginPath(); x.moveTo(padL, Y); x.lineTo(padL + w, Y); x.stroke();
    x.fillStyle = "#888"; x.textAlign = "right"; x.fillText(tk.label + "/s", padL - 6, Y); x.textAlign = "left"; x.fillText(tk.label + "/s", padL + w + 6, Y);
  }
  const step = w / 89;
  const line = (k, col) => {
    x.beginPath(); live.pts.forEach((p, i) => { const X = padL + w - (live.pts.length - 1 - i) * step, Y = padT + h - (p[k] / sc.top) * h; i ? x.lineTo(X, Y) : x.moveTo(X, Y); });
    x.strokeStyle = col; x.lineWidth = 2; x.lineJoin = "round"; x.stroke();
  };
  line("rx", C_DL); line("tx", C_UL);
}
const daily = { month: "", mode: localStorage.getItem("xoDailyMode") || "month" };
async function loadDaily(shift) {
  if (shift && daily.month) { const [y, m] = daily.month.split("-").map(Number); const d = new Date(y, m - 1 + shift, 1); daily.month = d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0"); }
  const wk = daily.mode === "week";
  document.querySelectorAll("#dMode button").forEach((b) => b.classList.toggle("primary", b.dataset.m === daily.mode));
  $("#dNav").classList.toggle("hidden", wk);
  const r = await api("GET", "api/traffic/daily" + (wk ? "?days=7" : daily.month ? "?month=" + daily.month : ""));
  if (!wk) { daily.month = r.month; $("#dMonth").textContent = r.month; }
  $("#dSum").innerHTML = `<span style="color:${C_DL}">↓ ${t("dlLbl")} ${fmtBytes(r.rx)}</span> · <span style="color:${C_UL}">↑ ${t("ulLbl")} ${fmtBytes(r.tx)}</span> · ${t("traffic")} ${fmtBytes(r.rx + r.tx)}` + (r.since ? ` · ${t("dSince")} ${r.since}` : "");
  const W = 760, H = 230, padL = 62, padR = 8, padT = 10, padB = 24, w = W - padL - padR, h = H - padT - padB;
  const sc = niceScale(Math.max(0, ...r.days.map((d) => Math.max(d.rx, d.tx)))), n = r.days.length, slot = w / n;
  const bw = Math.min(slot * 0.36, 26);
  let g = sc.ticks.map((tk) => { const Y = padT + h - (tk.v / sc.top) * h;
    return `<line x1="${padL}" x2="${W - padR}" y1="${Y}" y2="${Y}" stroke="rgba(128,128,128,.2)"/><text x="${padL - 6}" y="${Y + 4}" text-anchor="end" class="ax">${tk.label}</text>`; }).join("");
  g += r.days.map((d, i) => {
    const cx = padL + slot * i + slot / 2, hr = (d.rx / sc.top) * h, ht = (d.tx / sc.top) * h, today = d.date === r.today;
    return `<g><title>${d.date}\n↓ ${t("dlLbl")} ${fmtBytes(d.rx)}\n↑ ${t("ulLbl")} ${fmtBytes(d.tx)}</title>
      <rect x="${cx - slot / 2}" y="${padT}" width="${slot}" height="${h}" fill="${today ? "rgba(128,128,128,.10)" : "transparent"}"/>
      <rect x="${cx - bw}" y="${padT + h - hr}" width="${bw}" height="${hr}" rx="1.5" fill="${C_DL}"/>
      <rect x="${cx}" y="${padT + h - ht}" width="${bw}" height="${ht}" rx="1.5" fill="${C_UL}"/>
      <text x="${cx}" y="${H - 7}" text-anchor="middle" class="ax${today ? " today" : ""}">${d.day}</text></g>`;
  }).join("");
  $("#dailyChart").innerHTML = `<svg viewBox="0 0 ${W} ${H}">${g}</svg>`;
}
$("#dPrev").onclick = guard(() => loadDaily(-1)); $("#dNext").onclick = guard(() => loadDaily(1));
document.querySelectorAll("#dMode button").forEach((b) => (b.onclick = guard(() => { daily.mode = b.dataset.m; localStorage.setItem("xoDailyMode", daily.mode); return loadDaily(); })));

function render() {
  liveSync(); if (state.view === "overview" && !daily.loaded && !$("#app").classList.contains("hidden")) { daily.loaded = true; loadDaily().catch(() => (daily.loaded = false)); }
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
  $("#selActs").classList.toggle("hidden", !n);
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
  if (cl.disabled) return `<span dir="auto" class="pill warn">${esc(m.reason === "traffic" ? t("overLimit") : m.reason === "expired" ? t("expired") : t("paused"))}</span>`;
  if (!m.expiry) return `<span dir="auto" class="pill gray">${t("never")}</span>`;
  const d = Math.ceil((m.expiry * 1000 - Date.now()) / 86400000);
  return d <= 0 ? `<span dir="auto" class="pill warn">${t("expired")}</span>` : `<span dir="auto" class="pill ${d <= 3 ? "warn" : ""}">${d} ${t("daysLeft")}</span>`;
}

function renderInbounds() {
  const list = $("#inboundList");
  if (!state.status.core.installed) { list.innerHTML = `<div class="card empty">${esc(t("hintMissing"))}</div>`; return; }
  const ibs = state.inbounds;
  if (!ibs.length) { list.innerHTML = `<div class="card empty">${t("noInbounds")}</div>`; return; }
  list.innerHTML = ibs.map((ib, idx) => {
    const pills = [ib.protocol, ib.network, ib.security].filter(Boolean).map((p) => `<span dir="auto" class="pill gray">${esc(p)}</span>`).join("");
    const clients = "";
    return `<div class="card">
      <div class="ib-head">
        <div class="ib-title"><span class="ibnum" dir="ltr">${idx + 1}</span>${ib.system ? "" : `<input type="checkbox" data-sel="${esc(ib.id)}" ${state.sel.has(ib.id) ? "checked" : ""}>`}<b>${esc(ib.tag || ib.id)}</b>${pills}<span dir="auto" class="pill">:${esc(ib.port)}</span>
          ${ib.system ? `<span dir="auto" class="pill gray">${t("system")}</span>` : !ib.managed ? `<span dir="auto" class="pill gray">${t("unmanaged")}</span>` : ""}</div>
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
      ${ib.singleLink ? `<div class="clients"><p class="muted">${t("singleUser")} ${qm("qSingle")}</p>${copyRow(ib.singleLink)}</div>` : ""}
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
  const certOpts = (certs || []).map((c, i) => `<option value="${i}">${esc(c.domain)} · ${esc(c.source)}</option>`).join("");
  openModal(`<h3>${ed ? t("editInbound") + ` · <span class="mono">${esc(ed.id)}</span>` : t("addInbound")}</h3>
  <form id="ibForm" class="form">
    <label>${t("protocol")}<select name="protocol"><option>vless</option><option>vmess</option><option>trojan</option><option value="shadowsocks">shadowsocks 2022</option><option value="hysteria">hysteria2</option><option>socks</option><option>http</option><option>wireguard</option></select></label>
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
    <div data-show="proto" class="rgrid">
      <label class="wide" data-show="venc">Decryption <small class="muted">(server)</small><input name="pv_dec" dir="ltr" class="mono" value="none"></label>
      <label class="wide" data-show="venc">Encryption <small class="muted">(client links)</small><input name="pv_enc" readonly dir="ltr" class="mono" value="none"></label>
      <label data-show="venc">Auth key<select name="pv_auth"><option value="x25519">X25519</option><option value="mlkem768">ML-KEM-768</option></select></label>
      <label data-show="venc">Mode<select name="pv_mode"><option>native</option><option>xorpub</option><option>random</option></select></label>
      <div class="actions wide" data-show="venc"><button type="button" class="btn small primary" id="pvGen">Generate</button><button type="button" class="btn small danger" id="pvClear">${t("rClear")}</button></div>
      <label class="wide" data-show="vision">Vision testseed<span class="inrow">${[0, 1, 2, 3].map((i) => `<input name="pv_ts${i}" type="number" min="0" max="65535" value="${[900, 500, 900, 256][i]}">`).join("")}</span><small class="muted">xtls-rprx-vision</small></label>
      <div class="wide" data-show="fb"><div class="row-between"><b>Fallbacks</b><button type="button" class="btn small" id="fbAdd">+ Fallback</button></div><div id="fbList" class="stack"></div></div>
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
  const fbRow = (x = {}) => {
    const row = document.createElement("div"); row.className = "fbrow";
    row.innerHTML = `<input data-k="name" placeholder="SNI (name)" dir="ltr"><input data-k="alpn" placeholder="alpn" dir="ltr"><input data-k="path" placeholder="/path" dir="ltr"><input data-k="dest" placeholder="80 / 127.0.0.1:8080" dir="ltr"><input data-k="xver" type="number" min="0" max="2" placeholder="xver"><button type="button" class="btn small danger">✕</button>`;
    row.querySelectorAll("input").forEach((i) => { i.value = x[i.dataset.k] ?? ""; });
    row.querySelector("button").onclick = () => row.remove();
    $("#fbList").appendChild(row);
  };
  $("#fbAdd").onclick = () => fbRow();
  const encOf = async (dec) => { f.pv_enc.value = "none"; if (dec && dec !== "none") try { f.pv_enc.value = (await api("GET", "api/vless/enc?dec=" + encodeURIComponent(dec))).encryption; } catch (e) { $("#ibErr").textContent = e.message; } };
  $("#pvGen").onclick = async () => { try { const k = await api("GET", `api/vless/enc?auth=${f.pv_auth.value}&mode=${f.pv_mode.value}`); f.pv_dec.value = k.decryption; f.pv_enc.value = k.encryption; sync(); } catch (e) { $("#ibErr").textContent = e.message; } };
  $("#pvClear").onclick = () => { f.pv_dec.value = "none"; f.pv_enc.value = "none"; sync(); };
  f.pv_dec.onchange = () => encOf(f.pv_dec.value.trim());
  if (ed) {
    const v = ed.form, r = v.reality, pv = v.proto;
    if (pv) {
      f.pv_dec.value = pv.decryption || "none"; f.pv_enc.value = pv.encryption || "none";
      (pv.testseed || []).forEach((n, i) => { if (f["pv_ts" + i]) f["pv_ts" + i].value = n; });
      (pv.fallbacks || []).forEach(fbRow);
      const parts = (pv.decryption || "").split(".");
      if (parts.length > 3) { f.pv_mode.value = parts[1]; f.pv_auth.value = parts[parts.length - 1].length > 60 ? "mlkem768" : "x25519"; }
    }
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
      out.innerHTML = !r ? "—" : r.feasible ? `<span dir="auto" class="pill ok">${t("rsOk")}</span> TLS ${esc(r.tls)} · ${esc(r.alpn)} · ${esc(r.keyEx)} · ${esc(r.cert)} · ${r.latency} ms`
        : `<span dir="auto" class="pill bad">${esc(r.reason || t("rsNo"))}</span>`;
      if (r && r.feasible && !f.r_sni.value.trim()) f.r_sni.value = r.sni;
    } catch (e) { out.textContent = e.message; }
  };
  const sync = () => {
    const net = f.network.value, sec = f.security.value, proto = f.protocol.value;
    const wg = proto === "wireguard", fixed = wg || proto === "socks" || proto === "http";
    f.network.disabled = fixed; f.security.disabled = fixed;
    const show = { path: !fixed && ["ws", "xhttp", "httpupgrade"].includes(net), grpc: !fixed && net === "grpc", sni: !fixed && sec !== "none", reality: !fixed && sec === "reality", tls: !fixed && sec === "tls", venc: proto === "vless", proto: ["vless", "trojan"].includes(proto),
      vision: proto === "vless" && net === "tcp" && (sec !== "none" || (f.pv_dec.value.trim() || "none") !== "none"),
      fb: ["vless", "trojan"].includes(proto) && net === "tcp" && (proto === "trojan" || (f.pv_dec.value.trim() || "none") === "none") };
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
    if (["vless", "trojan"].includes(f.protocol.value)) {
      d.proto = { decryption: (d.pv_dec || "none").trim() || "none", testseed: [0, 1, 2, 3].map((i) => +d["pv_ts" + i] || 0),
        fallbacks: !$("#fbList").parentElement.classList.contains("hidden") ? [...$("#fbList").children].map((row) => { const o = {}; row.querySelectorAll("input").forEach((i) => { o[i.dataset.k] = i.value.trim(); }); o.xver = +o.xver || 0; return o; }).filter((o) => o.dest) : [] };
      if (f.protocol.value === "trojan") { delete d.proto.decryption; delete d.proto.testseed; }
    }
    Object.keys(d).filter((k) => k.startsWith("r_") || k.startsWith("pv_")).forEach((k) => delete d[k]);
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

// WireGuard: turn a wireguard:// link into a .conf for the official app
function wgConf(link) {
  const u = new URL(link.replace(/^wireguard:/, "http:"));
  const q = u.searchParams, name = decodeURIComponent(u.hash.slice(1)) || "wg";
  const host = u.hostname, ep = (host.includes(":") ? "[" + host + "]" : host) + ":" + (u.port || "51820");
  const conf = ["[Interface]", "PrivateKey = " + decodeURIComponent(u.username), "Address = " + (q.get("address") || "10.0.0.2/32"),
    "DNS = 1.1.1.1, 8.8.8.8", "MTU = " + (q.get("mtu") || "1420"), "", "[Peer]", "PublicKey = " + q.get("publickey"),
    "AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = " + ep, "PersistentKeepalive = 25", ""].join("\n");
  const file = (name.replace(/[^A-Za-z0-9_=+.-]/g, "").slice(0, 15) || "wg") + ".conf";
  return { name, conf, file };
}
async function wgFill(box, token) {
  if (!box || !token) return;
  const links = await api("GET", "api/wg?token=" + encodeURIComponent(token)).catch(() => []);
  if (!links || !links.length) return;
  box.innerHTML = `<label>${t("wgTitle")}</label><p class="muted small">${t("wgHint")}</p>` + links.map((l) => {
    const w = wgConf(l);
    return `<div class="wgrow"><span class="mono">${esc(w.name)}</span><span class="actions"><button type="button" class="btn small primary" data-wgdl="${esc(l)}">${t("wgFile")}</button><button type="button" class="btn small" data-wgqr="${esc(l)}">QR</button></span><img class="qr hidden" alt="QR"></div>`;
  }).join("");
}
document.addEventListener("click", (e) => {
  const d = e.target.closest("[data-wgdl]");
  if (d) {
    const w = wgConf(d.dataset.wgdl);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([w.conf], { type: "text/plain" })); a.download = w.file;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    return;
  }
  const qb = e.target.closest("[data-wgqr]");
  if (qb) {
    const img = qb.closest(".wgrow").querySelector("img");
    if (!img.getAttribute("src")) img.src = "api/qr?text=" + encodeURIComponent(wgConf(qb.dataset.wgqr).conf);
    img.classList.toggle("hidden");
  }
});

function openClient(ib, cl) {
  const m = cl.meta || {};
  const sub = m.subToken ? subURL(m) : "";
  openModal(`<div class="row-between"><h3 class="mono">${esc(cl.email)}</h3>${clientStatus(cl)}</div>
    <p class="muted">${t("up")} ${fmtBytes(m.up)} · ${t("down")} ${fmtBytes(m.down)} · ${m.limitBytes ? fmtBytes(m.limitBytes) : t("unlimited")}</p>
    <label>${t("link")}</label>${copyRow(cl.link)}
    ${sub ? `<label>${t("sub")}</label>${copyRow(sub)}` : ""}
    ${cl.relayLinks && cl.relayLinks.length ? `<label>${t("relayLinks")}</label><div class="links-list">${cl.relayLinks.map(copyRow).join("")}</div>` : ""}
    <img class="qr" alt="QR" src="api/qr?text=${encodeURIComponent(sub || cl.link)}">
    <div id="wgBox"></div>
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
  wgFill($("#wgBox"), m.subToken);
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
          <span dir="auto" class="pill gray">${fmtBytes(used)} / ${u.limitBytes ? fmtBytes(u.limitBytes) : t("unlimited")}</span>
          <span dir="auto" class="pill gray">${u.inbounds.length ? u.inbounds.length + " " + t("ibCount") : t("noInboundsYet")}</span></div>
        <div class="actions">
          <button class="btn small primary" data-u="edit" data-i="${i}">${t("editUser")}</button>
          <button class="btn small" data-u="qr" data-i="${i}">QR</button>
          <button class="btn small danger" data-u="del" data-i="${i}">${t("del")}</button>
        </div>
      </div>
      ${u.limitBytes ? `<div class="bar"><i style="width:${pct}%"></i></div>` : ""}
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
    openModal(`<h3 class="mono">${esc(u.email)}</h3>${copyRow(subURL(u))}<img class="qr" alt="QR" src="api/qr?text=${encodeURIComponent(subURL(u))}"><div id="wgBox"></div><div class="actions"><button class="btn" data-close>${t("cancel")}</button></div>`);
    wgFill($("#wgBox"), u.subToken);
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
    <div class="presets" id="qList">${groups.map(([g, title]) => `<div class="pgroup"><h4><label class="gall"><input type="checkbox" data-gall> ${esc(title)}</label></h4><div class="pgrid">${r.presets.filter((p) => p.group === g).map(item).join("")}</div></div>`).join("")}</div>
    <form id="qForm" class="form" style="grid-template-columns:2fr 1fr 1fr">
      <label>${t("clientName")}<input name="client" value="user1" pattern="[A-Za-z0-9._@+\\-]{1,64}"></label>
      <label>${t("expiryDays")}<input name="expiryDays" type="number" min="0" value="30"></label>
      <label>${t("limitGB")}<input name="limitGB" type="number" min="0" step="0.5" value="0"></label>
      <label style="grid-column:1/-1">${t("dest")} (REALITY)<span class="inrow"><input name="dest" placeholder="www.microsoft.com:443"><input name="sni" placeholder="SNI" style="max-width:40%"><button type="button" class="btn small" id="qScan">🔍 ${t("rsFind")}</button></span></label>
    </form>
    <p id="qErr" class="err"></p>
    <div class="actions"><button class="btn primary" id="qCreate"></button><button class="btn" data-close>${t("cancel")}</button></div>`, true);
  const boxes = (root) => [...(root || $("#qList")).querySelectorAll(".pgrid input:not(:disabled)")];
  const syncAll = () => $("#qList").querySelectorAll(".pgroup").forEach((g) => { const bs = boxes(g), c = bs.filter((b) => b.checked).length, a = g.querySelector("[data-gall]"); a.checked = bs.length > 0 && c === bs.length; a.indeterminate = c > 0 && c < bs.length; a.disabled = !bs.length; });
  const count = () => { syncAll(); $("#qCreate").textContent = t("createN") + " (" + boxes().filter((b) => b.checked).length + ")"; };
  $("#qList").onchange = (e) => { if (e.target.matches("[data-gall]")) boxes(e.target.closest(".pgroup")).forEach((b) => (b.checked = e.target.checked)); count(); }; count();
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
async function loadXray(now) {
  const x = await api("GET", "api/xray/latest" + (now ? "?now=1" : ""));
  const newer = x.latest && x.current && versionLess(x.current, x.latest);
  const mids = (tunnelData?.servers || []).filter((s) => s.xrayVer && x.latest && versionLess(s.xrayVer, x.latest));
  $("#xuBox").innerHTML = `<p>${t("xuCur")}: <b class="mono">${esc(x.current || "?")}</b> · ${t("xuNew")}: <b class="mono">${esc(x.latest || "?")}</b> ${newer ? "" : x.latest ? `<span class="muted">(${t("xuOk")})</span>` : ""}</p>
    ${x.err ? `<p class="err">${esc(x.err)}</p>` : ""}
    ${newer ? `<button class="btn primary small" id="xuUpd">${esc(t("xuUpd").replace("{v}", x.latest))}</button>` : ""}
    ${mids.length ? `<p class="muted small">${t("xuMid")}: ${mids.map((s) => esc(s.name) + " (" + esc(s.xrayVer) + ")").join(sep())}<br>${t("xuMidHint")}</p>` : ""}`;
  document.querySelector('nav [data-view="settings"]')?.classList.toggle("badge", !!newer);
  const u = $("#xuUpd");
  if (u) u.onclick = guard(async () => {
    u.disabled = true;
    try { await api("POST", "api/xray/update", {}); }
    catch (e) {
      if (!String(e.message).startsWith("TEST: ")) { u.disabled = false; throw e; }
      if (!confirm(t("xuWarn").replace("{e}", e.message.slice(6)))) { u.disabled = false; return; }
      await api("POST", "api/xray/update", { force: true });
    }
    toast(t("done")); refreshStatus(); loadXray();
  });
}
$("#xuCheck").onclick = guard(() => loadXray(true));
function bkTime(n) {
  const m = /config-(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)(\d\d)/.exec(n);
  if (!m) return esc(n);
  const d = new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  return esc(d.toLocaleString(locale(), { dateStyle: "medium", timeStyle: "medium" }));
}
async function loadSettings() {
  const s = state.status.settings, f = $("#settingsForm");
  f.publicHost.value = s.publicHost || ""; f.subBase.value = s.subBase || "";
  loadXray().catch(() => {});
  const list = await api("GET", "api/backups");
  $("#backupList").innerHTML = list.length ? list.map((n) => `<div class="item"><span title="${esc(n)}">${bkTime(n)}</span><button class="btn small" data-restore="${esc(n)}">${t("restore")}</button></div>`).join("") : `<p class="muted">—</p>`;
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
const tnTestRes = {}; let tnPoll;
// port fields accept Persian/Arabic digits too; "" keeps the current port
function portNum(v) {
  v = String(v || "").trim().replace(/[۰-۹]/g, (c) => "۰۱۲۳۴۵۶۷۸۹".indexOf(c)).replace(/[٠-٩]/g, (c) => "٠١٢٣٤٥٦٧٨٩".indexOf(c));
  if (!v) return 0;
  const n = /^\d+$/.test(v) ? +v : NaN;
  if (!(n >= 1 && n <= 65535)) throw new Error(t("tpBadNum"));
  return n;
}
let portEdit = ""; // "<server index>:<field>" being edited on a card
$("#tunnelPorts").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  const f = e.target;
  await api("POST", "api/tunnels/settings", { port: portNum(f.port.value), xport: portNum(f.xport.value), rport: portNum(f.rport.value), rtarget: f.rtarget.value.trim() });
  toast(t("done")); document.activeElement?.blur(); loadTunnels();
}));
// REALITY site of the tunnel: pick one with the scanner, or check it here and on the middle servers
$("#tunnelPorts").addEventListener("click", guard(async (e) => {
  const b = e.target.closest("[data-rc]"); if (!b) return;
  const f = $("#tunnelPorts");
  if (b.dataset.rc === "scan") { openRealityScan((x) => { f.rtarget.value = x.target; rcheck(); }); return; }
  await rcheck();
}));
let rcSeq = 0;
async function rcheck() {
  const f = $("#tunnelPorts"), out = $("#rcOut"), seq = ++rcSeq;
  const pill = (r) => !r ? `<span class="muted">${t("rcNoAns")}</span>` : r.feasible ? `<span dir="auto" class="pill ok">${t("rsOk")}</span> ${r.latency} ms`
    : `<span dir="auto" class="pill bad">${esc(r.reason || t("rsNo"))}</span>`;
  out.classList.remove("hidden"); out.innerHTML = `<span class="muted">${t("rcWait")}</span>`;
  let r;
  try { r = await api("POST", "api/tunnels/rcheck", { target: f.rtarget.value.trim() }); } catch (e) { out.innerHTML = `<span class="err">${esc(e.message)}</span>`; return; }
  const draw = (servers) => {
    if (seq !== rcSeq) return;
    out.innerHTML = `<b class="mono" dir="ltr">${esc(r.target)}</b><span>${t("rcHere")}: ${pill(r.here)}</span>` + (servers || []).map((s) =>
      `<span>${esc(s.name)}: ${s.off ? `<span class="muted">${t("rcOff")}</span>` : s.old ? `<span class="muted">${t("rcOld")}</span>` : s.busy ? `<span class="muted">${t("rcWait")}</span>` : pill(s.res)}</span>`).join("");
  };
  for (let i = 0; i < 25 && seq === rcSeq; i++) {
    let v; try { v = await api("GET", "api/tunnels/rcheck?id=" + r.id); } catch { break; }
    draw(v.servers);
    if (!v.servers.some((s) => s.busy)) break;
    await new Promise((ok) => setTimeout(ok, 1500));
  }
}
$("#dtPorts").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  const f = e.target;
  await api("POST", "api/tunnels/dtsettings", { wghost: f.wghost.value.trim() });
  toast(t("done")); document.activeElement?.blur(); loadTunnels();
}));
function renderTunnels() {
  const d = tunnelData; if (!d) return;
  $("#tunnelInfo").textContent = d.ready ? t("tnInfo").replace("{x}", (d.xport ? ", XHTTP " + d.xport : "") + (d.rport ? ", REALITY " + d.rport : "")).replace("{port}", d.port || "—").replace("{domain}", d.domain) : t("tnNeedSSL");
  $("#addTunnelBtn").disabled = !d.ready;
  const tp = $("#tunnelPorts");
  if (d.ready && document.activeElement?.form !== tp) tp.innerHTML = `
    <label>${t("tpWs")}<input name="port" inputmode="numeric" dir="ltr" value="${d.port || ""}" placeholder="${t("tpAuto")}"></label>
    <label>${t("tpXh")}<input name="xport" inputmode="numeric" dir="ltr" value="${d.xport || ""}" placeholder="${t("tpAuto")}"></label>
    <label>${t("tpRt")}<input name="rport" inputmode="numeric" dir="ltr" value="${d.rport || ""}" placeholder="${t("tpAuto")}"></label>
    <label><span>${t("tpRtT")} ${qm("qRtT")}</span><input name="rtarget" dir="ltr" value="${esc(d.rtarget || "")}" placeholder="www.microsoft.com:443"></label>
    <button class="btn" type="button" data-rc="scan">${t("rsScan")}</button><button class="btn" type="button" data-rc="check">${t("rcCheck")}</button>
    <button class="btn" type="submit">${t("tpSave")}</button><small class="muted">${t("tpHint")}</small>`;
  else if (!d.ready) tp.innerHTML = "";
  const dp = $("#dtPorts");
  if (d.ready && d.servers.length && document.activeElement?.form !== dp) dp.innerHTML = `
    <b class="dthead">${t("udpTitle")}</b>
    <label>${t("udpHost")}<input name="wghost" dir="ltr" value="${esc(d.wghost || "")}" placeholder="${t("tpAuto")}"></label>
    <button class="btn" type="submit">${t("dtSave")}</button><small class="muted">${t("udpHint")}</small>`;
  else if (!d.ready || !d.servers.length) dp.innerHTML = "";
  if (!d.servers.length) { $("#tunnelList").innerHTML = `<div class="card empty">${t("tnNoSrv")}</div>`; return; }
  const now = Date.now() / 1000;
  clearTimeout(tnPoll); if (d.servers.some((s) => s.prevMethod || (s.domain && !s.certOk && !s.certErr)) || spActive()) tnPoll = setTimeout(() => { if (state.view === "tunnels" && !tnTyping()) loadTunnels(); }, spActive() ? 1500 : 3000);
  $("#tunnelList").innerHTML = d.servers.map((s, i) => {
    const seen = s.lastSeen ? ago(Math.max(0, Math.round(now - s.lastSeen))) + " " + t("tnAgo") : t("tnNever");
    return `<div class="card">
      <div class="ib-head">
        <div class="ib-title"><span class="dot${s.online ? "" : " bad"}"></span><b>${esc(s.name)}</b>
          <span dir="auto" class="pill gray">${esc(t("m" + cap(s.method)) || s.method)}</span>
          <span dir="auto" class="pill ${s.online ? "" : "warn"}">${s.online ? t("tnOnline") : t("tnOffline")} · ${esc(seen)}</span>
          ${s.publicIP || s.host ? `<span dir="auto" class="pill gray mono">${esc(s.publicIP || s.host)}</span>` : ""}
          ${s.agentVer ? `<span dir="auto" class="pill gray">v${esc(s.agentVer)}</span>` : ""}
          <span dir="auto" class="pill gray">${s.inbounds.length} ${t("ibCount")}</span></div>
        <div class="actions">
          ${s.host ? `<button class="btn small primary" data-tn="deploy" data-i="${i}">${t("tnDeploy")}</button>` : ""}
          <button class="btn small" data-tn="test" data-i="${i}">${t("tnTest")}</button>
          <button class="btn small" data-tn="join" data-i="${i}">${t("tnNewCmd")}</button>
          <button class="btn small danger" data-tn="del" data-i="${i}">${t("del")}</button>
        </div>
      </div>
      ${methodCards(s, i)}
      ${revBlock(s, i)}
      ${s.methodErr ? `<p class="err">${esc(t("mBack").replace("{x}", s.methodErr))}</p>` : ""}
      ${tnTestRes[s.id] ? `<p class="${tnTestRes[s.id].ok ? "okmsg" : "err"}">${esc(tnTestRes[s.id].text)}</p>` : ""}
      ${s.lastFail ? `<p class="muted small">${t("tnLastFail")}: ${esc(s.failAt ? ago(Math.max(0, Math.round(now - s.failAt))) + " " + t("tnAgo") : "")} · ${t("tnFails").replace("{n}", s.fails || 0)} · <span class="mono">${esc(s.lastFail)}</span></p>` : ""}
      ${s.xrayErr ? `<p class="err">${t("tnXrayErr")}: ${esc(s.xrayErr)}</p>` : ""}
      ${s.command ? `<div class="clients"><p class="muted">${t("tnQuick")}</p>${copyRow(s.command)}</div>` : ""}
      <details class="muted small-details"><summary>${t("tnRemove").replace(/[:：]$/, "")}</summary>${copyRow(s.remove)}</details>
    </div>`;
  }).join("");
}
// ready domain lists for the game unblocker: a starting point, test them
const sniPresets = {
  Steam: ["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "valvesoftware.com"],
  Epic: ["epicgames.com", "epicgames.dev", "unrealengine.com", "fortnite.com", "hcaptcha.com", "challenges.cloudflare.com", "statsigapi.net", "featureassets.org"],
  Riot: ["riotgames.com", "riotcdn.net", "leagueoflegends.com", "playvalorant.com"],
  "Call of Duty": ["activision.com", "callofduty.com", "demonware.net"],
  PlayStation: ["playstation.com", "playstation.net", "sonyentertainmentnetwork.com"],
  Xbox: ["xbox.com", "xboxlive.com"],
  NVIDIA: ["nvidia.com", "geforcenow.com"],
  "Speed test": ["speed.cloudflare.com"],
};
// ---------- unblocker tab ----------
let sniData = null, sniPoll;
async function loadSni() {
  clearTimeout(sniPoll);
  try { sniData = await api("GET", "api/sni"); } catch (e) { return; }
  renderSni();
  sniPoll = setTimeout(() => { if (state.view === "unblock" && document.visibilityState === "visible") loadSni(); }, 5000);
}
function sniBase(n) {
  const p = n.split(".");
  const two = /^(co|com|net|org|gov|ac|edu)$/.test(p[p.length - 2] || "") && p.length > 2;
  return p.slice(two ? -3 : -2).join(".");
}
function sniTime(ts) { return new Date(ts * 1000).toLocaleString(locale(), { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
function renderSni() {
  const d = sniData; if (!d) return;
  const f = $("#sniForm");
  if (document.activeElement?.form !== f) f.innerHTML = `
    <label class="wide">${t("sniDoms")}<textarea name="domains" spellcheck="false">${esc((d.domains || []).join("\n"))}</textarea></label>
    <div class="snipre"><span class="muted small">${t("sniPre")}</span>${Object.keys(sniPresets).map((k) => `<button class="btn small" type="button" data-sp="${esc(k)}">${esc(k)}</button>`).join("")}</div>
    <label>${t("sniHours")}<input name="hours" inputmode="numeric" dir="ltr" value="${d.hours || 24}"></label>
    <button class="btn primary" type="submit">${t("sniSave")}</button><small class="muted">${t("sniHint")}</small>`;
  const noDom = !(d.domains || []).length;
  const row = (key, name, ip, on, st) => `<div class="snirow"><label class="chk"><input type="checkbox" data-sent="${esc(key)}"${on ? " checked" : ""}${noDom && !on ? " disabled" : ""}> <b>${esc(name)}</b></label><span class="mono" dir="ltr">${esc(ip || "—")}</span>${st}</div>`;
  let mst = "";
  if (d.main) mst = d.mainErr ? `<span class="err">${esc(d.mainErr)}</span>` : `<span class="okmsg">${esc(t("sniActive").replace("{n}", d.mainN || 0).replace("{ip}", d.mainIP || "—"))}</span>`;
  let ent = row("main", t("sniMainSrv"), d.mainIP, d.main, mst);
  for (const s of d.servers || []) {
    let st = "";
    if (s.on) {
      if (s.agentVer && versionLess(s.agentVer, d.sniVer)) st = `<span class="err">${esc(t("sniOld").replace("{v}", d.sniVer))}</span>`;
      else if (!s.ip) st = `<span class="muted">${t("sniNoIP")}</span>`;
      else if (s.err) st = `<span class="err">${esc(s.err)}</span>`;
      else if (!s.online) st = `<span class="muted">${t("sniOffline")}</span>`;
      else st = `<span class="okmsg">${esc(t("sniActive").replace("{n}", s.n || 0).replace("{ip}", s.ip))}</span>`;
      if (s.agentVer && versionLess(s.agentVer, d.sniLogVer) && !versionLess(s.agentVer, d.sniVer)) st += ` <small class="muted">${esc(t("sniSeenOld").replace("{v}", d.sniLogVer))}</small>`;
    }
    ent += row(s.id, s.name, s.ip, s.on, st);
  }
  $("#sniEntries").innerHTML = (noDom ? `<p class="muted small">${t("sniNeedDom")}</p>` : "") + ent;
  const act = d.active || [];
  $("#sniActive").innerHTML = act.length ? `<div class="rsWrap"><table class="rsTable snitbl"><thead><tr><th>IP</th><th>${t("sniUser")}</th><th>${t("sniEntry")}</th><th>${t("sniUntil")}</th><th></th></tr></thead><tbody>${act.map((x) =>
    `<tr><td class="mono">${esc(x.ip)}</td><td>${esc(x.user || "—")}</td><td>${esc(x.entry === "main" ? t("sniMainSrv") : x.entry)}</td><td>${esc(sniTime(x.until))}</td><td><button class="btn small danger" data-srev="${esc(x.ip)}">${t("sniRemove")}</button></td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">${t("sniNoAct")}</p>`;
  const only = $("#sniOnlyNew").checked, now = d.now || Date.now() / 1000;
  const seen = (d.seen || []).filter((x) => !only || !x.listed);
  $("#sniSeen").innerHTML = seen.length ? `<div class="rsWrap"><table class="rsTable snitbl"><thead><tr><th>${t("sniName")}</th><th>${t("sniCount")}</th><th>${t("sniLast")}</th><th>IP</th><th>${t("sniUser")}</th><th></th></tr></thead><tbody>${seen.map((x) => {
    const b = sniBase(x.name);
    return `<tr><td class="mono">${esc(x.name)}</td><td>${x.n}</td><td>${esc(ago(Math.max(0, Math.round(now - x.last))))}</td><td class="mono">${esc(x.ip)}</td><td>${esc(x.user || "—")}</td><td>${x.listed ? `<span class="okmsg">${t("sniInList")}</span>` : `<span class="sadd"><button class="btn small" data-sadd="${esc(b)}" title="${esc(t("sniAddAll"))}">+ ${esc(b)}</button>${b !== x.name ? `<button class="btn small ghost" data-sadd="${esc(x.name)}" title="${esc(t("sniAddOne"))}">${t("sniOnlyThis")}</button>` : ""}</span>`}</td></tr>`;
  }).join("")}</tbody></table></div>` : `<p class="muted">${t("sniNoSeen")}</p>`;
}
$("#sniOnlyNew").addEventListener("change", renderSni);
$("#sniForm").addEventListener("click", (e) => {
  const b = e.target.closest("[data-sp]"); if (!b) return;
  const ta = $("#sniForm textarea"), have = new Set(ta.value.split(/\s+/).filter(Boolean));
  sniPresets[b.dataset.sp].forEach((x) => have.add(x));
  ta.value = [...have].join("\n"); ta.focus();
});
$("#sniForm").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  const f = e.target;
  await api("POST", "api/sni", { domains: f.domains.value, main: !!sniData?.main, hours: +f.hours.value || 24 });
  toast(t("done")); document.activeElement?.blur(); loadSni();
}));
$("#sniEntries").addEventListener("change", guard(async (e) => {
  const c = e.target.closest("input[data-sent]"); if (!c) return;
  try {
    if (c.dataset.sent === "main") await api("POST", "api/sni", { domains: (sniData.domains || []).join("\n"), main: c.checked, hours: sniData.hours || 24 });
    else await api("POST", "api/tunnels/" + c.dataset.sent + "/sni", { on: c.checked });
    toast(t("done"));
  } finally { loadSni(); }
}));
$("#view-unblock").addEventListener("click", guard(async (e) => {
  const r = e.target.closest("[data-srev]");
  if (r) { r.disabled = true; try { await api("POST", "api/sni/revoke", { ip: r.dataset.srev }); toast(t("sniRemoved")); } finally { loadSni(); } return; }
  const a = e.target.closest("[data-sadd]");
  if (a) { a.disabled = true; try { await api("POST", "api/sni/domains", { add: [a.dataset.sadd] }); toast(t("sniAdded").replace("{d}", a.dataset.sadd)); } finally { loadSni(); } }
}));
function revBlock(s, i) {
  const d = tunnelData;
  if (!s.agentVer || versionLess(s.agentVer, d.revVer)) return s.lastSeen ? `<p class="muted small">${esc(t("rvOld").replace("{v}", d.revVer))}</p>` : "";
  const mn = (m) => ({ wss: "WS", xhttp: "XHTTP", reality: "REALITY" })[m] || m || "REALITY";
  let rv = "";
  if (s.revPort) {
    const ports = [s.revPort, s.domain && s.certOk ? s.revPortW : 0, s.domain && s.certOk ? s.revPortX : 0].filter(Boolean).join(sep());
    if (s.search === "search") rv = t("rvSearch").replace("{m}", s.searchN.split(" ").map((x, k) => k ? x : mn(x)).join(" "));
    else if (s.search === "cool") rv = t("rvCool").replace("{t}", new Date(s.searchAt * 1000).toLocaleTimeString());
    else if (s.mode === "rev") rv = t("rvRevVia").replace("{m}", mn(s.bridgeVia));
    else if (s.via) rv = t("rvVia").replace("{m}", mn(s.via));
    else rv = t("rvFwd") + " · " + t("rvReady").replace("{p}", ports);
  }
  const labels = (d.domain || "").split("."), base = labels.length > 2 ? labels.slice(1).join(".") : d.domain || "example.com";
  let st = "";
  if (s.domain) {
    if (s.certOk) st = `<span class="okmsg">${esc(t("dmOk").replace("{d}", new Date(s.certExp * 1000).toLocaleDateString()))}</span>`;
    else if (s.certErr) st = `<span class="err">${esc(t("dmErr"))}: ${esc(s.certErr)}</span>`;
    else st = `<span class="muted">${s.certBusy ? t("dmBusy") : t("dmWait")}</span>`;
  }
  const rp = s.revPort ? `<details class="muted small-details"><summary>${t("rpTitle")} ${qm("qRevPorts")} · ${esc(s.revSet ? t("rpManual") : t("rpAuto"))}</summary>
      <div class="dmrow">REALITY <input id="rpR-${i}" class="w6" dir="ltr" value="${s.revPort || ""}"> WS <input id="rpW-${i}" class="w6" dir="ltr" value="${s.revPortW || ""}"> XHTTP <input id="rpX-${i}" class="w6" dir="ltr" value="${s.revPortX || ""}">
      <button class="btn small" data-tn="rpsave" data-i="${i}">${t("dmSave")}</button> <button class="btn small ghost" data-tn="rpauto" data-i="${i}">${t("rpAutoBtn")}</button></div></details>` : "";
  return `${rv ? `<p class="muted small">↔ ${esc(rv)}</p>` : ""}${rp}${s.bridgeErr ? `<p class="err">${esc(s.bridgeErr)}</p>` : ""}
    <div class="dmrow"><label><span>${t("dmLabel")} ${qm("qDomain")}</span> <input id="tnDom-${i}" dir="ltr" value="${esc(s.domain || "")}" placeholder="mid.${esc(base)}"></label>
      <button class="btn small" data-tn="domain" data-i="${i}">${t("dmSave")}</button> ${st}</div>
    ${s.domain && s.certOk ? "" : `<p class="muted small">${esc(t("dmHint").replace("{ip}", s.publicIP || s.host || "IP"))}</p>`}`;
}
$("#tunnelList").addEventListener("keydown", guard(async (e) => {
  const inp = e.target.closest(".pedit input");
  if (inp && e.key === "Enter") { e.preventDefault(); const [, i, k] = inp.id.split("-"); await savePort(i, k); return; }
  if (inp && e.key === "Escape") { portEdit = ""; renderTunnels(); return; }
  if ((e.key === "Enter" || e.key === " ") && e.target.matches("[role=button]")) { e.preventDefault(); e.target.click(); }
}));
const tnTyping = () => !!document.activeElement?.closest?.("#tunnelList input:not([type=checkbox]), #tunnelList select");
function versionLess(a, b) {
  const pa = String(a).split(".").map(Number), pb = String(b).split(".").map(Number);
  for (let i = 0; i < 3; i++) { const x = pa[i] || 0, y = pb[i] || 0; if (x !== y) return x < y; }
  return false;
}
const cap = (m) => (m === "wss" ? "Wss" : m.charAt(0).toUpperCase() + m.slice(1));
const methodPort = { wss: "port", xhttp: "xport", reality: "rport", wg: "wgport", kcp: "kport", frp: "frpport", backhaul: "bhport", ssh: "sshport" };
const carrierKeys = { frp: ["frpproto", "frpgre"], backhaul: ["bhproto", "bhgre"] };
// why a method cannot run between this server and middle server s ("" = it can)
function methodBlock(s, m) {
  const d = tunnelData;
  if (m === "wg" && !d.wgOn) return t("mNoUdp");
  if (m === "kcp" && !d.kOn) return d.wghost ? t("mNoKcp").replace("{v}", d.kcpXray) : t("mNoUdp");
  if (["gre", "frp", "backhaul", "ssh"].includes(m) && !d.wgOn) return t("mNoUdp");
  if (m === "gre" && (!d.greIP || (s.lastSeen && !s.publicIP))) return t("mNoGre");
  if (s.capable && s.capable[m] === false && s.lastSeen) return t("mOldMid");
  if (m === "ssh" && s.lastSeen && !s.sshHost) return t("mNoSshKey");
  return "";
}
// "Port: N ✎" on a card, or its inline editor
function portLine(i, k) {
  const v = tunnelData[k];
  if (portEdit === i + ":" + k) return `<span class="pedit"><input id="pe-${i}-${k}" inputmode="numeric" dir="ltr" value="${esc(v || "")}" aria-label="${t("pePort")}">
    <button type="button" class="btn small primary" data-pe-save="${k}" data-i="${i}" title="${t("peSave")}">✓</button><button type="button" class="btn small" data-pe-cancel="1" title="${t("peCancel")}">✕</button></span>`;
  return `<span class="pport" role="button" tabindex="0" data-pe="${k}" data-i="${i}" title="${t("peEdit")}">${t("pePort")}: <b class="mono">${esc(v || t("tpAuto"))}</b> ✎</span>`;
}
// protocol and "over GRE" of FRP / Backhaul (the same for every middle server)
function carrierOpts(m, i) {
  const [pk, gk] = carrierKeys[m.id], d = tunnelData;
  return `<div class="mopt"><span>${t("cProto")}</span><select data-copt="${pk}" data-i="${i}" dir="ltr">${m.protos.map((p) => `<option ${d[pk] === p ? "selected" : ""}>${p}</option>`).join("")}</select></div>
    <label class="mopt"><input type="checkbox" data-copt="${gk}" data-i="${i}" ${d[gk] ? "checked" : ""}><span>${t("cOverGre")}</span>${qm("cOverGreHint")}</label>`;
}
// what each end of a carrier reports (only problems)
function carrierState(s, m) {
  const mid = (s.cstate || {})[m], main = (s.cmain || {})[m];
  return (mid ? `<small class="err" dir="auto">${t("cMid")}: ${esc(mid)}</small>` : "") + (main ? `<small class="err" dir="auto">${t("cMain")}: ${esc(main)}</small>` : "");
}
function methodCards(s, i) {
  const ms = tunnelData.methods || [];
  const off = s.off || [];
  return `<div class="mcards">${ms.map((m) => {
    const on = s.method === m.id, trying = on && s.prevMethod, why = m.ready ? methodBlock(s, m.id) : "";
    const can = m.ready && !on && !why;
    const inPool = !off.includes(m.id);
    const cls = "mcard" + (on ? " on" : "") + (m.ready ? "" : " soon") + (m.ready && !on && !inPool ? " out" : "");
    return `<div class="${cls}" data-tn="method" data-i="${i}" data-m="${m.id}" ${can ? `role="button" tabindex="0"` : ""}>
      <div class="mhead"><b>${esc(t("m" + cap(m.id)))}</b>${m.id === "gre" ? qm("qGre") : ""}</div><small>${esc(t("m" + cap(m.id) + "D"))}</small>
      ${(() => {
        const port = m.ready && methodPort[m.id] && tunnelData.ready && !(m.udp && why === t("mNoUdp")) ? `<div class="mopt mport">${portLine(i, methodPort[m.id])}${m.carrier ? qm("qCPort") : ""}</div>` : "";
        const opts = [
          m.protos ? carrierOpts(m, i) : "",
          (m.id === "wss" || m.id === "xhttp") && m.ready ? `<label class="mopt"><input type="checkbox" data-copt="frag" data-i="${i}" ${tunnelData.frag ? "checked" : ""}><span>${t("cFrag")}</span>${qm("qFrag")}</label>` : "",
          m.ready ? `<label class="mopt"><input type="checkbox" data-pool="${m.id}" data-i="${i}" ${inPool || on ? "checked" : ""} ${on || trying ? "disabled" : ""}><span>${t("poolIn")}</span>${qm("poolHint")}</label>` : "",
        ].join("");
        return `<div class="mbottom">${port}${opts ? `<div class="mopts">${opts}</div>` : ""}`;
      })()}
      ${m.carrier ? carrierState(s, m.id) : ""}
      ${why ? `<small class="muted" dir="auto">${esc(why)}</small>` : ""}</div>
      <div class="mfoot"><em>${on ? (trying ? t("mTrying") : "✓ " + t("mActive")) : m.ready ? "" : t("mSoon")}</em>
      ${m.ready && tunnelData.ready && !why ? spButton(s, i, m.id) + spLine(s, m.id) : ""}</div></div>`;
  }).join("")}</div>`;
}
// manual test of one card's path: ping + speed, run by the middle server
const spActive = () => (tunnelData?.servers || []).some((s) => Object.values(s.speed || {}).some((x) => x.state === "queued" || x.state === "running"));
function spButton(s, i, k) {
  const old = !s.agentVer || versionLess(s.agentVer, k === "wg" ? tunnelData.wgTestVer || "0.8.0" : tunnelData.testVer || "0.7.0");
  const cur = (s.speed || {})[k], busy = cur && (cur.state === "queued" || cur.state === "running");
  if (old) return `<button type="button" class="btn small sbtn" disabled title="${esc(t("spUpd").replace("{v}", k === "wg" ? tunnelData.wgTestVer || "0.8.0" : tunnelData.testVer || "0.7.0"))}">${t("spTest")}</button>`;
  return `<button type="button" class="btn small sbtn" data-sp="${k}" data-i="${i}" title="${esc(t("spTitle"))}" ${busy || spActiveOn(s) || !s.online ? "disabled" : ""}>${t("spTest")}</button>`;
}
const spActiveOn = (s) => Object.values(s.speed || {}).some((x) => x.state === "queued" || x.state === "running");
function spLine(s, k) {
  const v = (s.speed || {})[k];
  if (!s.agentVer || versionLess(s.agentVer, tunnelData.testVer || "0.7.0")) return s.lastSeen ? `<small class="spres muted">${esc(t("spUpd").replace("{v}", tunnelData.testVer || "0.7.0"))}</small>` : "";
  if (!v) return "";
  if (v.state === "queued") return `<small class="spres muted">${t("spQueued")}</small>`;
  if (v.state === "running") return `<small class="spres muted">${t("spRunning")}</small>`;
  const when = v.done ? ago(Math.max(0, Math.round(Date.now() / 1000 - v.done))) + " " + t("tnAgo") : "";
  if (v.state === "failed" || !v.res) return `<small class="spres err" dir="auto">${esc(t("spFail").replace("{e}", v.err || "?"))} · ${esc(when)}</small>`;
  const r = v.res, num = (x) => (x >= 100 ? Math.round(x) : Math.round(x * 10) / 10).toString();
  const tip = [t("spPing").replace("{ms}", num(r.ms)).replace("{min}", num(r.min)).replace("{max}", num(r.max)).replace("{j}", num(r.jitter)), r.dlErr, r.ulErr, r.err].filter(Boolean).join(" · ");
  const dl = r.down ? "↓ " + num(r.down) : "↓ ✕", ul = r.up ? "↑ " + num(r.up) : "↑ ✕";
  return `<small class="spres ok" title="${esc(tip)}"><span>${t("spPingL")} <bdi dir="ltr" class="mono">${num(r.ms)} ms</bdi></span>
    <bdi dir="ltr" class="mono">${num(r.min)}–${num(r.max)} ms · ±${num(r.jitter)}</bdi>
    <bdi dir="ltr" class="mono">${dl}  ${ul} Mbps</bdi><span class="muted">${esc(when)}</span></small>`;
}
async function startSpeed(s, k) {
  if (!s) return;
  await api("POST", "api/tunnels/" + s.id + "/speed", { kind: k });
  s.speed = s.speed || {}; s.speed[k] = { kind: k, state: "queued" };
  renderTunnels();
}
async function savePort(i, k) {
  const n = portNum($(`#pe-${i}-${k}`).value), d = tunnelData;
  if (!n || n === d[k]) { portEdit = ""; renderTunnels(); return; }
  if (k === "frpport" || k === "bhport" || k === "sshport") {
    await api("POST", "api/tunnels/csettings", { [k]: n });
    toast(t("done"));
  } else if (k === "wgport" || k === "kport") {
    const m = k === "wgport" ? "wg" : "kcp";
    if (d.servers.some((x) => x.method === m || x.prevMethod === m) && !confirm(t(m === "wg" ? "peAskWg" : "peAskKcp").replace("{p}", n))) return;
    await api("POST", "api/tunnels/dtsettings", { [k]: n });
    toast(t("done"));
  } else {
    const m = Object.keys(methodPort).find((x) => methodPort[x] === k);
    if (d.servers.some((x) => x.method === m || x.prevMethod === m) && !confirm(t("peAskUsed").replace("{m}", t("m" + cap(m))).replace("{p}", n))) return;
    const r = await api("POST", "api/tunnels/settings", { [k]: n });
    toast(r && r.moved && r.moved.length ? t("peMoved") : t("done"));
  }
  portEdit = ""; document.activeElement?.blur(); loadTunnels();
}
$("#tunnelList").addEventListener("click", guard(async (e) => {
  const cp = e.target.closest("[data-copy]"); if (cp) { copyText(cp.dataset.copy); return; }
  const pe = e.target.closest("[data-pe]");
  if (pe) { portEdit = pe.dataset.i + ":" + pe.dataset.pe; renderTunnels(); const inp = $(`#pe-${pe.dataset.i}-${pe.dataset.pe}`); inp?.focus(); inp?.select(); return; }
  const ps = e.target.closest("[data-pe-save]"); if (ps) { await savePort(ps.dataset.i, ps.dataset.peSave); return; }
  if (e.target.closest("[data-pe-cancel]")) { portEdit = ""; renderTunnels(); return; }
  if (e.target.closest(".pedit")) return;
  const sb = e.target.closest("button[data-sp]");
  if (sb) { await startSpeed(tunnelData.servers[+sb.dataset.i], sb.dataset.sp); return; }
  if (e.target.closest(".spres") || e.target.closest(".pool") || e.target.closest(".copt") || e.target.closest(".mopt") || e.target.closest(".qm")) return;
  const mb = e.target.closest("[data-tn=method][role=button]");
  if (mb) {
    const s = tunnelData.servers[+mb.dataset.i], m = mb.dataset.m;
    if (!s.agentVer || versionLess(s.agentVer, tunnelData.methodVer)) { alert(t("mNeedAgent").replace("{v}", tunnelData.methodVer)); return; }
    const why = methodBlock(s, m); if (why) { alert(why); return; }
    if (!confirm(t("mAsk").replace("{m}", t("m" + cap(m))))) return;
    await api("POST", "api/tunnels/" + s.id + "/method", { method: m }); toast(t("done")); loadTunnels(); return;
  }
  const b = e.target.closest("button[data-tn]"); if (!b) return;
  const s = tunnelData.servers[+b.dataset.i];
  if (b.dataset.tn === "del") {
    if (!confirm(t("tnConfirmDel"))) return;
    await api("DELETE", "api/tunnels/" + s.id); toast(t("done")); loadTunnels(); refreshInbounds();
  } else if (b.dataset.tn === "join") {
    await api("POST", "api/tunnels/" + s.id + "/join"); await loadTunnels();
    const ns = tunnelData.servers.find((x) => x.id === s.id); if (ns && ns.command) openJoin(ns);
  } else if (b.dataset.tn === "domain") {
    await api("POST", "api/tunnels/" + s.id + "/domain", { domain: $("#tnDom-" + b.dataset.i).value.trim() });
    document.activeElement?.blur(); toast(t("done")); loadTunnels();
  } else if (b.dataset.tn === "rpsave" || b.dataset.tn === "rpauto") {
    const v = (k) => +$("#rp" + k + "-" + b.dataset.i).value.trim();
    await api("POST", "api/tunnels/" + s.id + "/revports", b.dataset.tn === "rpauto" ? { auto: true } : { r: v("R"), w: v("W"), x: v("X") });
    toast(t("done")); loadTunnels();
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
// a method in or out of a middle server's rotation
$("#tunnelList").addEventListener("change", guard(async (e) => {
  const co = e.target.closest("[data-copt]");
  if (co) {
    const v = co.type === "checkbox" ? co.checked : co.value;
    try { await api("POST", "api/tunnels/csettings", { [co.dataset.copt]: v }); toast(t("done")); } finally { co.blur(); loadTunnels(); }
    return;
  }
  const cb = e.target.closest("input[data-pool]"); if (!cb) return;
  const s = tunnelData.servers[+cb.dataset.i];
  try { await api("POST", "api/tunnels/" + s.id + "/pool", { method: cb.dataset.pool, on: cb.checked }); toast(t("done")); }
  finally { loadTunnels(); }
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
    <label><span>${t("tnStart")} ${qm("qStart")}</span><select name="method"><option value="wss">Xray WS (WebSocket + TLS)</option><option value="xhttp">Xray XHTTP (HTTP/2 + TLS)</option><option value="reality">Xray REALITY</option><option value="wg">WireGuard (UDP)</option><option value="kcp">mKCP (UDP)</option><option value="gre">GRE</option></select></label>
    <label id="tnIPRow" class="hidden"><span>${t("tnPubIP")} ${qm("qPubIP")}</span><input name="ip" placeholder="1.2.3.4" inputmode="decimal"></label>
    <details><summary>${t("tnSshOpt")}</summary>
    <label>${t("tnHost")}<input name="host" placeholder="1.2.3.4"></label>
    <label>${t("tnSshPort")}<input name="sshPort" type="number" min="1" max="65535" value="22"></label>
    <label>${t("tnSshUser")}<input name="sshUser" value="root"></label>
    </details>
  </form>
  <p id="tnErr" class="err"></p>
  <div class="actions"><button class="btn primary" id="tnSave">${t("create")}</button><button class="btn" data-close>${t("cancel")}</button></div>`);
  $("#tnForm").addEventListener("submit", (e) => { e.preventDefault(); $("#tnSave").click(); });
  const tf = $("#tnForm"), isIP = (v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v.trim());
  const ipRow = () => $("#tnIPRow").classList.toggle("hidden", tf.method.value !== "gre");
  tf.method.onchange = ipRow;
  tf.host.oninput = () => { if (isIP(tf.host.value) && (!tf.ip.value || tf.ip.dataset.auto)) { tf.ip.value = tf.host.value.trim(); tf.ip.dataset.auto = "1"; } };
  tf.ip.oninput = () => { delete tf.ip.dataset.auto; };
  $("#tnSave").onclick = async () => {
    const d = Object.fromEntries(new FormData($("#tnForm"))); d.sshPort = +d.sshPort || 22;
    if (d.method !== "gre") delete d.ip;
    const before = new Set((tunnelData?.servers || []).map((x) => x.id));
    const btn = $("#tnSave"); btn.disabled = true; btn.textContent = t("tnCreating"); $("#tnErr").textContent = "";
    let id = "";
    try { id = (await api("POST", "api/tunnels", d)).id; }
    catch (e) {
      // the answer can get lost while xray restarts (when the panel is reached
      // through xray): look for the new server before calling it a failure
      if (e.message === "login") return;
      for (let k = 0; k < 4 && !id; k++) {
        await new Promise((res) => setTimeout(res, 2500));
        try { tunnelData = await api("GET", "api/tunnels"); } catch { continue; }
        id = (tunnelData.servers.find((x) => !before.has(x.id) && x.name === (d.name.trim() || d.host.trim() || "tunnel")) || {}).id || "";
      }
      if (!id) { if ($("#tnErr")) { $("#tnErr").textContent = e.message; btn.disabled = false; btn.textContent = t("create"); } return; }
    }
    closeModal(); await loadTunnels(); refreshInbounds();
    const s = tunnelData.servers.find((x) => x.id === id);
    if (s && s.host) openDeploy(s);
    else if (s && s.command) openJoin(s);
  };
};
// the one-time install command of a middle server, ready to copy
function openJoin(s) {
  openModal(`<h3>${t("tnCmdTitle")} · ${esc(s.name)}</h3><p class="muted">${t("tnQuick")}</p>${copyRow(s.command)}<div class="actions"><button class="btn" data-close>${t("close")}</button></div>`, true);
}
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
setInterval(() => { if (state.view === "tunnels" && !tnTyping() && !$("#app").classList.contains("hidden")) loadTunnels(); }, 15000);

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
        <td>${x.feasible ? `<span dir="auto" class="pill ok">${t("rsOk")}</span>` : `<span dir="auto" class="pill bad" title="${esc(x.reason || "")}">${esc(x.reason || t("rsNo"))}</span>`}</td>
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
