// Language picker shared by the panel, the subscription page and the
// unblocker activation page. XOLang.mount(slot, langs, current, onPick)
// replaces slot with a globe button that opens a searchable grid of
// languages, each in its own name. langs = [[code, native, english, rtl], ...]
(function () {
  "use strict";
  if (window.XOLang) return;
  var css =
    ".xl{position:relative;display:inline-block;font-size:13px}" +
    ".xl-btn{display:inline-flex;align-items:center;gap:7px;height:34px;padding:0 12px 0 10px;border-radius:999px;cursor:pointer;font:inherit;" +
    "border:1px solid var(--xl-line,var(--line,#2c2c31));background:var(--xl-bg,var(--card,#18181b));color:var(--xl-ink,var(--ink,#ececea));white-space:nowrap;transition:border-color .15s}" +
    ".xl-btn:hover,.xl.open .xl-btn{border-color:var(--xl-acc,var(--accent,var(--acc,#5fb39a)))}" +
    ".xl-btn svg{width:15px;height:15px;flex:none;opacity:.8}.xl-btn i{font-style:normal;opacity:.55;font-size:10px;transition:transform .15s}.xl.open .xl-btn i{transform:rotate(180deg)}" +
    ".xl-pop{position:absolute;top:calc(100% + 8px);inset-inline-end:0;z-index:60;width:min(320px,calc(100vw - 24px));padding:8px;border-radius:16px;" +
    "background:var(--xl-bg,var(--card,#18181b));border:1px solid var(--xl-line,var(--line,#2c2c31));box-shadow:0 18px 50px rgba(0,0,0,.28);display:none}" +
    ".xl.open .xl-pop{display:block;animation:xlpop .14s ease-out}@keyframes xlpop{from{opacity:0;transform:translateY(-4px)}}" +
    ".xl-q{width:100%;box-sizing:border-box;margin:0 0 6px;padding:7px 10px;border-radius:10px;font:inherit;font-size:13px;outline:none;" +
    "border:1px solid var(--xl-line,var(--line,#2c2c31));background:var(--xl-soft,var(--bg,#0f0f10));color:var(--xl-ink,var(--ink,#ececea))}" +
    ".xl-list{max-height:min(360px,60vh);overflow:auto;display:grid;grid-template-columns:1fr 1fr;gap:3px}" +
    ".xl-list button{all:unset;box-sizing:border-box;cursor:pointer;padding:7px 10px;border-radius:10px;display:flex;flex-direction:column;line-height:1.35;color:var(--xl-ink,var(--ink,#ececea))}" +
    ".xl-list button:hover,.xl-list button:focus-visible{background:var(--xl-soft,var(--soft,#232327))}" +
    ".xl-list button.on{background:var(--xl-soft,var(--soft,#232327));box-shadow:inset 0 0 0 1px var(--xl-acc,var(--accent,var(--acc,#5fb39a)))}" +
    ".xl-list b{font-weight:600;font-size:14px}.xl-list small{opacity:.6;font-size:11px;direction:ltr;text-align:start}";
  var globe = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.6 2.8 3.9 5.8 3.9 9s-1.3 6.2-3.9 9c-2.6-2.8-3.9-5.8-3.9-9S9.4 5.8 12 3z"/></svg>';
  var all = [];
  function closeAll(except) { all.forEach(function (n) { if (n !== except) n.classList.remove("open"); }); }
  document.addEventListener("click", function () { closeAll(); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeAll(); });
  function mount(slot, langs, cur, onPick, label) {
    if (!document.getElementById("xl-css")) {
      var st = document.createElement("style"); st.id = "xl-css"; st.textContent = css; document.head.appendChild(st);
    }
    var n = document.createElement("div"); n.className = "xl";
    n.innerHTML = '<button type="button" class="xl-btn" aria-haspopup="listbox">' + globe + '<span class="xl-cur"></span><i>▾</i></button>' +
      '<div class="xl-pop"><input type="search" class="xl-q" autocomplete="off"><div class="xl-list" role="listbox"></div></div>';
    slot.replaceWith(n); all.push(n);
    var list = n.querySelector(".xl-list"), q = n.querySelector(".xl-q"), btn = n.querySelector(".xl-btn");
    langs.forEach(function (l) {
      var b = document.createElement("button"); b.type = "button"; b.dataset.l = l[0]; b.setAttribute("role", "option");
      b.dir = l[3] ? "rtl" : "ltr"; b.lang = l[0];
      b.innerHTML = "<b></b><small></small>"; b.firstChild.textContent = l[1]; b.lastChild.textContent = l[2];
      b.onclick = function () { n.classList.remove("open"); onPick(l[0]); };
      list.appendChild(b);
    });
    function filter() {
      var s = q.value.trim().toLowerCase();
      list.querySelectorAll("button").forEach(function (b) { b.hidden = !!s && b.textContent.toLowerCase().indexOf(s) < 0 && b.dataset.l.indexOf(s) !== 0; });
    }
    q.oninput = filter;
    q.onkeydown = function (e) { if (e.key === "Enter") { var f = list.querySelector("button:not([hidden])"); if (f) f.click(); } };
    btn.onclick = function (e) {
      e.stopPropagation(); closeAll(n); n.classList.toggle("open");
      if (n.classList.contains("open")) { q.value = ""; filter(); var on = list.querySelector(".on"); if (on) on.scrollIntoView({ block: "nearest" }); if (matchMedia("(pointer:fine)").matches) q.focus(); }
    };
    n.querySelector(".xl-pop").onclick = function (e) { e.stopPropagation(); };
    n.set = function (code, lbl, ph) {
      var m = langs.filter(function (l) { return l[0] === code; })[0] || langs[0];
      n.querySelector(".xl-cur").textContent = m[1];
      btn.title = lbl || ""; btn.setAttribute("aria-label", (lbl ? lbl + ": " : "") + m[1]); q.placeholder = ph || "";
      list.querySelectorAll("button").forEach(function (b) { b.classList.toggle("on", b.dataset.l === code); });
    };
    n.set(cur, label);
    return n;
  }
  window.XOLang = { mount: mount };
})();
