/* ==========================================================================
   CyberBuddy — shared app helpers + live scan engines
   GitHub Pages cannot run Python. When /api/* is absent we run the same
   scoring logic in the browser and fetch headers through a public lookup
   (local server.py is always preferred when it is online).
   ========================================================================== */
"use strict";

document.documentElement.classList.add("js");

/* ---------- Icon set ---------------------------------------------------- */
const ICONS = {
  logo: '<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><rect x="2" y="2" width="28" height="28" rx="7" stroke="currentColor" stroke-width="2.2"/><path d="M8 16h4l3-7 6 14 3-7h4" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  frame: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M15 3v18" stroke-dasharray="3 3"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
  cors: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="5.5" cy="12" r="2.5"/><circle cx="18.5" cy="12" r="2.5"/><path d="M8 12h3M13 12h3" stroke-dasharray="2 2"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 5v14M5 12h14" stroke-linecap="round"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M9 6l6 6-6 6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>',
  linkedin: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>'
};

/* ---------- Site root (GitHub project pages + local) -------------------- */

function appBase() {
  // Slice the *pathname*, never an index into the full URL.
  const marker = "/js/app.js";
  const scripts = document.getElementsByTagName("script");
  for (let i = 0; i < scripts.length; i++) {
    const raw = scripts[i].getAttribute("src") || scripts[i].src || "";
    if (!raw) continue;
    try {
      const path = new URL(raw, window.location.href).pathname.replace(/\\/g, "/");
      if (!path.endsWith(marker)) continue;
      let base = path.slice(0, -marker.length);
      if (base === "/") base = "";
      return base;
    } catch (_) { /* ignore */ }
  }
  const path = (window.location.pathname || "").replace(/\\/g, "/");
  const fromTool = path.match(/^(.*)\/tools\/[^/]+\/?$/);
  if (fromTool) return fromTool[1];
  const known = path.match(/^(\/CyberBuddy)(?=\/|$)/i);
  return known ? known[1] : "";
}

function pagePath() {
  return (window.location.pathname || "").replace(/\/index\.html$/, "/") || "/";
}

function apiUrl(path) {
  return appBase() + path;
}

function apiHeadersInit() {
  return { cache: "no-store", headers: { "X-Requested-With": "CyberBuddy" } };
}

/* ---------- Theme (dark / light) ---------------------------------------- */

const THEME_KEY = "cb-theme";

function currentTheme() {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

function applyTheme(theme, persist) {
  const root = document.documentElement;
  if (theme === "light") root.setAttribute("data-theme", "light");
  else root.removeAttribute("data-theme");
  if (persist !== false) {
    try { localStorage.setItem(THEME_KEY, theme); } catch (_) { /* private mode */ }
  }
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", theme === "light" ? "#eef2f7" : "#07090d");
  const btn = document.getElementById("themeToggle");
  if (btn) {
    const next = theme === "light" ? "dark" : "light";
    btn.innerHTML = ICONS[next === "dark" ? "moon" : "sun"];
    btn.setAttribute("aria-label", "Switch to " + next + " mode");
    btn.title = "Switch to " + next + " mode";
    btn.classList.toggle("is-light", theme === "light");
  }
}

function initThemeToggle() {
  applyTheme(currentTheme(), false);
}

/* ---------- Shell ------------------------------------------------------- */

function renderHeader(current) {
  const base = appBase();
  const html =
    '<div class="ambient" aria-hidden="true"></div>' +
    '<a class="skip-link" href="#main">Skip to content</a>' +
    '<header class="site-header"><div class="container header-inner">' +
    '<a class="brand" href="' + base + '/">' +
    '<span class="brand-mark">' + ICONS.logo + "</span><span>CyberBuddy</span></a>" +
    '<nav class="main-nav" aria-label="Tools">' +
    navLink(base, "/", "Hub", current) +
    toolsMenu(base, "hdr") +
    "</nav>" +
    '<button type="button" id="themeToggle" class="theme-toggle" aria-label="Switch theme" title="Switch theme">' +
    ICONS.sun + "</button>" +
    '<span class="engine-chip" id="engineChip" title="Checking scan engine…">' +
    '<span class="engine-dot" id="engineDot"></span>' +
    '<span id="engineText">engine · …</span></span>' +
    "</div></header>";
  document.body.insertAdjacentHTML("afterbegin", html);
  detectEngine();
  initAmbient();
  initThemeToggle();

  document.addEventListener("click", (e) => {
    document.querySelectorAll("details.nav-menu[open]").forEach((m) => {
      if (!m.contains(e.target)) m.removeAttribute("open");
    });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document.querySelectorAll("details.nav-menu[open]").forEach((m) => m.removeAttribute("open"));
    }
  });
}

const TOOLS_MENU = [
  {
    href: "/tools/clickjacking/",
    label: "Clickjacking Validator",
    status: "live",
    icon: "frame",
    desc: "Load a target in a live frame. If the real UI appears, the page can be clickjacked — screenshot the result as proof.",
    tags: ["X-Frame-Options", "frame-ancestors", "iframe PoC"]
  },
  {
    href: "/tools/headers/",
    label: "Security Headers",
    status: "live",
    icon: "shield",
    desc: "Grade CSP, X-Frame-Options, HSTS, cookie flags and the COOP/COEP family into an A–F score with the raw header behind every finding.",
    tags: ["CSP", "HSTS", "COOP/COEP", "grade A–F"]
  },
  {
    href: "/tools/cors/",
    label: "CORS Validator",
    status: "live",
    icon: "cors",
    desc: "See how the target treats this page as a cross-origin caller — origin access, credentials, and Vary: Origin.",
    tags: ["ACAO", "credentials", "Vary: Origin"]
  }
];
const TOOLS_SOON = ["CSP Policy Auditor", "TLS / SSL Analyzer", "Subdomain Enumeration"];

function toolsMenu(base, uid) {
  const id = "toolsMenu-" + (uid || "x");
  const up = uid === "ftr" ? " up" : "";
  const path = pagePath();
  const items = TOOLS_MENU.map((t) => {
    const active = (base + t.href) === path;
    return '<a class="nav-menu-item' + (active ? " active" : "") + '" href="' + base + t.href + '">' +
      t.label + '<span class="nav-status ' + t.status + '">' + t.status + "</span></a>";
  }).join("");
  const soon = TOOLS_SOON.map((s) =>
    '<span class="nav-menu-item disabled" aria-disabled="true">' + s +
    '<span class="nav-status soon">soon</span></span>'
  ).join("");
  return '<details class="nav-menu' + up + '" id="' + id + '">' +
    "<summary>Tools " + ICONS.chevron + "</summary>" +
    '<div class="nav-menu-panel">' + items +
    '<div class="nav-menu-divider">In development</div>' + soon +
    "</div></details>";
}

function navLink(base, href, label, current) {
  const path = pagePath();
  const isCurrent = (base + href) === path || (href === "/" && (path === base + "/" || path === base));
  return '<a href="' + base + href + '"' + (isCurrent ? ' aria-current="page"' : "") + ">" + label + "</a>";
}

function renderFooter() {
  const base = appBase();
  const html =
    '<footer class="site-footer"><div class="container footer-inner">' +
    '<div class="footer-brand"><span class="brand-mark">' + ICONS.logo + "</span>" +
    "<div><strong>CyberBuddy</strong><span>Browser security assessment suite</span></div></div>" +
    '<nav class="footer-nav" aria-label="Footer">' +
    '<a href="' + base + '/">Hub</a>' +
    toolsMenu(base, "ftr") +
    "</nav>" +
    '<div class="footer-contact">' +
    "<strong>Connect</strong>" +
    "<span>Ideas, feedback, or collaboration on improving CyberBuddy?</span>" +
    '<a href="mailto:amitpal.secure@gmail.com">amitpal.secure@gmail.com</a>' +
    '<a class="social-link" href="https://www.linkedin.com/in/amitpal-wb/" target="_blank" rel="noopener noreferrer">' +
    ICONS.linkedin + "Connect on LinkedIn</a>" +
    "</div>" +
    '<p class="footer-legal">' +
    "Authorized testing only. CyberBuddy performs read-only checks against URLs you provide; " +
    "you are responsible for having permission to test them. On GitHub Pages, header values are " +
    "read through a public lookup so the graders can run without a Python host. Run server.py " +
    "locally for a same-origin engine that never leaves your machine. © 2026 CyberBuddy." +
    "</p>" +
    "</div></footer>";
  document.body.insertAdjacentHTML("beforeend", html);
}

function renderToolCards() {
  const grid = document.getElementById("toolGrid");
  if (!grid) return;
  const base = appBase();
  const live = TOOLS_MENU.filter((t) => t.status === "live").length;
  const count = document.getElementById("toolCount");
  if (count) count.textContent = String(live).padStart(2, "0") + " live";
  const cards = TOOLS_MENU.map((t, i) => {
    const icon = ICONS[t.icon] || ICONS.plus;
    const tags = (t.tags || []).map((tag) => '<span class="tool-tag">' + esc(tag) + "</span>").join("");
    const led = t.status === "live" ? "status-led" : "status-led " + t.status;
    return '<a class="tool-card card corner-card reveal" style="--d: ' + (0.05 + i * 0.07) + 's" href="' +
      base + t.href + '">' +
      '<div class="tool-card-top"><span class="tool-card-icon">' + icon +
      '</span><span class="' + led + '">' + esc(t.status) + "</span></div>" +
      "<div><h3>" + esc(t.label) + '</h3><p class="tool-card-desc">' + esc(t.desc) + "</p></div>" +
      '<div class="tool-card-tags">' + tags + "</div>" +
      '<span class="tool-card-open">Run check ' + ICONS.chevron + "</span></a>";
  }).join("");
  const soonTags = TOOLS_SOON.map((s) => '<span class="tool-tag">' + esc(s.split(" ")[0]) + "</span>").join("");
  const ghost =
    '<div class="tool-card card tool-card--ghost reveal" style="--d: .26s">' +
    '<div class="tool-card-top"><span class="tool-card-icon">' + ICONS.plus +
    '</span><span class="status-led soon">soon</span></div>' +
    "<div><h3>More tools coming soon</h3>" +
    '<p class="tool-card-desc">' + esc(TOOLS_SOON.join(", ")) +
    " and more are on the bench — this slot is reserved for the next check to ship.</p></div>" +
    '<div class="tool-card-tags">' + soonTags + "</div></div>";
  grid.innerHTML = cards + ghost;
  initCardSpotlights(grid);
}

/* ---------- Engine detection -------------------------------------------- */

window.__cbEngine = { mode: "checking" };

async function detectEngine() {
  const chip = document.getElementById("engineChip");
  const dot = document.getElementById("engineDot");
  const text = document.getElementById("engineText");
  if (!chip || !dot || !text) return { online: false, reason: "no-chip" };

  const timeout = new Promise((resolve) => setTimeout(() => resolve("timeout"), 2500));
  try {
    const res = await Promise.race([
      fetch(apiUrl("/api/health"), apiHeadersInit()),
      timeout
    ]);
    if (res !== "timeout" && res && res.ok) {
      const ctype = (res.headers.get("content-type") || "").toLowerCase();
      if (ctype.includes("application/json")) {
        const data = await res.json();
        if (data && data.ok === true) {
          window.__cbEngine = { mode: "python" };
          chip.title = "Python engine online — scans run on this host";
          chip.classList.add("is-on");
          dot.classList.add("on");
          text.textContent = "python · online";
          return { online: true, reason: "python" };
        }
      }
    }
  } catch (_) { /* fall through to live */ }

  window.__cbEngine = { mode: "live" };
  chip.title = "Live mode — graders run in this browser (GitHub Pages)";
  chip.classList.add("is-live");
  dot.classList.add("on", "live");
  text.textContent = "live · github";
  return { online: false, reason: "live" };
}

async function apiCall(path, url) {
  try {
    const res = await fetch(apiUrl(path) + "?" + new URLSearchParams({ url }), apiHeadersInit());
    const ctype = (res.headers.get("content-type") || "").toLowerCase();
    if (!ctype.includes("application/json")) return null;
    let data = null;
    try { data = await res.json(); } catch (_) { return null; }
    if (!res.ok) {
      return { error: (data && data.error) || ("API " + res.status), status: res.status };
    }
    return data;
  } catch (err) {
    return null;
  }
}

function isUsableScan(data, kind) {
  if (!data || data.error && !data.checks && !data.findings) return false;
  if (kind === "headers") return Array.isArray(data.checks) && data.grade;
  if (kind === "scan") return Array.isArray(data.findings);
  if (kind === "cors") return Array.isArray(data.checks);
  return false;
}

async function apiScan(url) {
  const local = await apiCall("/api/scan", url);
  if (isUsableScan(local, "scan")) {
    local._source = "python";
    return local;
  }
  return gradeClickjackingLive(url);
}

async function apiHeaders(url) {
  const local = await apiCall("/api/headers", url);
  if (isUsableScan(local, "headers")) {
    local._source = "python";
    return local;
  }
  return gradeHeadersLive(url);
}

async function apiCors(url) {
  const local = await apiCall("/api/cors", url);
  if (isUsableScan(local, "cors")) {
    local._source = "python";
    return local;
  }
  return probeCorsLive(url);
}

function isEngineDown(data) {
  return data == null;
}

function apiErrorMessage(data) {
  if (!data) return "";
  if (data.error) return String(data.error);
  if (data.summary && data.risk === "unknown") return String(data.summary);
  return "";
}

function sourceLabel(data) {
  const s = data && data._source;
  if (s === "python") return "python engine";
  if (s === "relay") return "live lookup";
  if (s === "browser") return "this browser";
  if (s === "none") return "no engine";
  return s || "live";
}

/* ---------- Shared helpers ---------------------------------------------- */

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function normalizeUrl(raw) {
  raw = (raw || "").trim();
  if (!raw) return "";
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw) && !/^https?:\/\//i.test(raw)) return "";
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  return raw;
}

function validUrl(raw) {
  try {
    const u = new URL(normalizeUrl(raw));
    return u.protocol === "http:" || u.protocol === "https:";
  } catch (_) {
    return false;
  }
}

function gradeFor(score) {
  score = Number(score) || 0;
  if (score >= 90) return "a";
  if (score >= 75) return "b";
  if (score >= 60) return "c";
  if (score >= 45) return "d";
  return "f";
}

function gradeLetter(score) {
  return gradeFor(score).toUpperCase();
}

function pushUrlParam(url) {
  const next = new URL(window.location.href);
  next.searchParams.set("url", url);
  history.replaceState(null, "", next);
}

function fmtStamp(d) {
  d = d || new Date();
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function setLoading(btn, loading) {
  if (!btn) return;
  btn.disabled = loading;
  btn.classList.toggle("is-loading", loading);
  if (loading) {
    if (!btn.querySelector(".spinner")) {
      btn.insertAdjacentHTML("afterbegin", '<span class="spinner" aria-hidden="true"></span>');
    }
  } else {
    const s = btn.querySelector(".spinner");
    if (s) s.remove();
  }
}

function bump(el) {
  if (!el) return;
  el.classList.remove("bump");
  void el.offsetWidth;
  el.classList.add("bump");
}

function prefersReduced() {
  return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
}

function countUp(el, target, suffix) {
  if (!el) return;
  suffix = suffix || "";
  if (prefersReduced() || !("requestAnimationFrame" in window)) {
    el.textContent = target + suffix;
    return;
  }
  const t0 = performance.now();
  const dur = 650;
  (function frame(t) {
    const p = Math.min(1, (t - t0) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(target * eased) + suffix;
    if (p < 1) requestAnimationFrame(frame);
  })(t0);
}

function initReveal() {
  const els = Array.prototype.slice.call(document.querySelectorAll(".reveal"));
  if (!els.length) return;
  const inView = (el) => {
    const r = el.getBoundingClientRect();
    return r.top < window.innerHeight && r.bottom > 0;
  };
  if (!("IntersectionObserver" in window)) {
    els.forEach((el) => el.classList.add("in"));
    return;
  }
  els.forEach((el) => { if (inView(el)) el.classList.add("in"); });
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        e.target.classList.add("in");
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.05 });
  els.forEach((el) => io.observe(el));
  setTimeout(() => { els.forEach((el) => el.classList.add("in")); }, 2000);
}

function exportReport() {
  window.print();
}

function initAmbient() {
  const el = document.querySelector(".ambient");
  if (!el || prefersReduced()) return;
  let raf = 0;
  let x = 0;
  let y = 0;
  window.addEventListener("pointermove", (e) => {
    x = e.clientX;
    y = e.clientY;
    if (raf) return;
    raf = requestAnimationFrame(() => {
      el.style.setProperty("--mx", x + "px");
      el.style.setProperty("--my", y + "px");
      raf = 0;
    });
  }, { passive: true });
}

function initCardSpotlights(root) {
  if (!root || prefersReduced()) return;
  root.querySelectorAll(".tool-card").forEach((card) => {
    card.addEventListener("pointermove", (e) => {
      const r = card.getBoundingClientRect();
      card.style.setProperty("--sx", (e.clientX - r.left) + "px");
      card.style.setProperty("--sy", (e.clientY - r.top) + "px");
    });
  });
}

/* ==========================================================================
   Live engines — faithful port of the Python graders
   ========================================================================== */

const WEIGHTS = {
  "Content-Security-Policy": 25,
  "X-Frame-Options": 15,
  "Strict-Transport-Security": 15,
  "X-Content-Type-Options": 10,
  "Referrer-Policy": 10,
  "Permissions-Policy": 5,
  "Cross-Origin-Opener-Policy": 5,
  "Cross-Origin-Embedder-Policy": 5,
  "Cross-Origin-Resource-Policy": 5
};
const XFO_MISSING_WITH_CSP = 5;
const REFERRER_OK = {
  "no-referrer": 1, "same-origin": 1, "strict-origin": 1,
  "strict-origin-when-cross-origin": 1, "origin": 1, "origin-when-cross-origin": 1
};

function parseCsp(csp) {
  const directives = {};
  String(csp || "").split(";").forEach((part) => {
    part = part.trim();
    if (!part) return;
    const tokens = part.split(/\s+/);
    directives[tokens[0].toLowerCase()] = tokens.slice(1).map((t) => t.toLowerCase());
  });
  return directives;
}

function srcIssues(name, tokens) {
  const issues = [];
  if (tokens.indexOf("*") !== -1) issues.push([name + " allows * (any origin can load this type)", 15]);
  if (tokens.indexOf("'unsafe-inline'") !== -1) issues.push([name + " allows 'unsafe-inline' (weakens XSS protections)", 15]);
  if (tokens.indexOf("'unsafe-eval'") !== -1) issues.push([name + " allows 'unsafe-eval'", 10]);
  if (tokens.some((t) => t === "data:" || t.indexOf("data:") === 0)) issues.push([name + " allows data: URIs", 10]);
  if (tokens.indexOf("http:") !== -1) issues.push([name + " allows http: (mixed content)", 10]);
  return issues;
}

function check(name, status, detail, evidence, deduction) {
  return { name: name, status: status, detail: detail, evidence: evidence || "", deduction: deduction || 0 };
}

function checkTransport(url) {
  try {
    if (new URL(url).protocol === "https:") {
      return check("Transport", "ok", "HTTPS in use — headers cannot be stripped on the wire.", "", 0);
    }
  } catch (_) { /* ignore */ }
  return check("Transport", "weak", "HTTP URL. Response headers can be stripped or injected on the network. Prefer HTTPS.", url, 5);
}

function checkCsp(value) {
  if (!value) {
    return check("Content-Security-Policy", "missing",
      "Header not present. CSP is the modern defense-in-depth header: restrict script sources, block mixed content, and set frame-ancestors.",
      "", WEIGHTS["Content-Security-Policy"]);
  }
  const d = parseCsp(value);
  const notes = [];
  let deduction = 0;
  const hasScript = "script-src" in d || "script-src-elem" in d;
  const hasDefault = "default-src" in d;
  if (!hasScript && !hasDefault) {
    notes.push("no script-src or default-src (scripts are unrestricted)");
    deduction = Math.max(deduction, 15);
  }
  let tokens = null;
  let label = "";
  if (d["script-src"]) { tokens = d["script-src"]; label = "script-src"; }
  else if (d["script-src-elem"]) { tokens = d["script-src-elem"]; label = "script-src-elem"; }
  else if (hasDefault) { tokens = d["default-src"]; label = "default-src"; }
  if (tokens) {
    srcIssues(label, tokens).forEach((pair) => {
      notes.push(pair[0]);
      deduction = Math.max(deduction, pair[1]);
    });
  }
  if (d["script-src"] && d["script-src-elem"]) {
    srcIssues("script-src-elem", d["script-src-elem"]).forEach((pair) => {
      notes.push(pair[0]);
      deduction = Math.max(deduction, pair[1]);
    });
  }
  if (notes.length) {
    return check("Content-Security-Policy", "weak", "Header present but " + notes.join("; ") + ".", value.slice(0, 300), deduction);
  }
  let detail = "Header present with no obvious weak directives.";
  if (d["frame-ancestors"]) detail += " Includes frame-ancestors (clickjacking control).";
  return check("Content-Security-Policy", "ok", detail, value.slice(0, 300), 0);
}

function frameAncestorsRestricts(csp) {
  if (!csp) return false;
  const sources = parseCsp(csp)["frame-ancestors"];
  if (!sources) return false;
  return sources.indexOf("*") === -1;
}

function checkXfo(value, faOk) {
  if (!value) {
    const ded = faOk ? XFO_MISSING_WITH_CSP : WEIGHTS["X-Frame-Options"];
    const note = faOk
      ? "CSP frame-ancestors covers framing; X-Frame-Options is optional when present."
      : "Browsers may allow framing unless CSP frame-ancestors is also set.";
    return check("X-Frame-Options", "missing", "Header not present. " + note, "", ded);
  }
  const token = value.trim().split(",")[0].trim().toUpperCase();
  if (token === "DENY" || token === "SAMEORIGIN") {
    return check("X-Frame-Options", "ok", token + " blocks cross-origin framing.", value.trim(), 0);
  }
  if (token.indexOf("ALLOW-FROM") === 0) {
    return check("X-Frame-Options", "weak", "ALLOW-FROM is obsolete and ignored by modern browsers. Use CSP frame-ancestors.", value.trim(), WEIGHTS["X-Frame-Options"]);
  }
  return check("X-Frame-Options", "weak", "Unrecognized value; treat as ineffective.", value.trim(), WEIGHTS["X-Frame-Options"]);
}

function checkHsts(value, isHttps) {
  if (!isHttps) {
    return check("Strict-Transport-Security", "info", "Only meaningful over HTTPS — no HSTS check on an HTTP target.", "", 0);
  }
  if (!value) {
    return check("Strict-Transport-Security", "missing", "Header not present. HSTS forces HTTPS and prevents SSL-stripping for returning visitors.", "", WEIGHTS["Strict-Transport-Security"]);
  }
  const m = /max-age=(\d+)/i.exec(value);
  const maxAge = m ? parseInt(m[1], 10) : 0;
  if (maxAge === 0) {
    return check("Strict-Transport-Security", "missing", "max-age=0 disables HSTS (browsers forget the policy). This is not a protection.", value.trim(), WEIGHTS["Strict-Transport-Security"]);
  }
  if (maxAge < 180 * 86400) {
    return check("Strict-Transport-Security", "weak", "max-age=" + maxAge + "s is short; browsers need ≥ 15552000s (180 days) for meaningful protection.", value.trim(), 5);
  }
  if (value.toLowerCase().indexOf("includesubdomains") === -1) {
    return check("Strict-Transport-Security", "weak", "Max-age is fine but includeSubDomains is missing.", value.trim(), 5);
  }
  return check("Strict-Transport-Security", "ok", "HSTS present with a strong max-age (and includeSubDomains).", value.trim(), 0);
}

function checkNosniff(value) {
  if (!value) {
    return check("X-Content-Type-Options", "missing", "Header not present. Set 'nosniff' to stop MIME-sniffing attacks.", "", WEIGHTS["X-Content-Type-Options"]);
  }
  if (value.trim().toLowerCase() === "nosniff") {
    return check("X-Content-Type-Options", "ok", "nosniff set — browsers will not MIME-sniff responses.", value.trim(), 0);
  }
  return check("X-Content-Type-Options", "weak", "Only 'nosniff' is meaningful.", value.trim(), WEIGHTS["X-Content-Type-Options"]);
}

function checkReferrer(value) {
  if (!value) {
    return check("Referrer-Policy", "missing", "Header not present. Browsers fall back to 'strict-origin-when-cross-origin', but an explicit policy is clearer and more consistent.", "", WEIGHTS["Referrer-Policy"]);
  }
  const token = value.trim().split(",")[0].trim().toLowerCase();
  if (REFERRER_OK[token]) {
    return check("Referrer-Policy", "ok", token + " — referrer leakage is limited.", value.trim(), 0);
  }
  if (token === "unsafe-url" || token === "no-referrer-when-downgrade") {
    return check("Referrer-Policy", "weak", "'" + token + "' can leak full URLs (including query strings) to other origins.", value.trim(), WEIGHTS["Referrer-Policy"]);
  }
  return check("Referrer-Policy", "weak", "Unrecognized policy value.", value.trim(), 5);
}

function checkPermissions(value) {
  if (!value) {
    return check("Permissions-Policy", "missing", "Header not present. Recommended for locking down powerful features (camera, microphone, geolocation). Optional hardening.", "", WEIGHTS["Permissions-Policy"]);
  }
  const wildcarded = [];
  value.split(",").forEach((tok) => {
    if (tok.indexOf("=") === -1) return;
    const parts = tok.split("=");
    const allow = parts.slice(1).join("=").trim().toLowerCase();
    if (allow === "*" || allow === "(*)") wildcarded.push(parts[0].trim());
  });
  if (wildcarded.length) {
    return check("Permissions-Policy", "weak", "Feature(s) allowlisted as bare wildcard: " + wildcarded.join(", ") + ". Restrict them to 'self' or an origin allowlist.", value.slice(0, 300), 5);
  }
  return check("Permissions-Policy", "ok", "Header present.", value.slice(0, 300), 0);
}

function checkCoop(value) {
  if (!value) {
    return check("Cross-Origin-Opener-Policy", "missing", "Header not present. 'same-origin' isolates the browsing context from cross-origin popups (mitigates some Spectre-era attacks).", "", WEIGHTS["Cross-Origin-Opener-Policy"]);
  }
  const token = value.trim().split(";")[0].trim().toLowerCase();
  if (token === "same-origin" || token === "same-origin-allow-popups") {
    return check("Cross-Origin-Opener-Policy", "ok", token + " — cross-origin popup isolation active.", value.trim(), 0);
  }
  return check("Cross-Origin-Opener-Policy", "weak", "'unsafe-none' provides no cross-origin isolation.", value.trim(), WEIGHTS["Cross-Origin-Opener-Policy"]);
}

function checkCoep(value) {
  if (!value) {
    return check("Cross-Origin-Embedder-Policy", "missing", "Header not present. 'require-corp' forces CORP/CORS on all subresources (needed for cross-origin isolation).", "", WEIGHTS["Cross-Origin-Embedder-Policy"]);
  }
  const token = value.trim().split(";")[0].trim().toLowerCase();
  if (token === "require-corp") {
    return check("Cross-Origin-Embedder-Policy", "ok", "require-corp — subresources must opt in via CORP or CORS.", value.trim(), 0);
  }
  if (token === "credentialless") {
    return check("Cross-Origin-Embedder-Policy", "ok", "credentialless — cross-origin subresources load without credentials.", value.trim(), 0);
  }
  return check("Cross-Origin-Embedder-Policy", "weak", "'unsafe-none' does not restrict cross-origin subresources.", value.trim(), WEIGHTS["Cross-Origin-Embedder-Policy"]);
}

function checkCorp(value) {
  if (!value) {
    return check("Cross-Origin-Resource-Policy", "missing", "Header not present. Restricts which origins may load this resource ('same-origin' / 'same-site' / 'cross-origin').", "", WEIGHTS["Cross-Origin-Resource-Policy"]);
  }
  const token = value.trim().toLowerCase();
  if (token === "same-origin" || token === "same-site" || token === "cross-origin") {
    return check("Cross-Origin-Resource-Policy", "ok", token + " — resource loading policy explicit.", value.trim(), 0);
  }
  return check("Cross-Origin-Resource-Policy", "weak", "Unrecognized value.", value.trim(), 5);
}

function cookieFlagNotes(setCookie) {
  const notes = [];
  String(setCookie || "").split("\n").forEach((raw) => {
    raw = raw.trim();
    if (!raw) return;
    const parts = raw.split(";").map((p) => p.trim());
    const name = (parts[0].split("=")[0] || "cookie").trim();
    const attrs = parts.slice(1).map((p) => p.toLowerCase());
    const flags = {};
    let samesite = "";
    attrs.forEach((a) => {
      flags[a.split("=")[0].trim()] = true;
      if (a.indexOf("samesite=") === 0) samesite = a.split("=")[1].trim();
    });
    const missing = [];
    if (!flags.secure) missing.push("Secure");
    if (!flags.httponly) missing.push("HttpOnly");
    if (!flags.samesite) missing.push("SameSite");
    else if (samesite === "none" && !flags.secure) missing.push("SameSite=None requires Secure");
    if (missing.length) notes.push(name + ": " + missing.join(", ") + " missing");
  });
  return notes;
}

function checkCookies(value) {
  if (!value) return null;
  const notes = cookieFlagNotes(value);
  if (notes.length) {
    return check("Set-Cookie flags", "weak", notes.join("; ") + ".", value.slice(0, 250), 5);
  }
  return check("Set-Cookie flags", "ok", "Secure, HttpOnly and SameSite are set on the response cookies.", value.slice(0, 250), 0);
}

function riskForGrade(grade) {
  return { A: "low", B: "low", C: "medium", D: "medium", F: "high" }[grade] || "unknown";
}

function summarizeHeaders(grade, missing) {
  let extra = "";
  if (missing.length && grade !== "A") {
    extra = " Missing: " + missing.slice(0, 4).join(", ") + (missing.length > 4 ? "…" : "") + ".";
  }
  if (grade === "A") return "Strong header posture. Keep it this way — and re-test after any deployment change.";
  if (grade === "B") return "Good posture with a few gaps. Close them for a bulletproof baseline." + extra;
  if (grade === "C") return "Notable gaps — attackers get signal here. Prioritize the missing headers." + extra;
  if (grade === "D") return "Weak posture. Multiple important headers missing or misconfigured." + extra;
  return "Critical posture. Key protections are absent — treat the site as exposed until fixed." + extra;
}

function interestingHeaders(headers) {
  const keys = [
    "content-security-policy", "content-security-policy-report-only", "x-frame-options",
    "strict-transport-security", "x-content-type-options", "referrer-policy",
    "permissions-policy", "feature-policy", "cross-origin-opener-policy",
    "cross-origin-embedder-policy", "cross-origin-resource-policy", "set-cookie"
  ];
  const out = {};
  keys.forEach((k) => { if (headers[k]) out[k] = headers[k]; });
  return out;
}

function gradeHeadersFromMap(url, status, finalUrl, headers, source) {
  headers = headers || {};
  let isHttps = false;
  try { isHttps = new URL(finalUrl || url).protocol === "https:"; } catch (_) { /* ignore */ }
  const csp = headers["content-security-policy"];
  const faOk = frameAncestorsRestricts(csp);
  const checks = [
    checkTransport(finalUrl || url),
    checkCsp(csp),
    checkXfo(headers["x-frame-options"], faOk),
    checkHsts(headers["strict-transport-security"], isHttps),
    checkNosniff(headers["x-content-type-options"]),
    checkReferrer(headers["referrer-policy"]),
    checkPermissions(headers["permissions-policy"] || headers["feature-policy"]),
    checkCoop(headers["cross-origin-opener-policy"]),
    checkCoep(headers["cross-origin-embedder-policy"]),
    checkCorp(headers["cross-origin-resource-policy"])
  ];
  if (headers["content-security-policy-report-only"]) {
    checks.push(check("CSP-Report-Only", "info", "Report-Only CSP is present and does not enforce anything — it only reports violations.", headers["content-security-policy-report-only"].slice(0, 300), 0));
  }
  const ck = checkCookies(headers["set-cookie"]);
  if (ck) checks.push(ck);
  const score = Math.max(0, 100 - checks.reduce((n, c) => n + (c.deduction || 0), 0));
  const grade = gradeLetter(score);
  const missing = checks.filter((c) => c.status === "missing").map((c) => c.name);
  return {
    url: url,
    final_url: finalUrl || url,
    status_code: status,
    checks: checks,
    score: score,
    grade: grade,
    risk: riskForGrade(grade),
    summary: summarizeHeaders(grade, missing),
    headers: interestingHeaders(headers),
    _source: source || "live"
  };
}

/* ---------- Clickjacking scoring ---------------------------------------- */

function assessXfo(value) {
  if (!value) {
    return { name: "X-Frame-Options", status: "missing", detail: "Header not present. Browsers may allow framing unless CSP frame-ancestors is set.", evidence: "" };
  }
  const raw = value.trim();
  const token = raw.split(",")[0].trim().toUpperCase();
  if (token === "DENY") {
    return { name: "X-Frame-Options", status: "protected", detail: "DENY blocks framing from any origin, including the site itself.", evidence: raw };
  }
  if (token === "SAMEORIGIN") {
    return { name: "X-Frame-Options", status: "protected", detail: "SAMEORIGIN allows framing only by the same origin.", evidence: raw };
  }
  if (token.indexOf("ALLOW-FROM") === 0) {
    return { name: "X-Frame-Options", status: "weak", detail: "ALLOW-FROM is obsolete and ignored by modern browsers. Use CSP frame-ancestors.", evidence: raw };
  }
  return { name: "X-Frame-Options", status: "weak", detail: "Unrecognized X-Frame-Options value; treat as ineffective.", evidence: raw };
}

function assessFrameAncestors(cspValue) {
  if (!cspValue) {
    return { name: "CSP frame-ancestors", status: "missing", detail: "No Content-Security-Policy header. frame-ancestors is the modern clickjacking control.", evidence: "" };
  }
  const d = parseCsp(cspValue);
  if (!("frame-ancestors" in d)) {
    return { name: "CSP frame-ancestors", status: "missing", detail: "CSP is present but frame-ancestors is not set. Other CSP directives do not stop framing.", evidence: cspValue.slice(0, 300) };
  }
  const sources = d["frame-ancestors"];
  const ev = "frame-ancestors " + sources.join(" ");
  if (!sources.length || (sources.length === 1 && sources[0] === "'none'")) {
    return { name: "CSP frame-ancestors", status: "protected", detail: "frame-ancestors 'none' forbids all framing (strongest modern control).", evidence: ev };
  }
  if (sources.length === 1 && sources[0] === "'self'") {
    return { name: "CSP frame-ancestors", status: "protected", detail: "frame-ancestors 'self' allows only same-origin frames.", evidence: ev };
  }
  if (sources.indexOf("*") !== -1) {
    return { name: "CSP frame-ancestors", status: "weak", detail: "frame-ancestors * allows any origin to frame the page.", evidence: ev };
  }
  return { name: "CSP frame-ancestors", status: "protected", detail: "frame-ancestors allowlist is set. Confirm every listed origin is trusted.", evidence: ev };
}

function scoreClickjacking(findings) {
  const xfo = findings.filter((f) => f.name === "X-Frame-Options")[0];
  const csp = findings.filter((f) => f.name === "CSP frame-ancestors")[0];
  const xfoOk = xfo && xfo.status === "protected";
  const cspOk = csp && csp.status === "protected";
  const cspWeak = csp && csp.status === "weak";
  if (cspWeak) {
    return ["high", "frame-ancestors is too permissive (e.g. *). Modern browsers honour CSP over X-Frame-Options, so the page can be framed by untrusted origins."];
  }
  if (cspOk) return ["low", "Modern CSP frame-ancestors is in force. Residual risk is low for standard browsers."];
  if (xfoOk) return ["medium", "Only X-Frame-Options protects the page. Add CSP frame-ancestors for modern, consistent coverage."];
  return ["high", "No effective framing protection detected. The page is likely clickjackable."];
}

function gradeClickjackingFromMap(url, status, finalUrl, headers, source) {
  headers = headers || {};
  const findings = [
    (function () {
      try {
        if (new URL(finalUrl || url).protocol === "https:") {
          return { name: "Transport", status: "info", detail: "HTTPS in use. Framing headers must still be set on every sensitive response.", evidence: "" };
        }
      } catch (_) { /* ignore */ }
      return { name: "Transport", status: "weak", detail: "HTTP URL. Headers can be stripped or injected on the network. Prefer HTTPS.", evidence: "" };
    }()),
    assessXfo(headers["x-frame-options"]),
    assessFrameAncestors(headers["content-security-policy"])
  ];
  if (headers["content-security-policy-report-only"]) {
    const d = parseCsp(headers["content-security-policy-report-only"]);
    findings.push({
      name: d["frame-ancestors"] ? "CSP-Report-Only frame-ancestors" : "CSP-Report-Only",
      status: "info",
      detail: d["frame-ancestors"]
        ? "frame-ancestors exists only on Content-Security-Policy-Report-Only and does not block framing."
        : "Report-Only CSP is present but does not enforce framing restrictions.",
      evidence: headers["content-security-policy-report-only"].slice(0, 300)
    });
  }
  findings.push({
    name: "Permissions-Policy",
    status: "info",
    detail: headers["permissions-policy"] || headers["feature-policy"]
      ? "Header present. Useful for feature lockdown, not a clickjacking primary control."
      : "No Permissions-Policy header. Optional extra hardening (not a substitute for frame-ancestors).",
    evidence: (headers["permissions-policy"] || headers["feature-policy"] || "").slice(0, 250)
  });
  const scored = scoreClickjacking(findings);
  return {
    url: url,
    final_url: finalUrl || url,
    status_code: status,
    findings: findings,
    risk: scored[0],
    summary: scored[1],
    headers: interestingHeaders(headers),
    _source: source || "live"
  };
}

/* ---------- Header lookup (Python first, then live relays) -------------- */

function parseRawHeaderDump(text) {
  const headers = {};
  let status = null;
  String(text || "").split(/\r?\n/).forEach((line) => {
    const st = /^HTTP\/\S+\s+(\d+)/i.exec(line);
    if (st) {
      status = parseInt(st[1], 10);
      return;
    }
    const m = /^([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) return;
    const k = m[1].toLowerCase();
    if (k === "set-cookie" && headers[k]) headers[k] += "\n" + m[2];
    else headers[k] = m[2];
  });
  return { status_code: status, headers: headers };
}

function dumpLooksLikeHeaders(parsed) {
  if (!parsed || !parsed.headers) return false;
  const keys = Object.keys(parsed.headers);
  if (!keys.length) return false;
  return keys.some((k) =>
    k === "content-security-policy" || k === "x-frame-options" ||
    k === "strict-transport-security" || k === "x-content-type-options" ||
    k === "content-type" || k === "server" || k === "cache-control" ||
    k === "referrer-policy" || k.indexOf("access-control") === 0
  );
}

async function fetchText(href, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms || 10000);
  try {
    const res = await fetch(href, { signal: ctrl.signal, cache: "no-store" });
    if (!res.ok) return "";
    return await res.text();
  } catch (_) {
    return "";
  } finally {
    clearTimeout(t);
  }
}

async function lookupHeadersLive(url) {
  const encoded = encodeURIComponent(url);
  let host = "";
  try { host = new URL(url).hostname; } catch (_) { /* ignore */ }
  const ht = "https://api.hackertarget.com/httpheaders/?q=";
  const probes = [
    ht + encoded,
    host ? ht + encodeURIComponent(host) : "",
    "https://api.allorigins.win/raw?url=" + encodeURIComponent(ht + url),
    host ? "https://api.allorigins.win/raw?url=" + encodeURIComponent(ht + host) : "",
    "https://corsproxy.io/?url=" + encodeURIComponent(ht + url)
  ].filter(Boolean);

  for (let i = 0; i < probes.length; i++) {
    const text = await fetchText(probes[i], 12000);
    if (!text || /error|rate limit|api count/i.test(text) && text.length < 80) continue;
    let body = text;
    try {
      const json = JSON.parse(text);
      if (json && typeof json.contents === "string") body = json.contents;
    } catch (_) { /* plain text */ }
    const parsed = parseRawHeaderDump(body);
    if (dumpLooksLikeHeaders(parsed)) {
      return { status_code: parsed.status_code, headers: parsed.headers, source: "relay" };
    }
  }

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch(url, { mode: "cors", credentials: "omit", cache: "no-store", signal: ctrl.signal });
    clearTimeout(t);
    const headers = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    if (Object.keys(headers).length) {
      return { status_code: res.status, headers: headers, source: "browser", final_url: res.url || url };
    }
  } catch (_) { /* CORS blocked — expected for most targets */ }

  return null;
}

async function gradeHeadersLive(url) {
  const looked = await lookupHeadersLive(url);
  if (!looked) {
    return {
      url: url, final_url: url, status_code: null,
      checks: [check("request", "error", "Could not read response headers from this hosted page. The Python engine is offline and the live lookup did not return headers.", "", 0)],
      score: 0, grade: "F", risk: "unknown",
      summary: "No header data. Run python3 server.py for a same-origin scan, or retry — the public lookup may be rate-limited.",
      headers: {}, _source: "none"
    };
  }
  return gradeHeadersFromMap(url, looked.status_code, looked.final_url || url, looked.headers, looked.source);
}

async function gradeClickjackingLive(url) {
  const looked = await lookupHeadersLive(url);
  if (!looked) {
    return {
      url: url, final_url: url, status_code: null,
      findings: [{
        name: "Frame test",
        status: "info",
        detail: "Visual proof only. Header values were not available from this host — if the real UI is visible in the frame, treat the page as clickjackable.",
        evidence: ""
      }],
      risk: "unknown",
      summary: "If you can see the real site in the frame, it is clickjackable in this browser.",
      headers: {},
      _source: "browser"
    };
  }
  return gradeClickjackingFromMap(url, looked.status_code, looked.final_url || url, looked.headers, looked.source);
}

async function probeCorsLive(url) {
  const origin = (window.location && window.location.origin) || "null";
  const checks = [];
  let status = null;
  try {
    const res = await fetch(url, { mode: "cors", credentials: "omit", cache: "no-store" });
    status = res.status;
    const acao = res.headers.get("access-control-allow-origin");
    const acac = res.headers.get("access-control-allow-credentials");
    const vary = res.headers.get("vary") || "";
    if (!acao) {
      checks.push(check("Access-Control-Allow-Origin", "ok", "This origin cannot read the response. Restrictive and safe.", "ACAO: (absent)", 0));
    } else if (acao === "*") {
      checks.push(check("Access-Control-Allow-Origin", "info", "Any website can read this resource. Fine only for fully public data.", "ACAO: *", 0));
    } else {
      checks.push(check("Access-Control-Allow-Origin", "info", "This origin is allowed. Confirm it is an intentional allowlist, not a reflection of every caller. A second-origin reflection proof needs the Python engine.", "ACAO: " + acao, 0));
    }
    if (acac && acac.trim().toLowerCase() === "true") {
      checks.push(check("Allow-Credentials", "info", "The server is willing to allow credentials for CORS reads.", "ACAC: " + acac, 0));
    }
    if (acao && acao !== "*" && !/origin/i.test(vary)) {
      checks.push(check("Vary: Origin", "weak", "Origin-specific CORS headers without Vary: Origin. Shared caches may reuse one caller’s policy.", "Vary: " + (vary || "(absent)"), 0));
    } else if (/origin/i.test(vary)) {
      checks.push(check("Vary: Origin", "ok", "Cached responses are partitioned by caller origin.", "Vary: " + vary, 0));
    }
    const weak = checks.some((c) => c.status === "weak");
    return {
      url: url, final_url: res.url || url, status_code: status,
      checks: checks,
      risk: weak ? "medium" : "low",
      summary: "HTTP " + status + " from this browser origin (" + origin + "). Single-origin probe — use server.py for two-origin reflection proof.",
      headers: {},
      origins_tested: [origin],
      _source: "browser"
    };
  } catch (err) {
    checks.push(check("Fetch result", "ok", "The browser blocked the cross-origin read, or the request failed. That usually means this origin is not allowed.", String(err && err.message ? err.message : err), 0));
    return {
      url: url, final_url: url, status_code: null,
      checks: checks,
      risk: "low",
      summary: "This origin cannot read the target.",
      headers: {},
      origins_tested: [origin],
      _source: "browser"
    };
  }
}

/* ---------- Hub suite --------------------------------------------------- */

function initSuite() {
  const input = document.getElementById("suiteUrl");
  const go = document.getElementById("suiteGo");
  const out = document.getElementById("suiteResults");
  if (!input || !go || !out) return;

  async function run() {
    const url = normalizeUrl(input.value);
    if (!url || !validUrl(url)) { input.focus(); return; }
    input.value = url;
    setLoading(go, true);
    out.classList.remove("hidden");
    out.innerHTML = '<div class="suite-grid">' +
      suiteSkeleton("Clickjacking") + suiteSkeleton("Headers") + suiteSkeleton("CORS") +
      "</div>";
    const [cj, hd, cr] = await Promise.all([
      apiScan(url).catch(() => null),
      apiHeaders(url).catch(() => null),
      apiCors(url).catch(() => null)
    ]);
    const base = appBase();
    out.innerHTML = '<div class="suite-grid">' +
      suiteCard("Clickjacking", cj, "findings", base + "/tools/clickjacking/?url=" + encodeURIComponent(url)) +
      suiteCard("Headers", hd, "checks", base + "/tools/headers/?url=" + encodeURIComponent(url)) +
      suiteCard("CORS", cr, "checks", base + "/tools/cors/?url=" + encodeURIComponent(url)) +
      "</div>";
    setLoading(go, false);
  }

  go.addEventListener("click", run);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  const initial = new URLSearchParams(location.search).get("url");
  if (initial) {
    input.value = normalizeUrl(initial);
    run();
  }
}

function suiteSkeleton(title) {
  return '<article class="card suite-card is-loading"><p class="card-title">' + esc(title) +
    '</p><div class="suite-pulse"></div><p class="text-muted">Scanning…</p></article>';
}

function suiteCard(title, data, listKey, href) {
  if (!data) {
    return '<article class="card suite-card"><p class="card-title">' + esc(title) +
      '</p><span class="risk unknown">UNAVAILABLE</span><p class="verdict-text">No result.</p></article>';
  }
  const risk = (data.risk || "unknown").toLowerCase();
  const grade = data.grade ? '<span class="grade ' + gradeFor(data.score) + '">' + esc(data.grade) + "</span>" : "";
  const items = (data[listKey] || []).slice(0, 3).map((c) =>
    '<li><span class="f-status ' + esc(c.status) + '">' + esc(c.status) + "</span> " + esc(c.name) + "</li>"
  ).join("");
  return '<article class="card suite-card">' +
    '<div class="suite-card-top"><p class="card-title">' + esc(title) + '</p>' +
    '<span class="risk ' + esc(risk) + '">' + esc((data.risk || "unknown").toUpperCase()) + "</span></div>" +
    '<div class="suite-card-body">' + grade +
    '<p class="verdict-text">' + esc(data.summary || "") + "</p></div>" +
    (items ? "<ul class=\"suite-list\">" + items + "</ul>" : "") +
    '<p class="suite-src">via ' + esc(sourceLabel(data)) + "</p>" +
    '<a class="tool-card-open" href="' + href + '">Open full report ' + ICONS.chevron + "</a></article>";
}

/* ---------- Tool chrome ------------------------------------------------- */

function setSourceChip(data) {
  const el = document.getElementById("sourceChip");
  if (!el) return;
  el.textContent = "via " + sourceLabel(data);
  el.classList.remove("hidden");
}
