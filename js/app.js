/* ==========================================================================
   CyberBuddy — shared app helpers
   ========================================================================== */
"use strict";

// Mark JS as available so .reveal stays visible if this file never loads.
document.documentElement.classList.add("js");

/* ---------- Icon set (inline SVG, currentColor) ------------------------- */
const ICONS = {
  logo: '<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><rect x="2" y="2" width="28" height="28" rx="4" stroke="currentColor" stroke-width="2.4"/><path d="M8 16h4l3-7 6 14 3-7h4" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  frame: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M15 3v18" stroke-dasharray="3 3"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
  cors: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="5.5" cy="12" r="2.5"/><circle cx="18.5" cy="12" r="2.5"/><path d="M8 12h3M13 12h3" stroke-dasharray="2 2"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 5v14M5 12h14" stroke-linecap="round"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M9 6l6 6-6 6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  linkedin: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>'
};

/* ---------- Shell rendering ---------------------------------------------- */

function appBase() {
  const scripts = document.getElementsByTagName("script");
  for (let i = 0; i < scripts.length; i++) {
    const src = scripts[i].src || "";
    const idx = src.indexOf("/js/app.js");
    if (idx === -1) continue;
    try {
      let base = new URL(src).pathname.slice(0, idx);
      if (base === "/") base = "";
      return base;
    } catch (_) { /* ignore bad src */ }
  }
  const path = window.location.pathname || "";
  const m = path.match(/^(\/CyberBuddy)(?=\/|$)/i);
  return m ? m[1] : "";
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
    "</div></header>";
  document.body.insertAdjacentHTML("afterbegin", html);

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
    "you are responsible for having permission to test them. No data is uploaded anywhere — " +
    "all scans run from your browser or your local server. © 2026 CyberBuddy." +
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
  if (count) {
    count.textContent = String(live).padStart(2, "0") + " live";
  }
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
  const soonTags = TOOLS_SOON.map((s) => {
    const short = s.split(" ")[0];
    return '<span class="tool-tag">' + esc(short) + "</span>";
  }).join("");
  const ghost =
    '<div class="tool-card card tool-card--ghost reveal" style="--d: .26s">' +
    '<div class="tool-card-top"><span class="tool-card-icon">' + ICONS.plus +
    '</span><span class="status-led soon">soon</span></div>' +
    "<div><h3>More tools coming soon</h3>" +
    '<p class="tool-card-desc">' + esc(TOOLS_SOON.join(", ")) +
    " and more are on the bench — this slot is reserved for the next check to ship.</p></div>" +
    '<div class="tool-card-tags">' + soonTags + "</div></div>";
  grid.innerHTML = cards + ghost;
}

async function detectEngine() {
  const chip = document.getElementById("engineChip");
  const dot = document.getElementById("engineDot");
  const text = document.getElementById("engineText");
  if (!chip || !dot || !text) return { online: false, reason: "no-chip" };

  const timeout = new Promise((resolve) => setTimeout(() => resolve("timeout"), 3500));
  try {
    const res = await Promise.race([
      fetch(apiUrl("/api/health"), apiHeadersInit()),
      timeout
    ]);
    if (res === "timeout" || !res.ok) throw new Error("unreachable");
    const data = await res.json();
    const ok = data && data.ok === true;
    chip.title = ok ? "Scan engine online — full header checks enabled" : "Scan engine unreachable";
    dot.classList.toggle("on", ok);
    text.textContent = ok ? "engine · online" : "engine · offline";
    return { online: ok, reason: ok ? "online" : "offline" };
  } catch (_) {
    chip.title = "Scan engine not running — static mode";
    dot.classList.remove("on");
    text.textContent = "engine · static";
    return { online: false, reason: "static" };
  }
}

async function apiCall(path, url) {
  try {
    const res = await fetch(apiUrl(path) + "?" + new URLSearchParams({ url }), apiHeadersInit());
    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    if (!res.ok) {
      return { error: (data && data.error) || ("API " + res.status), status: res.status };
    }
    return data;
  } catch (err) {
    return null;
  }
}

function apiScan(url) { return apiCall("/api/scan", url); }
function apiHeaders(url) { return apiCall("/api/headers", url); }
function apiCors(url) { return apiCall("/api/cors", url); }

function isEngineDown(data) {
  return data == null;
}

function apiErrorMessage(data) {
  if (!data) return "";
  if (data.error) return String(data.error);
  if (data.summary && data.risk === "unknown") return String(data.summary);
  return "";
}

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

  setTimeout(() => {
    els.forEach((el) => el.classList.add("in"));
  }, 2000);
}

function exportReport() {
  window.print();
}
