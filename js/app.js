/* ==========================================================================
   CyberBuddy — shared app helpers
   ========================================================================== */
"use strict";

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

// Base path for links: "" when served at the site root (local server,
// preview, custom domain) or "/CyberBuddy" when hosted under that subpath
// (e.g. GitHub Pages). Detected from the URL so both work without config.
function appBase() {
  return window.location.pathname.indexOf("/CyberBuddy/") === 0 ? "/CyberBuddy" : "";
}

// Renders <header class="site-header"> + skip link; call once per page.
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
    '<span class="engine-chip" id="engineChip" title="Scan engine availability"><span class="engine-dot" id="engineDot"></span><span id="engineText">engine · …</span></span>' +
    "</div></header>";
  document.body.insertAdjacentHTML("afterbegin", html);

  // Close any open Tools dropdown on outside click / Escape.
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

// The Tools dropdown — add new tools here and they appear in the header
// and footer. "In development" entries show as disabled items.
const TOOLS_MENU = [
  { href: "/tools/clickjacking/", label: "Clickjacking Validator", status: "live" },
  { href: "/tools/headers/", label: "Security Headers", status: "beta" },
  { href: "/tools/cors/", label: "CORS Validator", status: "beta" }
];
const TOOLS_SOON = ["CSP Policy Auditor", "TLS / SSL Analyzer", "Subdomain Enumeration"];

// uid keeps header/footer dropdown ids unique ("hdr" / "ftr");
// "ftr" renders the panel opening upward so it never clips the page bottom.
function toolsMenu(base, uid) {
  const id = "toolsMenu-" + (uid || "x");
  const up = uid === "ftr" ? " up" : "";
  const path = new URL(window.location.href).pathname;
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
  const path = new URL(window.location.href).pathname;
  const isCurrent = (base + href) === path || (href === "/" && path === base + "/");
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

/* ---------- Engine availability ------------------------------------------- */

// Probe the local scan API (served by server.py). Falls back to a static
// mode when the page is opened from disk or a plain static host.
async function detectEngine() {
  const chip = document.getElementById("engineChip");
  const dot = document.getElementById("engineDot");
  const text = document.getElementById("engineText");
  if (!chip || !dot || !text) return { online: false, reason: "no-chip" };

  const timeout = new Promise((resolve) => setTimeout(() => resolve("timeout"), 3500));
  try {
    const res = await Promise.race([
      fetch("/api/health", { cache: "no-store" }),
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

/* ---------- API ------------------------------------------------------------ */

// Scan a URL for clickjacking / framing protections.
// Returns null when the engine is not reachable (static mode).
async function apiScan(url) {
  try {
    const res = await fetch("/api/scan?" + new URLSearchParams({ url }), { cache: "no-store" });
    if (!res.ok) throw new Error("API " + res.status);
    return await res.json();
  } catch (err) {
    return null;
  }
}

// Scan a URL for security headers. Same engine, extra endpoint.
async function apiHeaders(url) {
  try {
    const res = await fetch("/api/headers?" + new URLSearchParams({ url }), { cache: "no-store" });
    if (!res.ok) throw new Error("API " + res.status);
    return await res.json();
  } catch (err) {
    return null;
  }
}

/* ---------- Small helpers --------------------------------------------------- */

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// Prepend https:// when no scheme is given.
function normalizeUrl(raw) {
  raw = (raw || "").trim();
  if (!raw) return "";
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

// Write ?url=… into the address bar without reloading (shareable links).
function pushUrlParam(url) {
  const next = new URL(window.location.href);
  next.searchParams.set("url", url);
  history.replaceState(null, "", next);
}

// Human-readable timestamp for the report header.
function fmtStamp(d) {
  d = d || new Date();
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

// Loading state for buttons: disables, adds a spinner.
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

// Re-trigger the risk-pill pop animation after a status change.
function bump(el) {
  if (!el) return;
  el.classList.remove("bump");
  void el.offsetWidth;
  el.classList.add("bump");
}

function prefersReduced() {
  return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
}

// Animate a number from 0 to target (e.g. the header score).
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

// Scroll-triggered entrance animation for .reveal elements.
// Fail-safe: everything already on screen is revealed immediately, and a
// timeout force-reveals the rest — content can never stay invisible
// (important inside embedded preview panes where observers can misfire).
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

  // Immediate reveal for everything already on screen.
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

  // Never leave content hidden, whatever the embedding does.
  setTimeout(() => {
    els.forEach((el) => el.classList.add("in"));
  }, 2000);
}

// Open the browser print dialog (Export / Save as PDF for reports).
function exportReport() {
  window.print();
}
