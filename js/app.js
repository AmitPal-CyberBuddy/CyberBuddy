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
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M9 6l6 6-6 6" stroke-linecap="round" stroke-linejoin="round"/></svg>'
};

/* ---------- Shell rendering ---------------------------------------------- */

// Renders <header class="site-header"> + skip link; call once per page.
function renderHeader(current) {
  const host = window.location.hostname;
  const base = host === "127.0.0.1" || host === "localhost" ? "" : "/CyberBuddy";

  const html =
    '<a class="skip-link" href="#main">Skip to content</a>' +
    '<header class="site-header"><div class="container header-inner">' +
    '<a class="brand" href="' + base + '/">' + ICONS.logo + "<span>CyberBuddy</span></a>" +
    '<nav class="main-nav" aria-label="Tools">' +
    navLink(base, "/", "Hub", current) +
    navLink(base, "/tools/clickjacking/", "Clickjacking", current) +
    navLink(base, "/tools/headers/", "Headers", current) +
    navLink(base, "/tools/cors/", "CORS", current) +
    "</nav>" +
    '<span class="engine-chip" id="engineChip" title="Header API availability"><span class="engine-dot" id="engineDot"></span><span id="engineText">engine · …</span></span>' +
    "</div></header>";
  document.body.insertAdjacentHTML("afterbegin", html);
}

function navLink(base, href, label, current) {
  const isCurrent = (base + href) === new URL(window.location.href).pathname ||
                    (href === "/" && new URL(window.location.href).pathname === base + "/");
  const a = '<a href="' + base + href + '"' + (isCurrent ? ' aria-current="page"' : "") + ">" + label + "</a>";
  return a;
}

function renderFooter() {
  const html =
    '<footer class="site-footer"><div class="container footer-inner">' +
    '<div class="footer-brand brand"><span class="brand-mark">' + ICONS.logo + "</span>CyberBuddy</div>" +
    '<nav class="footer-nav" aria-label="Footer">' +
    '<a href="/CyberBuddy/">Hub</a>' +
    '<a href="/CyberBuddy/tools/clickjacking/">Clickjacking Validator</a>' +
    '<a href="/CyberBuddy/tools/headers/">Security Headers</a>' +
    '<a href="/CyberBuddy/tools/cors/">CORS Validator</a>' +
    "</nav>" +
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
// "frame only" mode when the page is opened from disk or a plain static host.
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
    chip.title = ok ? "Local scan engine online — full header checks enabled" : "Scan engine unreachable";
    dot.classList.toggle("on", ok);
    text.textContent = ok ? "engine · online" : "engine · offline";
    return { online: ok, reason: ok ? "online" : "offline" };
  } catch (_) {
    chip.title = "Local scan engine not running — static (frame-only) mode";
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

function setLoading(btn, loading) {
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = loading ? "Scanning…" : (btn.dataset.label || "Scan");
}

// Format a numeric grade A–F from 0–100 (for the headers page).
function gradeFor(score) {
  if (score >= 90) return "a";
  if (score >= 70) return "b";
  if (score >= 50) return "c";
  if (score >= 30) return "d";
  return "f";
}
