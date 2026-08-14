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
  frame: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><path class="dashed" d="M9 3v18M15 3v18" stroke-dasharray="3 3"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
  cors: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="5.5" cy="12" r="2.5"/><circle cx="18.5" cy="12" r="2.5"/><path class="dashed" d="M8 12h3M13 12h3" stroke-dasharray="2 2"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 5v14M5 12h14" stroke-linecap="round"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M9 6l6 6-6 6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>',
  arrowUp: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 19V5M5 12l7-7 7 7"/></svg>',
  linkedin: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>',
  medium: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M6.7 8.4a1 1 0 0 0-.33-.85L4.3 5.1V4.7h5.2l4 8.9 3.55-8.9H22v.4l-1.6 1.55a.5.5 0 0 0-.2.47v11.76a.5.5 0 0 0 .2.47l1.55 1.52v.4h-7.8v-.4l1.6-1.56a.5.5 0 0 0 .2-.47V8.2L11.2 18.9h-.55l-5-10.7v7.2a.7.7 0 0 0 .2.55l2.1 2.56v.4H2.6v-.4l2.1-2.56a.7.7 0 0 0 .2-.55l.03-7.2a.5.5 0 0 0-.23-.4z"/></svg>',
  github: '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.342-3.369-1.342-.454-1.155-1.11-1.462-1.11-1.462-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.161 22 16.418 22 12c0-5.523-4.477-10-10-10z"/></svg>'
};

/* ---------- Site root + optional hosted API ------------------------------ */

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
  const fromDir = path.match(/^(.*)\/(?:tools\/[^/]+|methodology)\/?$/);
  if (fromDir) return fromDir[1];
  const known = path.match(/^(\/CyberBuddy)(?=\/|$)/i);
  return known ? known[1] : "";
}

// Set this to the base URL of a hosted deployment of api/ (e.g.
// "https://cyberbuddy-api.vercel.app") to run scans with the real
// Python engine from the GitHub Pages site instead of live relays.
const API_BASE = "";

function pagePath() {
  return (window.location.pathname || "").replace(/\/index\.html$/, "/") || "/";
}

function apiUrl(path) {
  return (API_BASE || appBase()) + path;
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
  document.querySelectorAll('meta[name="theme-color"]').forEach((meta) => {
    meta.setAttribute("content", theme === "light" ? "#eef2f7" : "#07090d");
  });
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
  const btn = document.getElementById("themeToggle");
  applyTheme(currentTheme(), false);
  if (!btn) return;
  btn.addEventListener("click", () => {
    const next = currentTheme() === "light" ? "dark" : "light";
    applyTheme(next, true);
    // spin the icon as feedback (respect reduced motion via CSS)
    btn.classList.remove("spin");
    void btn.offsetWidth;
    btn.classList.add("spin");
  });
  // Follow OS preference when the user has not explicitly chosen a theme
  if (window.matchMedia) {
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    mq.addEventListener("change", (e) => {
      try {
        if (!localStorage.getItem(THEME_KEY)) {
          applyTheme(e.matches ? "light" : "dark", false);
        }
      } catch (_) { applyTheme(e.matches ? "light" : "dark", false); }
    });
  }
}

/* ---------- Scroll chrome (header state + back-to-top) ------------------ */

function initScrollChrome() {
  const header = document.querySelector(".site-header");
  const toTop = document.getElementById("toTop");
  const progress = document.getElementById("scrollProgress");
  if (!header && !toTop && !progress) return;
  let ticking = false;
  const onScroll = () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const y = window.scrollY || 0;
      if (header) header.classList.toggle("scrolled", y > 24);
      if (toTop) toTop.classList.toggle("show", y > 640);
      if (progress) {
        const max = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
        progress.style.width = Math.min(100, (y / max) * 100) + "%";
      }
      ticking = false;
    });
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  if (toTop) {
    toTop.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: prefersReduced() ? "auto" : "smooth" });
    });
  }
  onScroll();
}

/* ---------- Shell ------------------------------------------------------- */

function renderHeader(current) {
  const base = appBase();
  const html =
    '<div class="page-load-bar" aria-hidden="true"></div>' +
    '<div class="scroll-progress" id="scrollProgress" aria-hidden="true"></div>' +
    '<div class="aurora" aria-hidden="true"><i></i><i></i><i></i></div>' +
    '<div class="ambient" aria-hidden="true"></div>' +
    '<a class="skip-link" href="#main">Skip to content</a>' +
    '<header class="site-header"><div class="container header-inner">' +
    '<a class="brand" href="' + base + '/">' +
    '<span class="brand-mark">' + ICONS.logo + "</span><span>CyberBuddy</span></a>" +
    '<nav class="main-nav" aria-label="Tools">' +
    navLink(base, "/", "Hub", current) +
    navLink(base, "/#methodology", "Method", current) +
    toolsMenu(base, "hdr") +
    "</nav>" +
    '<button type="button" id="themeToggle" class="theme-toggle" aria-label="Switch theme" title="Switch theme">' +
    ICONS.sun + "</button>" +
    '<span class="engine-chip" id="engineChip" title="Checking scan engine…">' +
    '<span class="engine-dot" id="engineDot"></span>' +
    '<span id="engineText">engine · …</span></span>' +
    "</div></header>" +
    '<button type="button" id="toTop" class="to-top" aria-label="Back to top" title="Back to top">' +
    ICONS.arrowUp + "</button>";
  document.body.insertAdjacentHTML("afterbegin", html);
  // Keep the promise: the relay-consent gate must not prompt while engine
  // detection is still in flight (a local server.py means no relay is ever
  // reached, so there is nothing to consent to).
  window.__cbEngineReady = detectEngine();
  initAmbient();
  initThemeToggle();
  initScrollChrome();
  initKeyboard();

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
    tags: ["X-Frame-Options", "frame-ancestors", "iframe PoC", "WSTG-CLNT-09"]
  },
  {
    href: "/tools/headers/",
    label: "Security Headers",
    status: "live",
    icon: "shield",
    desc: "Grade CSP, X-Frame-Options, HSTS, cookie flags and the COOP/COEP family into an A–F score with the raw header behind every finding.",
    tags: ["CSP", "HSTS", "COOP/COEP", "grade A–F", "WSTG-CONF-07/12"]
  },
  {
    href: "/tools/cors/",
    label: "CORS Validator",
    status: "live",
    icon: "cors",
    desc: "See how the target treats this page as a cross-origin caller — origin access, credentials, and Vary: Origin.",
    tags: ["ACAO", "credentials", "Vary: Origin", "WSTG-CLNT-07"]
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
    '<a href="' + base + '/#methodology">Methodology</a>' +
    toolsMenu(base, "ftr") +
    "</nav>" +
    '<div class="footer-contact">' +
    "<strong>Connect</strong>" +
    "<span>Ideas, feedback, or collaboration on improving CyberBuddy?</span>" +
    '<a href="mailto:amitpal.secure@gmail.com">amitpal.secure@gmail.com</a>' +
    '<a class="social-link" href="https://github.com/AmitPal-CyberBuddy/CyberBuddy" target="_blank" rel="noopener noreferrer">' +
    ICONS.github + "Source on GitHub</a>" +
    '<a class="social-link" href="https://www.linkedin.com/in/amitpal-wb/" target="_blank" rel="noopener noreferrer">' +
    ICONS.linkedin + "Connect on LinkedIn</a>" +
    '<a class="social-link" href="https://amitpxl.medium.com/" target="_blank" rel="noopener noreferrer">' +
    ICONS.medium + "Read the blog · Medium</a>" +
    "</div>" +
    '<p class="footer-legal">' +
    "Authorized testing only. CyberBuddy performs read-only checks against URLs you provide; " +
    "you are responsible for having permission to test them. Scan history stays in your browser " +
    "and is never uploaded. On GitHub Pages the graders run in your browser; demo targets are " +
    "served from a published CI-built report, and header reads for other targets are proxied by " +
    "public relays only with your explicit consent. Run server.py locally for a same-origin " +
    "engine that never leaves your machine. Apache-2.0 licensed. © 2026 CyberBuddy." +
    "</p>" +
    "</div></footer>";
  document.body.insertAdjacentHTML("beforeend", html);
}

/* ---------- Blog (data-driven) ------------------------------------------ */
/* Add a post to BLOG_POSTS and it appears in the hub's "From the blog" grid —
   no HTML edits needed as new write-ups publish. */

const BLOG_POSTS = [
  {
    href: "https://amitpxl.medium.com/http-request-smuggling-vs-http-request-pipelining-why-theyre-often-confused-44ffe6e528eb",
    badge: "Newest",
    tags: ["HTTP", "Smuggling", "Burp"],
    title: "HTTP Request Smuggling vs HTTP Request Pipelining: Why They're Often Confused",
    excerpt: "Stop screenshotting every double response in Burp Repeater. I walk through how I separate harmless pipelining from actual queue poisoning.",
    date: "Jun 19, 2026"
  },
  {
    href: "https://amitpxl.medium.com/how-i-broke-encrypted-requests-by-reading-frontend-javascript-b016c5b9078d",
    tags: ["Client-side", "Crypto", "JS analysis"],
    title: "How I Broke Client-Side Encryption By Frontend JavaScript Analysis",
    excerpt: "A walkthrough of finding hardcoded AES keys in frontend JavaScript and decrypting protected API traffic outside the browser.",
    date: "May 27, 2026"
  }
];

function renderBlog() {
  const grid = document.getElementById("blogGrid");
  if (!grid) return;
  const readIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M9 6l6 6-6 6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  grid.innerHTML = BLOG_POSTS.map((p, i) => {
    const badge = p.badge ? '<span class="blog-badge">' + esc(p.badge) + "</span>" : "";
    const tags = (p.tags || []).map((t) => '<span class="tool-tag">' + esc(t) + "</span>").join("");
    return '<a class="blog-post reveal" style="--d: ' + (0.12 + i * 0.07) + 's" href="' + esc(p.href) +
      '" target="_blank" rel="noopener noreferrer">' +
      '<div class="blog-post-tags">' + badge + tags + "</div>" +
      "<h3>" + esc(p.title) + "</h3>" +
      '<p class="blog-excerpt">' + esc(p.excerpt) + "</p>" +
      '<div class="blog-post-foot">' +
      '<span class="blog-date">' + esc(p.date) + "</span>" +
      '<span class="blog-open">Read on Medium ' + readIcon + "</span>" +
      "</div></a>";
  }).join("");
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
  // Be specific about the trust level rather than a vague "live". A security
  // audience needs to know the grading is client-side and that reading
  // headers may involve a relay they have to approve.
  chip.title =
    "No Python engine detected. Graders run in this browser; reading " +
    "cross-origin headers needs your consent to use a public relay. " +
    "Run server.py locally for a same-origin scan.";
  chip.classList.add("is-live");
  dot.classList.add("on", "live");
  text.textContent = "browser · no engine";
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
  // status_code != null means the engine actually reached the target —
  // error payloads (unreachable target) are handled by isUnreachable below.
  if (kind === "headers") return data.status_code != null && Array.isArray(data.checks) && data.grade;
  if (kind === "scan") return data.status_code != null && Array.isArray(data.findings);
  if (kind === "cors") return data.status_code != null && Array.isArray(data.checks);
  return false;
}

// A live engine (Python) that answered us but could not reach the *target*
// returns status_code: null plus a "request" check in status "error"
// (DNS failure, connection refused, or a timeout). That is a genuinely
// different outcome from "no engine / relay blocked" — surface it as
// "target not reachable" instead of silently falling through to a relay
// that cannot tell the difference either.
function isUnreachable(data, listKey) {
  if (!data || data.status_code != null) return false;
  const list = data[listKey];
  if (!Array.isArray(list) || !list.length) return false;
  const err = list.find((c) => c && c.status === "error");
  if (!err) return false;
  // A policy refusal ("blocked scan target: …") is a guard, not a dead host.
  return !/blocked scan target/i.test(err.detail || "");
}

function markUnreachable(data, source) {
  data._source = source || data._source || "python";
  data._unreachable = true;
  return data;
}

// Human-readable reason for an unreachable target, from the engine's own
// error text (e.g. "Request failed: <urlopen error timed out>").
function unreachableDetail(data) {
  const list = (data && (data.checks || data.findings)) || [];
  const err = list.find((c) => c && c.status === "error");
  return (err && err.detail) || (data && data.summary) || "No response received.";
}

async function apiScan(url) {
  const local = await apiCall("/api/scan", url);
  if (isUsableScan(local, "scan")) {
    local._source = "python";
    return local;
  }
  if (isUnreachable(local, "findings")) return markUnreachable(local, "python");
  const cached = await cachedReportFor(url);
  if (cached && cached.clickjacking && cached.clickjacking.status_code != null &&
      isUsableScan(cached.clickjacking, "scan")) {
    cached.clickjacking._source = "cache";
    cached.clickjacking._cached_at = cached.generated_at || "";
    return cached.clickjacking;
  }
  return gradeClickjackingLive(url);
}

async function apiHeaders(url) {
  const local = await apiCall("/api/headers", url);
  if (isUsableScan(local, "headers")) {
    local._source = "python";
    return local;
  }
  if (isUnreachable(local, "checks")) return markUnreachable(local, "python");
  const cached = await cachedReportFor(url);
  if (cached && cached.headers && cached.headers.status_code != null &&
      isUsableScan(cached.headers, "headers")) {
    cached.headers._source = "cache";
    cached.headers._cached_at = cached.generated_at || "";
    return cached.headers;
  }
  return gradeHeadersLive(url);
}

async function apiCors(url) {
  const local = await apiCall("/api/cors", url);
  if (isUsableScan(local, "cors")) {
    local._source = "python";
    return local;
  }
  if (isUnreachable(local, "checks")) return markUnreachable(local, "python");
  const cached = await cachedReportFor(url);
  if (cached && cached.cors && cached.cors.status_code != null &&
      isUsableScan(cached.cors, "cors")) {
    cached.cors._source = "cache";
    cached.cors._cached_at = cached.generated_at || "";
    return cached.cors;
  }
  return probeCorsLive(url);
}

/* ---------- Cached reports (pre-scanned reports served by Pages) ------- */
/* When enabled (see README), tools/build_cache.py pre-scans the URLs in
   urls.txt with the real Python engines and writes cache/<host>.json into
   the site. Pages serves those same-origin, so configured targets get
   full-strength results (two-origin CORS proof, server-side header reads,
   metadata blocking) with no third-party relays. If the file is absent,
   scans fall through to the live engines. */

const CACHE_MAX_AGE_MS = 48 * 60 * 60 * 1000; // prefer cache fresher than 48h

function cacheLookupKeys(url) {
  const keys = [];
  const add = (u) => { if (u && keys.indexOf(u) === -1) keys.push(u); };
  add(url);
  try {
    const u = new URL(url);
    const path = u.pathname || "/";
    const trimmed = path !== "/" ? path.replace(/\/+$/, "") : "/";
    const withSlash = trimmed === "/" ? "/" : trimmed + "/";
    add(u.origin + trimmed + u.search);
    add(u.origin + withSlash + u.search);
    add(u.origin);
    add(u.origin + "/");
  } catch (_) { /* ignore */ }
  return keys;
}

async function cachedReportFor(url) {
  let host = "";
  try { host = new URL(url).hostname; } catch (_) { return null; }
  let data = null;
  try {
    // Cached reports live on the Pages origin (GitHub Actions publishes them
    // into the site), so always use appBase() — never API_BASE.
    // Leading slash is required: appBase() is "/CyberBuddy" on Pages, "" locally.
    const res = await fetch(appBase() + "/cache/" + encodeURIComponent(host) + ".json", { cache: "no-store" });
    if (!res.ok) return null;
    data = await res.json();
  } catch (_) { return null; }
  const urls = (data && data.urls) ? data.urls : {};
  let entry = null;
  const keys = cacheLookupKeys(url);
  for (let i = 0; i < keys.length; i++) {
    if (urls[keys[i]]) { entry = urls[keys[i]]; break; }
  }
  if (!entry) return null;
  // Only accept entries where at least one engine actually reached the
  // target (a full network failure means the cache job could not scan it),
  // and skip ancient reports.
  const reachable = [entry.clickjacking, entry.headers, entry.cors]
    .some((r) => r && r.status_code != null);
  if (!reachable) return null;
  const at = new Date(entry.generated_at || 0).getTime();
  if (!at || (Date.now() - at) > CACHE_MAX_AGE_MS) return null;
  return entry;
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
  // "published report" — a pre-scanned demo target from urls.txt, built in
  // CI and served to everyone. NOT another user's scan of your target.
  if (s === "cache") return "published report";
  if (s === "relay") return "third-party relay";
  if (s === "cache-lookup") return "this browser (cached 10 min)";
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

/* Reports get an unambiguous UTC stamp — a screenshot pasted into an
   assessment should not depend on the reader guessing the tester's zone. */
function fmtStampUtc(d) {
  d = d || new Date();
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/* ---------- Report provenance ------------------------------------------
   Burned into the report card so a cropped screenshot still identifies the
   tool, target, engine and time. */

function renderProvenance(data, toolName) {
  const el = document.getElementById("reportProvenance");
  if (!el) return;
  const bits = [
    '<span class="prov-brand">CyberBuddy · ' + esc(toolName) + "</span>",
    '<span class="prov-sep">|</span>',
    "<span>" + esc((data && data.url) || "—") + "</span>",
    '<span class="prov-sep">|</span>',
    "<span>" + esc(fmtStampUtc()) + "</span>",
    '<span class="prov-sep">|</span>',
    "<span>source: " + esc(sourceLabel(data)) + "</span>"
  ];
  if (data && data.confirmation === "manual") {
    bits.push('<span class="prov-sep">|</span>',
      '<span class="prov-manual">analyst-attested</span>');
  }
  if (isUnverified(data)) {
    bits.push('<span class="prov-sep">|</span>',
      '<span class="prov-manual">unverified relay data</span>');
  }
  el.innerHTML = bits.join(" ");
}

/* ---------- Evidence mode ----------------------------------------------
   Collapses the page chrome after a scan so the whole report card fits one
   viewport and a snipping-tool capture gets everything in one shot. */

const EVIDENCE_KEY = "cb-evidence-mode";

function evidenceEnabled() {
  try { return localStorage.getItem(EVIDENCE_KEY) !== "0"; } catch (_) { return true; }
}

function applyEvidenceMode(on) {
  document.body.classList.toggle("evidence", !!on);
}

function enterEvidenceMode() {
  if (!evidenceEnabled()) return;
  applyEvidenceMode(true);
  const results = document.getElementById("results");
  if (results && !prefersReduced() && typeof results.scrollIntoView === "function") {
    requestAnimationFrame(() => {
      try {
        results.scrollIntoView({ block: "start", behavior: "smooth" });
      } catch (_) { /* older engines: ignore */ }
    });
  }
}

function initEvidenceToggle() {
  const wrap = document.getElementById("evidenceToggle");
  if (!wrap) return;
  wrap.innerHTML =
    '<label class="evidence-toggle">' +
    '<input type="checkbox" id="evidenceChk"' + (evidenceEnabled() ? " checked" : "") + " /> " +
    "Evidence mode — collapse page chrome after a scan so the report fits one screenshot" +
    "</label>";
  const chk = document.getElementById("evidenceChk");
  chk.addEventListener("change", () => {
    try { localStorage.setItem(EVIDENCE_KEY, chk.checked ? "1" : "0"); } catch (_) { /* ignore */ }
    const hasResults = document.getElementById("results") &&
      !document.getElementById("results").classList.contains("hidden");
    applyEvidenceMode(chk.checked && hasResults);
  });
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

function initStats() {
  const els = Array.prototype.slice.call(document.querySelectorAll("[data-count]"));
  if (!els.length) return;
  const pad = (n, w) => String(n).padStart(w || 0, "0");
  const run = (el) => {
    const target = parseInt(el.getAttribute("data-count") || "0", 10);
    const suffix = el.getAttribute("data-suffix") || "";
    const width = parseInt(el.getAttribute("data-pad") || "0", 10);
    if (prefersReduced() || !("requestAnimationFrame" in window)) {
      el.textContent = pad(target, width) + suffix;
      return;
    }
    const t0 = performance.now();
    const dur = 900;
    (function frame(t) {
      const p = Math.min(1, (t - t0) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = pad(Math.round(target * eased), width) + suffix;
      if (p < 1) requestAnimationFrame(frame);
    })(t0);
  };
  if (!("IntersectionObserver" in window)) {
    els.forEach(run);
    return;
  }
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        run(e.target);
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.4 });
  els.forEach((el) => io.observe(el));
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

/* ==========================================================================
   Export menu — print, PoC image, evidence card, clipboard
   ========================================================================== */

/* Screen capture is the ONLY way to get the framed target into an image:
   a cross-origin iframe cannot be rasterised (html2canvas explicitly does
   not render iframes, and any canvas touching cross-origin pixels is
   tainted, so toDataURL throws). getDisplayMedia captures real screen
   pixels, so the frame is included. Desktop Chrome/Edge can share a single
   tab; Firefox/Safari offer window or screen only; iOS has no support. */
function canCapturePoc() {
  return !!(navigator.mediaDevices &&
    typeof navigator.mediaDevices.getDisplayMedia === "function" &&
    window.isSecureContext);
}

function downloadBlob(blob, filename) {
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 4000);
}

function safeSlug(url) {
  try {
    return (new URL(url).hostname || "target").replace(/[^a-z0-9.-]/gi, "-");
  } catch (_) {
    return "target";
  }
}

function stampName(prefix, url, ext) {
  const t = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
  return prefix + "-" + safeSlug(url) + "-" + t + "." + ext;
}

async function downloadPocImage(data, btn) {
  if (!canCapturePoc()) return false;
  let stream = null;
  try {
    stream = await navigator.mediaDevices.getDisplayMedia({
      video: { displaySurface: "browser" },
      audio: false,
      preferCurrentTab: true,
      selfBrowserSurface: "include"
    });
    const track = stream.getVideoTracks()[0];
    // Give the compositor a frame to settle before grabbing.
    await new Promise((r) => setTimeout(r, 350));

    const settings = track.getSettings();
    const width = settings.width || 1280;
    const height = settings.height || 720;

    const video = document.createElement("video");
    video.srcObject = stream;
    video.muted = true;
    await video.play();
    await new Promise((r) => setTimeout(r, 220));

    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    canvas.getContext("2d").drawImage(video, 0, 0, width, height);
    video.pause();
    video.srcObject = null;

    const blob = await new Promise((r) => canvas.toBlob(r, "image/png"));
    if (!blob) throw new Error("encode failed");
    downloadBlob(blob, stampName("cyberbuddy-poc", (data && data.url) || "", "png"));
    if (btn) flashBtn(btn, true, "PoC image saved ✓");
    return true;
  } catch (err) {
    if (btn) flashBtn(btn, false, "Capture cancelled");
    return false;
  } finally {
    if (stream) stream.getTracks().forEach((t) => t.stop());
  }
}

/* Deterministic, dependency-free evidence card drawn from the scan JSON.
   Same-origin canvas only, so it never taints and always downloads — the
   trade-off is that it cannot show the live framed site. */
function buildEvidenceCard(data, toolName) {
  const W = 1200;
  const pad = 48;
  const rows = (data.checks || data.findings || []);
  const lineH = 21;

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  const mono = '13px "IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace';

  // Measure first so the canvas is exactly tall enough.
  ctx.font = mono;
  const wrapText = (text, maxW) => {
    const words = String(text || "").split(/\s+/);
    const out = [];
    let line = "";
    words.forEach((w) => {
      const t = line ? line + " " + w : w;
      if (ctx.measureText(t).width > maxW && line) {
        out.push(line);
        line = w;
      } else {
        line = t;
      }
    });
    if (line) out.push(line);
    return out;
  };

  const measured = rows.map((c) => ({
    row: c,
    detail: wrapText(c.detail, W - pad * 2 - 200),
    evidence: c.evidence ? wrapText(c.evidence, W - pad * 2 - 200).slice(0, 3) : []
  }));
  const bodyH = measured.reduce(
    (n, m) => n + lineH * (1 + m.detail.length + m.evidence.length) + 14, 0
  );
  const H = 300 + bodyH + 70;
  canvas.width = W;
  canvas.height = H;

  const C = {
    bg: "#07090d", card: "#0e121a", line: "#232a36", ink: "#eef3f8",
    ink2: "#c5ced8", faint: "#7d8798", brand: "#3ee0c2",
    high: "#ff6b7a", med: "#ffc857", low: "#3ee0a6", info: "#7aa2ff"
  };
  const statusColour = (s) => ({
    ok: C.low, protected: C.low, missing: C.high, error: C.high,
    weak: C.med, info: C.info
  }[s] || C.faint);

  ctx.fillStyle = C.bg;
  ctx.fillRect(0, 0, W, H);
  ctx.fillStyle = C.card;
  ctx.fillRect(pad - 18, pad - 18, W - (pad - 18) * 2, H - (pad - 18) * 2);
  ctx.strokeStyle = C.line;
  ctx.strokeRect(pad - 18, pad - 18, W - (pad - 18) * 2, H - (pad - 18) * 2);

  let y = pad + 12;
  ctx.fillStyle = C.brand;
  ctx.font = '600 13px "IBM Plex Mono", ui-monospace, monospace';
  ctx.fillText("CYBERBUDDY · " + toolName.toUpperCase(), pad, y);
  y += 34;

  ctx.fillStyle = C.ink;
  ctx.font = '700 26px "Sora", system-ui, sans-serif';
  const risk = (data.risk || "unknown").toUpperCase();
  const gradeTxt = data.grade ? "  ·  Grade " + data.grade.toUpperCase() +
    " (" + (data.score != null ? data.score : "?") + "/100)" : "";
  ctx.fillText(risk + gradeTxt, pad, y);
  ctx.fillStyle = risk === "HIGH" ? C.high : risk === "MEDIUM" ? C.med
    : risk === "LOW" ? C.low : C.info;
  ctx.fillRect(pad, y + 10, ctx.measureText(risk + gradeTxt).width, 3);
  y += 40;

  ctx.font = mono;
  const meta = [
    ["Target", data.url || "—"],
    ["Final URL", data.final_url || data.url || "—"],
    ["HTTP status", data.status_code != null ? String(data.status_code) : "—"],
    ["Generated", fmtStampUtc()],
    ["Source", sourceLabel(data)]
  ];
  if (data.confirmation === "manual") meta.push(["Confirmation", "analyst-attested (visual)"]);
  if (isUnverified(data)) meta.push(["Caveat", "relay data — not independently verified"]);
  meta.forEach(([k, v]) => {
    ctx.fillStyle = C.faint;
    ctx.fillText(k, pad, y);
    ctx.fillStyle = C.ink2;
    ctx.fillText(String(v).slice(0, 110), pad + 130, y);
    y += lineH;
  });

  y += 12;
  ctx.strokeStyle = C.line;
  ctx.beginPath();
  ctx.moveTo(pad, y);
  ctx.lineTo(W - pad, y);
  ctx.stroke();
  y += 26;

  if (data.summary) {
    ctx.fillStyle = C.ink2;
    wrapText(data.summary, W - pad * 2).slice(0, 3).forEach((l) => {
      ctx.fillText(l, pad, y);
      y += lineH;
    });
    y += 14;
  }

  measured.forEach((m) => {
    const s = m.row.status || "info";
    ctx.fillStyle = statusColour(s);
    ctx.font = '700 11px "IBM Plex Mono", ui-monospace, monospace';
    ctx.fillText(s.toUpperCase(), pad, y);
    ctx.fillStyle = C.ink;
    ctx.font = '600 13px "IBM Plex Mono", ui-monospace, monospace';
    ctx.fillText(String(m.row.name || ""), pad + 96, y);
    y += lineH;
    ctx.font = mono;
    ctx.fillStyle = C.ink2;
    m.detail.forEach((l) => { ctx.fillText(l, pad + 96, y); y += lineH; });
    ctx.fillStyle = C.faint;
    m.evidence.forEach((l) => { ctx.fillText(l, pad + 96, y); y += lineH; });
    y += 14;
  });

  ctx.fillStyle = C.faint;
  ctx.font = '11px "IBM Plex Mono", ui-monospace, monospace';
  ctx.fillText("Authorized testing only. Read-only GET. Results are advisory.", pad, H - pad + 6);

  return canvas;
}

async function downloadEvidenceCard(data, toolName, btn) {
  if (!data) return false;
  try {
    const canvas = buildEvidenceCard(data, toolName);
    const blob = await new Promise((r) => canvas.toBlob(r, "image/png"));
    if (!blob) throw new Error("encode failed");
    downloadBlob(blob, stampName("cyberbuddy-evidence", data.url || "", "png"));
    if (btn) flashBtn(btn, true, "Card saved ✓");
    return true;
  } catch (_) {
    if (btn) flashBtn(btn, false, "");
    return false;
  }
}

/* Renders the split Export control into #exportMenu. getData() returns the
   last scan result so the menu always acts on current data. */
function initExportMenu(toolName, getData) {
  const wrap = document.getElementById("exportMenu");
  if (!wrap) return;
  const capture = canCapturePoc();
  wrap.innerHTML =
    '<details class="export-menu" id="exportDetails">' +
    '<summary aria-haspopup="menu">Export ' + ICONS.chevron + "</summary>" +
    '<div class="export-menu-panel" role="menu">' +
    '<button type="button" class="export-menu-item" role="menuitem" data-act="print">' +
    "Print / Save as PDF<span>Full report card, paper layout</span></button>" +
    '<button type="button" class="export-menu-item" role="menuitem" data-act="poc"' +
    (capture ? "" : " disabled") + ">" +
    "Download PoC image (PNG)<span>" +
    (capture
      ? "Screen capture — includes the framed target"
      : "Unavailable in this browser — use your OS snipping tool") +
    "</span></button>" +
    '<button type="button" class="export-menu-item" role="menuitem" data-act="card">' +
    "Download evidence card (PNG)<span>Drawn from scan data — no live frame</span></button>" +
    '<div class="export-menu-divider"></div>' +
    '<button type="button" class="export-menu-item" role="menuitem" data-act="md">' +
    "Copy report (Markdown)<span>Paste into your report</span></button>" +
    '<button type="button" class="export-menu-item" role="menuitem" data-act="json">' +
    "Copy JSON<span>Raw result object</span></button>" +
    "</div></details>";

  const details = document.getElementById("exportDetails");
  wrap.querySelectorAll("[data-act]").forEach((item) => {
    item.addEventListener("click", async () => {
      const act = item.getAttribute("data-act");
      const data = getData();
      if (act !== "print" && !data) {
        flashBtn(item, false, "Run a scan first");
        return;
      }
      if (act === "print") { details.removeAttribute("open"); exportReport(); return; }
      if (act === "poc") { await downloadPocImage(data, item); return; }
      if (act === "card") { await downloadEvidenceCard(data, toolName, item); return; }
      if (act === "md") { await copyMarkdown(data, item); return; }
      if (act === "json") { await copyJsonReport(data, item); return; }
    });
  });

  document.addEventListener("click", (e) => {
    if (details && details.hasAttribute("open") && !details.contains(e.target)) {
      details.removeAttribute("open");
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && details) details.removeAttribute("open");
  });
}

/* ---------- Copy report as Markdown ------------------------------------ */
/* Builds a paste-ready Markdown summary of the last scan result — the
   same evidence the report card shows, formatted for pentest reports.
   Pure client-side (clipboard API + execCommand fallback); works on
   GitHub Pages and server.py alike. */

function markdownKind(data) {
  if (!data) return "generic";
  if (Array.isArray(data.checks) && data.grade) return "headers";
  if (Array.isArray(data.checks) && data.origins_tested) return "cors";
  if (Array.isArray(data.findings)) return "clickjacking";
  return "generic";
}

function mdCell(s) {
  return String(s == null ? "" : s).replace(/\|/g, "\\|").replace(/\n/g, " ").trim();
}

function toMarkdown(data) {
  if (!data) return "No scan data.";
  const kind = markdownKind(data);
  const title = kind === "headers" ? "Security Headers"
    : kind === "cors" ? "CORS Validator"
    : kind === "clickjacking" ? "Clickjacking Validator"
    : "CyberBuddy";
  const risk = (data.risk || "unknown").toUpperCase();
  const grade = data.grade ? " — Grade " + data.grade.toUpperCase() + " (" + (data.score ?? "?") + "/100)" : "";
  const lines = [
    "# CyberBuddy — " + title + " Report",
    "",
    "- **Target:** " + mdCell(data.url),
    "- **Final URL:** " + mdCell(data.final_url || data.url),
    "- **HTTP status:** " + (data.status_code != null ? data.status_code : "—"),
    "- **Risk:** " + risk + grade,
    "- **Source:** " + sourceLabel(data),
    "- **Generated:** " + fmtStampUtc()
  ];
  if (data.confirmation === "manual") {
    lines.push(
      "- **Confirmation:** analyst-attested (visual frame check, not measured from headers)"
    );
  }
  if (isUnverified(data)) {
    lines.push(
      "- **Caveat:** header values were proxied by a third-party relay and are " +
      "not independently verified. Re-run against `server.py` before relying on them."
    );
  }
  if (data.summary) lines.push("", "## Summary", "", data.summary);
  const rows = kind === "headers" ? (data.checks || [])
    : kind === "cors" ? (data.checks || [])
    : (data.findings || []);
  if (rows.length) {
    lines.push("", "## Findings", "", "| Check | Status | Assessment | Evidence |", "| --- | --- | --- | --- |");
    rows.forEach((c) => {
      lines.push("| " + mdCell(c.name) + " | " + mdCell(c.status) + " | " +
        mdCell(c.detail) + " | " + mdCell(c.evidence) + " |");
    });
  }
  lines.push("", "---", "Generated with CyberBuddy — authorized testing only.");
  return lines.join("\n");
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (_) { /* fall through */ }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return !!ok;
  } catch (_) {
    return false;
  }
}

function flashBtn(btn, ok, okLabel) {
  if (!btn) return;
  const original = btn.textContent;
  btn.textContent = ok ? (okLabel || "Copied ✓") : "Copy failed";
  btn.classList.add("flash", ok ? "flash-ok" : "flash-err");
  setTimeout(() => {
    btn.textContent = original;
    btn.classList.remove("flash", "flash-ok", "flash-err");
  }, 1600);
}

async function copyMarkdown(data, btn) {
  const ok = await copyText(toMarkdown(data));
  flashBtn(btn, ok);
  return ok;
}

async function copyJsonReport(data, btn) {
  if (!data) return false;
  const ok = await copyText(JSON.stringify(data, null, 2));
  flashBtn(btn, ok, "JSON copied ✓");
  return ok;
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
  // Clickjacking is specifically about framing — keep the findings to the two
  // framing controls, mirroring the Python engine. (Transport, cookies and
  // Permissions-Policy live in the Security Headers tool.)
  const findings = [
    assessXfo(headers["x-frame-options"]),
    assessFrameAncestors(headers["content-security-policy"])
  ];
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

/* ---------- Header lookup cache (dedupe + TTL) -------------------------- */
/* Concurrent scans of the same URL (the hub suite runs all three tools at
   once) share one lookup, and repeat scans reuse a 10-minute local cache —
   so public relays are hit far less often and rate limits rarely bite. */

const HEADER_CACHE_KEY = "cb-header-lookup-v1";
const HEADER_CACHE_TTL = 10 * 60 * 1000;

const headerLookupInFlight = new Map();

function headerCacheGet(url) {
  try {
    const raw = localStorage.getItem(HEADER_CACHE_KEY);
    if (!raw) return null;
    const map = JSON.parse(raw);
    const entry = map[url];
    if (!entry || !entry.at || !entry.value) return null;
    if (Date.now() - entry.at > HEADER_CACHE_TTL) return null;
    return entry.value;
  } catch (_) { return null; }
}

function headerCachePut(url, value) {
  try {
    const map = JSON.parse(localStorage.getItem(HEADER_CACHE_KEY) || "{}");
    const now = Date.now();
    Object.keys(map).forEach((k) => {
      if (!map[k].at || now - map[k].at > HEADER_CACHE_TTL) delete map[k];
    });
    map[url] = { at: now, value: value };
    localStorage.setItem(HEADER_CACHE_KEY, JSON.stringify(map));
  } catch (_) { /* private mode / quota — cache is best-effort */ }
}

async function lookupHeadersLive(url) {
  const cached = headerCacheGet(url);
  if (cached) return Object.assign({}, cached, { source: "cache-lookup" });
  if (headerLookupInFlight.has(url)) return headerLookupInFlight.get(url);
  const p = lookupHeadersRemote(url)
    .then((res) => {
      if (res) headerCachePut(url, res);
      return res;
    })
    .catch(() => null)
    .finally(() => { headerLookupInFlight.delete(url); });
  headerLookupInFlight.set(url, p);
  return p;
}

/* ---------- Third-party relay disclosure -------------------------------
   On GitHub Pages with no API_BASE configured, header reads are proxied by
   public services. That discloses the target URL — and the tester's IP — to
   operators outside the engagement, which many VAPT NDAs prohibit. So:
   ask first, send the hostname rather than the full URL by default, and
   label anything they return as unverified. */

const RELAY_HOSTS = ["hackertarget.com", "allorigins.win", "corsproxy.io", "codetabs.com"];
const RELAY_CONSENT_KEY = "cb-relay-consent";
// Session-scoped on purpose: consent should not silently persist across days.
function relayConsent() {
  try { return sessionStorage.getItem(RELAY_CONSENT_KEY) || ""; } catch (_) { return ""; }
}
function setRelayConsent(mode) {
  try { sessionStorage.setItem(RELAY_CONSENT_KEY, mode); } catch (_) { /* ignore */ }
}
function relayAllowed() {
  const c = relayConsent();
  return c === "host" || c === "full";
}
// "host" (default) sends only the hostname; "full" sends path + query too.
function relaySendsFullUrl() {
  return relayConsent() === "full";
}

// A direct cross-origin fetch involves no third party — the analyst's own
// browser talks to the target. Always worth trying first; it only succeeds
// when the target sends permissive CORS, but when it does the result is
// first-hand rather than relayed.
async function lookupHeadersDirect(url) {
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

async function lookupHeadersRemote(url) {
  const direct = await lookupHeadersDirect(url);
  if (direct) return direct;
  if (!relayAllowed()) return null;
  const encoded = encodeURIComponent(url);
  let host = "";
  try { host = new URL(url).hostname; } catch (_) { /* ignore */ }
  const ht = "https://api.hackertarget.com/httpheaders/?q=";
  // Host-only probes go first: most header checks are origin-level, and the
  // path/query is the part most likely to carry tokens or tenant IDs.
  const hostProbes = host ? [
    ht + encodeURIComponent(host),
    "https://api.allorigins.win/raw?url=" + encodeURIComponent(ht + host),
    "https://corsproxy.io/?url=" + encodeURIComponent(ht + host),
    "https://api.codetabs.com/v1/proxy?quest=" + encodeURIComponent(ht + host)
  ] : [];
  const fullProbes = relaySendsFullUrl() ? [
    ht + encoded,
    "https://api.allorigins.win/raw?url=" + encodeURIComponent(ht + url),
    "https://corsproxy.io/?url=" + encodeURIComponent(ht + url),
    "https://api.codetabs.com/v1/proxy?quest=" + encodeURIComponent(ht + url)
  ] : [];
  const probes = hostProbes.concat(fullProbes).filter(Boolean);

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

  return null;
}

async function gradeHeadersLive(url) {
  const looked = await lookupHeadersLive(url);
  if (!looked) {
    return {
      url: url, final_url: url, status_code: null,
      checks: [check("request", "error", "Could not read response headers from this hosted page. The target may be unreachable, the lookup may have been declined or rate-limited, or the Python engine is offline.", "", 0)],
      score: 0, grade: "F", risk: "unknown",
      summary: "No header data. The target may be unreachable, the lookup may have been declined or rate-limited, or its headers are blocked. Run python3 server.py for a same-origin scan, or retry.",
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

  let lastSuite = null;
  const toolbar = document.getElementById("suiteToolbar");
  const shareBtn = document.getElementById("suiteShare");
  const copyBtn = document.getElementById("suiteCopy");

  async function run() {
    const url = normalizeUrl(input.value);
    if (!url || !validUrl(url)) { input.focus(); return; }
    input.value = url;
    pushUrlParam(url);
    addRecentScan(url);
    renderRecentScans();
    setLoading(go, true);
    out.classList.remove("hidden");
    if (toolbar) toolbar.classList.add("hidden");
    // Ask before anything can reach a third-party relay. Without this the
    // hub silently degraded to "no header data" for every target on the
    // hosted site, with no way for the analyst to opt in.
    const consent = await ensureRelayConsent();
    if (consent === "deny") {
      out.innerHTML =
        '<div class="notice"><h3>Relay lookups declined</h3>' +
        "<p>Header grading needs either a local <code>server.py</code> or a " +
        "third-party relay. Run the Clickjacking tool for a frame-based visual " +
        "proof that needs neither, or start <code>python3 server.py</code> for " +
        "a full scan that never leaves your machine.</p></div>";
      setLoading(go, false);
      return;
    }
    out.innerHTML = '<div class="suite-grid">' +
      suiteSkeleton("Clickjacking") + suiteSkeleton("Headers") + suiteSkeleton("CORS") +
      "</div>";
    const [cj, hd, cr] = await Promise.all([
      apiScan(url).catch(() => null),
      apiHeaders(url).catch(() => null),
      apiCors(url).catch(() => null)
    ]);
    lastSuite = { url: url, clickjacking: cj, headers: hd, cors: cr };
    const base = appBase();
    out.innerHTML = '<div class="suite-grid">' +
      suiteCard("Clickjacking", cj, "findings", base + "/tools/clickjacking/?url=" + encodeURIComponent(url)) +
      suiteCard("Headers", hd, "checks", base + "/tools/headers/?url=" + encodeURIComponent(url)) +
      suiteCard("CORS", cr, "checks", base + "/tools/cors/?url=" + encodeURIComponent(url)) +
      "</div>";
    if (toolbar) toolbar.classList.remove("hidden");
    setLoading(go, false);
  }

  go.addEventListener("click", run);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  if (shareBtn) {
    shareBtn.addEventListener("click", async () => {
      const ok = await copyText(window.location.href);
      flashBtn(shareBtn, ok, "Link copied ✓");
    });
  }
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      if (!lastSuite) return;
      const parts = [
        toMarkdown(lastSuite.clickjacking),
        "",
        toMarkdown(lastSuite.headers),
        "",
        toMarkdown(lastSuite.cors)
      ];
      const ok = await copyText(parts.join("\n"));
      flashBtn(copyBtn, ok, "Suite copied ✓");
    });
  }
  initSuggestedTargets();
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
  if (data._unreachable) {
    return '<article class="card suite-card">' +
      '<div class="suite-card-top"><p class="card-title">' + esc(title) + '</p>' +
      '<span class="risk unreachable">UNREACHABLE</span></div>' +
      '<p class="verdict-text">Target did not respond — ' + esc(unreachableDetail(data)) + '</p>' +
      '<p class="suite-src">via ' + esc(sourceLabel(data)) + '</p>' +
      '<a class="tool-card-open" href="' + href + '">Open full report ' + ICONS.chevron + '</a></article>';
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

/* ---------- Relay consent gate -----------------------------------------
   Shown before the first scan that would need a public relay. Rendered
   into #relayGate on each tool page (and the hub). Resolves once the
   analyst chooses, so the scan can continue or abort. */

async function relayGateNeeded() {
  // Wait for engine detection to settle before deciding.
  try { await window.__cbEngineReady; } catch (_) { /* fall through */ }
  // Python engine present? Then relays are never reached.
  if (window.__cbEngine && window.__cbEngine.mode === "python") return false;
  return !relayConsent();
}

function renderRelayGate() {
  const wrap = document.getElementById("relayGate");
  if (!wrap) return Promise.resolve("skip");
  wrap.classList.remove("hidden");
  wrap.innerHTML =
    '<div class="relay-consent" role="alertdialog" aria-labelledby="relayGateTitle">' +
    '<h3 id="relayGateTitle">No local engine — header reads would use public relays</h3>' +
    "<p>This hosted page cannot read cross-origin response headers on its own. " +
    "To grade them it would proxy the request through public services, which " +
    "discloses what you are testing to operators outside your engagement:</p>" +
    "<ul>" + RELAY_HOSTS.map((h) => "<li><code>" + esc(h) + "</code></li>").join("") + "</ul>" +
    "<p>They would see the target and your IP address. Many assessment NDAs " +
    "prohibit this. For a fully private scan run <code>python3 server.py</code> locally.</p>" +
    '<div class="relay-consent-actions">' +
    '<button type="button" class="btn btn-primary btn-sm" data-consent="host">Allow — hostname only</button>' +
    '<button type="button" class="btn btn-ghost btn-sm" data-consent="full">Allow — full URL (path + query)</button>' +
    '<button type="button" class="btn btn-ghost btn-sm" data-consent="deny">No — frame test only</button>' +
    "</div></div>";
  return new Promise((resolve) => {
    wrap.querySelectorAll("[data-consent]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const mode = btn.getAttribute("data-consent");
        setRelayConsent(mode);
        wrap.classList.add("hidden");
        wrap.innerHTML = "";
        resolve(mode);
      });
    });
  });
}

/* Call before any scan that may fall through to a relay. */
async function ensureRelayConsent() {
  const needed = await relayGateNeeded();
  if (!needed) return relayConsent() || "skip";
  return renderRelayGate();
}

function isUnverified(data) {
  return !!(data && data._source === "relay");
}

function unverifiedFlag(data) {
  return isUnverified(data)
    ? '<span class="unverified-flag" title="Header values were proxied by a third-party service and are not independently verified">unverified</span>'
    : "";
}

/* ==========================================================================
   Visual confirmation (clickjacking, no header data)
   --------------------------------------------------------------------------
   When neither the Python engine nor a relay can supply header values, the
   frame itself is still real evidence — but the tool must not silently
   report "FRAME ONLY" while the analyst is looking at a rendered target.
   Ask them what they see, then record it as ANALYST-ATTESTED (never as a
   measured header result).
   ========================================================================== */

/* Heuristic hint. A cross-origin frame that never fires load, or fires with
   a zero-height document, is usually blocked. Advisory only — it just
   pre-selects the likely answer. */
function frameLikelyBlocked(frame, loaded) {
  if (!loaded) return true;
  try {
    const doc = frame.contentDocument;
    if (doc && doc.body && doc.body.scrollHeight === 0) return true;
  } catch (_) {
    // Throwing means a real cross-origin document is present → it rendered.
    return false;
  }
  return false;
}

function renderConfirmPrompt(hostId, suggestion, onChoose) {
  const wrap = document.getElementById(hostId);
  if (!wrap) return;
  const sug = (v) => (v === suggestion ? " suggested" : "");
  wrap.classList.remove("hidden");
  wrap.innerHTML =
    '<div class="confirm-prompt" role="group" aria-label="Visual confirmation">' +
    "<p><strong>Header values are unavailable from this host.</strong> " +
    "The frame above is still valid evidence — tell CyberBuddy what you see " +
    "and it will record your observation in the report.</p>" +
    '<div class="confirm-actions">' +
    '<button type="button" class="btn btn-ghost' + sug("framed") + '" data-verdict="framed">' +
    "The real site is rendered → framing allowed</button>" +
    '<button type="button" class="btn btn-ghost' + sug("blocked") + '" data-verdict="blocked">' +
    "Blank / refused → framing blocked</button>" +
    "</div>" +
    '<span class="confirm-hint">Recorded as <strong>analyst-attested</strong>, not as a ' +
    "measured header value. Note: this frame runs sandboxed without " +
    "<code>allow-same-origin</code>, so a few sites render blank because they need " +
    "same-origin storage — not because of framing headers. Confirm manually if unsure." +
    (suggestion
      ? " Highlighted button is CyberBuddy's guess from the frame's load behaviour."
      : "") +
    "</span></div>";
  wrap.querySelectorAll("[data-verdict]").forEach((btn) => {
    btn.addEventListener("click", () => {
      wrap.classList.add("hidden");
      wrap.innerHTML = "";
      onChoose(btn.getAttribute("data-verdict"));
    });
  });
}

/* Build the attested result object for a chosen verdict. */
function attestedClickjacking(base, verdict) {
  const framed = verdict === "framed";
  const data = Object.assign({}, base || {});
  data.confirmation = "manual";
  data.risk = framed ? "high" : "low";
  data.summary = framed
    ? "Analyst confirmed the target rendered inside a cross-origin frame. " +
      "No effective framing protection — the page can be clickjacked in this browser."
    : "Analyst confirmed the target refused to render in a cross-origin frame. " +
      "Framing appears to be blocked, though the specific header could not be read.";
  data.findings = [{
    name: "Frame test",
    status: framed ? "missing" : "protected",
    detail: framed
      ? "Analyst-attested: the real site UI rendered inside a cross-origin iframe."
      : "Analyst-attested: the target did not render inside a cross-origin iframe.",
    evidence: "Visual confirmation at " + fmtStampUtc()
  }];
  return data;
}

/* ---------- Share link (tool pages) ------------------------------------ */
/* Copies the current tool URL (with ?url= param) to the clipboard so
   pentesters can drop a shareable link straight into a report. */

function initShareButton() {
  const btn = document.getElementById("shareLink");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    const ok = await copyText(window.location.href);
    flashBtn(btn, ok, "Link copied ✓");
  });
}

/* ---------- Recent scans (hub page) ----------------------------------- */
/* Stores the last N scanned URLs in localStorage and renders them as
   quick-access chips on the hub. Each chip re-runs the suite. */

const RECENT_KEY = "cb-recent-scans";
const RECENT_MAX = 5;
// Client names age out on their own — a laptop left idle should not still
// be showing last month's engagement in the Recent chips.
const RECENT_TTL = 24 * 60 * 60 * 1000;

function getRecentScans() {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    const now = Date.now();
    // Entries are {url, at}; tolerate the older bare-string format.
    return arr
      .map((it) => (typeof it === "string" ? { url: it, at: now } : it))
      .filter((it) => it && it.url && (now - (it.at || 0)) < RECENT_TTL);
  } catch (_) { return []; }
}

function addRecentScan(url) {
  if (!url) return;
  try {
    let items = getRecentScans().filter((it) => it.url !== url);
    items.unshift({ url: url, at: Date.now() });
    if (items.length > RECENT_MAX) items = items.slice(0, RECENT_MAX);
    localStorage.setItem(RECENT_KEY, JSON.stringify(items));
  } catch (_) { /* quota / private mode */ }
}

/* Clearing history must also drop the header-lookup cache — it holds the
   same target URLs PLUS their full response headers, i.e. strictly more
   sensitive than the recent list. Clearing only RECENT_KEY left that data
   readable for another 10 minutes. */
function clearRecentScans() {
  try {
    localStorage.removeItem(RECENT_KEY);
    localStorage.removeItem(HEADER_CACHE_KEY);
  } catch (_) { /* private mode */ }
}

function renderRecentScans() {
  const wrap = document.getElementById("recentScans");
  if (!wrap) return;
  const items = getRecentScans();
  if (!items.length) {
    wrap.classList.add("hidden");
    wrap.innerHTML = "";
    return;
  }
  wrap.classList.remove("hidden");
  const chips = items.map((it) =>
    '<button type="button" class="recent-chip" data-url="' + esc(it.url) + '">' +
    esc(it.url) + "</button>"
  ).join("");
  wrap.innerHTML = '<span class="recent-label">Recent:</span> ' + chips +
    '<button type="button" class="recent-clear" id="clearRecent" title="Clear recent scans and cached headers">Clear</button>' +
    '<p class="privacy-note"><strong>Stored only in this browser</strong> (localStorage, cleared after 24h). ' +
    "Your scan history is never uploaded and is not visible to anyone else. " +
    "Clear also wipes the cached response headers.</p>";
  wrap.querySelectorAll(".recent-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const url = chip.getAttribute("data-url");
      const input = document.getElementById("suiteUrl") || document.getElementById("url");
      if (input) {
        input.value = url;
        const go = document.getElementById("suiteGo") || document.getElementById("go");
        if (go) go.click();
      }
    });
  });
  const clear = document.getElementById("clearRecent");
  if (clear) {
    clear.addEventListener("click", () => {
      clearRecentScans();
      renderRecentScans();
    });
  }
}

function initSuggestedTargets() {
  const wrap = document.getElementById("suggestedTargets");
  if (!wrap) return;
  // Point the "this site" chip at wherever CyberBuddy is actually hosted
  // (GitHub Pages vs. a local server.py), not a hard-coded Pages URL.
  const selfChip = document.getElementById("chipThisSite");
  if (selfChip) selfChip.setAttribute("data-url", window.location.origin + appBase() + "/");
  wrap.querySelectorAll("[data-url]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const url = chip.getAttribute("data-url");
      const input = document.getElementById("suiteUrl") || document.getElementById("url");
      if (!input || !url) return;
      input.value = url;
      const go = document.getElementById("suiteGo") || document.getElementById("go");
      if (go) go.click();
    });
  });
}

/* ---------- Keyboard shortcuts ---------------------------------------- */

// Element that had focus before the dialog opened, so it can be restored.
let kbdHelpReturnFocus = null;

function hideHelp() {
  const el = document.getElementById("kbdHelp");
  if (!el || el.classList.contains("hidden")) return;
  el.classList.add("hidden");
  el.setAttribute("aria-hidden", "true");
  if (kbdHelpReturnFocus && typeof kbdHelpReturnFocus.focus === "function") {
    kbdHelpReturnFocus.focus();
  }
  kbdHelpReturnFocus = null;
}

function toggleHelp() {
  const el = document.getElementById("kbdHelp");
  if (!el) return;
  const open = el.classList.contains("hidden");
  if (!open) { hideHelp(); return; }
  kbdHelpReturnFocus = document.activeElement;
  el.classList.remove("hidden");
  el.setAttribute("aria-hidden", "false");
  const close = document.getElementById("kbdHelpClose");
  if (close) close.focus();
}

/* Keep Tab inside the dialog while it is open (aria-modal is a promise to
   assistive tech that the rest of the page is inert — honour it). */
function trapHelpFocus(e) {
  if (e.key !== "Tab") return;
  const el = document.getElementById("kbdHelp");
  if (!el || el.classList.contains("hidden")) return;
  const focusable = el.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

function initKeyboard() {
  if (document.getElementById("kbdHelp")) return;
  const html =
    '<div id="kbdHelp" class="kbd-help hidden" role="dialog" aria-modal="true" aria-labelledby="kbdHelpTitle" aria-hidden="true">' +
    '<div class="kbd-help-panel">' +
    '<div class="kbd-help-head"><h2 id="kbdHelpTitle">Keyboard shortcuts</h2>' +
    '<button type="button" id="kbdHelpClose" class="btn btn-ghost btn-sm" aria-label="Close shortcuts">Close</button></div>' +
    "<dl>" +
    "<div><dt><kbd>/</kbd></dt><dd>Focus the target URL</dd></div>" +
    "<div><dt><kbd>t</kbd></dt><dd>Toggle light / dark theme</dd></div>" +
    "<div><dt><kbd>?</kbd></dt><dd>Show or hide this help</dd></div>" +
    "<div><dt><kbd>Esc</kbd></dt><dd>Close menus and this help</dd></div>" +
    "</dl>" +
    '<p class="form-hint">Authorized testing only. All checks are read-only GETs.</p>' +
    "</div></div>";
  document.body.insertAdjacentHTML("beforeend", html);
  const close = document.getElementById("kbdHelpClose");
  if (close) close.addEventListener("click", hideHelp);
  const overlay = document.getElementById("kbdHelp");
  if (overlay) {
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) hideHelp();
    });
  }
  document.addEventListener("keydown", trapHelpFocus);
  document.addEventListener("keydown", (e) => {
    const tag = ((e.target && e.target.tagName) || "").toLowerCase();
    const typing = tag === "input" || tag === "textarea" || tag === "select" ||
      !!(e.target && e.target.isContentEditable);
    if (e.key === "Escape") {
      hideHelp();
      return;
    }
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === "?") {
      e.preventDefault();
      toggleHelp();
    } else if (e.key === "/") {
      const input = document.getElementById("suiteUrl") || document.getElementById("url");
      if (input) {
        e.preventDefault();
        input.focus();
        if (input.select) input.select();
      }
    } else if (e.key === "t" || e.key === "T") {
      const btn = document.getElementById("themeToggle");
      if (btn) {
        e.preventDefault();
        btn.click();
      }
    }
  });
}
