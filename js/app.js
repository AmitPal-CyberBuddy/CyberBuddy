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
  policy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M6 3h12a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>',
  csrf: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.07 0l2-2a5 5 0 0 0-7.07-7.07l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.07 0l-2 2A5 5 0 0 0 12 20.07l1.1-1.1"/></svg>',
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
    navLink(base, "/guides/", "Guides", current) +
    navLink(base, "/#methodology", "Method", current) +
    toolsMenu(base, "hdr") +
    "</nav>" +
    '<button type="button" id="themeToggle" class="theme-toggle" aria-label="Switch theme" title="Switch theme">' +
    ICONS.sun + "</button>" +
    '<button type="button" id="kbdShortcut" class="kbd-shortcut" aria-label="Keyboard shortcuts" title="Keyboard shortcuts — press ?">?</button>' +
    '<button type="button" id="engineChip" class="engine-chip" aria-haspopup="dialog" aria-expanded="false" aria-controls="enginePopover" title="Checking scan engine — click to learn what this means">' +
    '<span class="engine-dot" id="engineDot"></span>' +
    '<span id="engineText">engine · …</span></button>' +
    '<div id="enginePopover" class="engine-popover hidden" role="dialog" aria-label="About the scan engine">' +
    '<p class="ep-title">Scan engine</p>' +
    '<p class="ep-status" id="enginePopStatus"><span class="engine-dot"></span><span>checking…</span></p>' +
    '<p class="ep-explain">CyberBuddy runs the same OWASP-aligned checks in three ways, and every report names the one that produced it:</p>' +
    "<ul>" +
    "<li><strong>Python engine</strong> — when <code>server.py</code> or the hosted API is online, scans run server-side with complete evidence (two-origin CORS proof, full header reads).</li>" +
    "<li><strong>In-browser graders</strong> — on this hosted page the same scoring runs in your browser. Reading headers of other sites may use a public relay, only with your consent.</li>" +
    "<li><strong>Published reports</strong> — demo targets are pre-scanned by CI and served from a cache. Their results are labelled <code>CACHED</code>, never <code>LIVE</code>.</li>" +
    "</ul>" +
    '<a class="ep-link" href="' + base + '/methodology/#hosted-scans">How the hosted site scans →</a>' +
    "</div>" +
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
  initEnginePopover();

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

/* Single registry for every live tool. The header Tools menu, the hub cards,
   the tools catalog (/tools/) and the footer all render from this one array —
   add a tool here and it appears everywhere. Metadata fields:

   - category: assess = URL-based target assessment (part of the hub suite);
               local = generator/analyzer that never scans a target.
   - input:    what the user hands the tool.
   - mode:     whether it contacts a target or stays entirely local.
   - evidence: the artifact the tool produces (never a fake LIVE/CACHED scan
               result or score for generators). */
const TOOL_CATEGORIES = {
  assess: {
    label: "Assess targets",
    hubLabel: "Assess a target",
    blurb: "URL-based checks that read a target you point them at. These four tools run together in the hub “Run suite” and produce LIVE/CACHED evidence reports.",
    suite: true
  },
  local: {
    label: "Local utilities",
    hubLabel: "Local security utilities",
    blurb: "Generators and analyzers that run entirely in your browser. They do not scan a target, do not join the “Run suite”, and produce no LIVE/CACHED result or score.",
    suite: false
  }
};

const TOOLS_MENU = [
  {
    href: "/tools/clickjacking/",
    label: "Clickjacking Validator",
    status: "live",
    icon: "frame",
    category: "assess",
    input: "URL",
    mode: "Contacts the target (read-only GET + live frame)",
    evidence: "Live frame proof + framing-header report card",
    desc: "Load a target in a live frame. If the real UI appears, the page can be clickjacked — screenshot the result as proof.",
    tags: ["X-Frame-Options", "frame-ancestors", "iframe PoC"],
    std: ["OWASP WSTG-CLNT-09", "CWE-1021"]
  },
  {
    href: "/tools/headers/",
    label: "Security Headers",
    status: "live",
    icon: "shield",
    category: "assess",
    input: "URL",
    mode: "Contacts the target (read-only GET)",
    evidence: "0–100 score + A–F grade report card",
    desc: "Grade CSP, X-Frame-Options, HSTS, cookie flags and the COOP/COEP family into an A–F score with the raw header behind every finding.",
    tags: ["CSP", "HSTS", "COOP/COEP", "grade A–F"],
    std: ["OWASP WSTG-CONF-07", "WSTG-CONF-12", "CWE-693"]
  },
  {
    href: "/tools/cors/",
    label: "CORS Validator",
    status: "live",
    icon: "cors",
    category: "assess",
    input: "URL",
    mode: "Contacts the target (read-only GET)",
    evidence: "Origin reflection + credentials report card",
    desc: "See how the target treats this page as a cross-origin caller — origin access, credentials, and Vary: Origin.",
    tags: ["ACAO", "credentials", "Vary: Origin"],
    std: ["OWASP WSTG-CLNT-07", "CWE-942"]
  },
  {
    href: "/tools/csp/",
    label: "CSP Policy Auditor",
    status: "live",
    icon: "policy",
    category: "assess",
    input: "URL",
    mode: "Contacts the target (read-only GET)",
    evidence: "Policy audit + directive-findings report card",
    desc: "Audit the enforced CSP for dangerous script sources, missing navigation controls, duplicate directives, and reporting gaps.",
    tags: ["script-src", "unsafe-inline", "frame-ancestors", "Report-Only"],
    std: ["OWASP WSTG-CONF-12", "CWE-79", "CWE-693"]
  },
  {
    href: "/tools/csrf/",
    label: "CSRF PoC Generator",
    status: "live",
    icon: "csrf",
    category: "local",
    input: "Raw HTTP request (Burp)",
    mode: "Local only — nothing sent, stored or relayed",
    evidence: "Standalone HTML PoC variants (no score, no LIVE/CACHED tag)",
    desc: "Paste a raw Burp request and get a standalone HTML proof-of-concept for authorized CSRF testing — parsed and generated fully in your browser.",
    tags: ["Burp request", "hidden form", "JSON fetch", "auto-submit"],
    std: ["OWASP WSTG-SESS-05", "CWE-352"]
  }
];
const TOOLS_SOON = ["TLS / SSL Analyzer", "Subdomain Enumeration"];

function toolsMenu(base, uid) {
  const id = "toolsMenu-" + (uid || "x");
  const up = uid === "ftr" ? " up" : "";
  const path = pagePath();

  const item = (t) => {
    const active = (base + t.href) === path;
    return '<a class="nav-menu-item' + (active ? " active" : "") + '" href="' + base + t.href + '">' +
      t.label + '<span class="nav-status ' + t.status + '">' + t.status + "</span></a>";
  };

  // Group live tools by category (assess vs local) so the menu stays small
  // even as more tools ship — never one top-level link per tool.
  const groups = [];
  ["assess", "local"].forEach((category) => {
    const tools = TOOLS_MENU.filter((t) => t.category === category);
    if (!tools.length) return;
    groups.push(
      '<div class="nav-menu-group">' + esc(TOOL_CATEGORIES[category].label) + "</div>" +
      tools.map(item).join("")
    );
  });

  const catalogActive = (base + "/tools/") === path;
  const catalog =
    '<a class="nav-menu-item' + (catalogActive ? " active" : "") + '" href="' + base + '/tools/">' +
    "All tools" + '<span class="nav-status live">catalog</span></a>';

  const soon = TOOLS_SOON.map((s) =>
    '<span class="nav-menu-item disabled" aria-disabled="true">' + s +
    '<span class="nav-status soon">soon</span></span>'
  ).join("");
  return '<details class="nav-menu' + up + '" id="' + id + '">' +
    "<summary>Tools " + ICONS.chevron + "</summary>" +
    '<div class="nav-menu-panel">' + catalog + groups.join("") +
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
    "<div><strong>CyberBuddy</strong><span>Browser security assessment suite</span>" +
    '<span class="footer-engine">Engine: in-browser on Pages · <code>python3 server.py</code> locally</span>' +
    '<span class="footer-contact">' +
    '<a href="mailto:amitpal.secure@gmail.com">amitpal.secure@gmail.com</a>' +
    '<a class="social-link" href="https://www.linkedin.com/in/amitpal-wb/" target="_blank" rel="noopener noreferrer">' +
    ICONS.linkedin + "Connect on LinkedIn</a>" +
    '<a class="social-link" href="https://amitpxl.medium.com/" target="_blank" rel="noopener noreferrer">' +
    ICONS.medium + "Read My blog · Medium</a>" +
    "</span></div></div>" +
    // Scalable footer: category links, not a growing per-tool list. New tools
    // appear here automatically via the catalog — no footer edit needed.
    '<nav class="footer-col" aria-label="Tools">' +
    "<strong>Tools</strong>" +
    '<a href="' + base + '/tools/">All tools</a>' +
    '<a href="' + base + '/tools/#assess-targets">Target assessments</a>' +
    '<a href="' + base + '/tools/#local-utilities">Local utilities</a>' +
    "</nav>" +
    // Guides are a section link, not one entry per guide — the same
    // scalability rule the Tools column follows.
    '<nav class="footer-col" aria-label="Learn">' +
    "<strong>Learn</strong>" +
    '<a href="' + base + '/guides/">Guides</a>' +
    '<a href="' + base + '/methodology/">Methodology</a>' +
    '<a href="' + base + '/#methodology">Scoring methodology</a>' +
    '<a href="' + base + '/methodology/#privacy">Privacy</a>' +
    "</nav>" +
    '<nav class="footer-col" aria-label="Project">' +
    "<strong>Project</strong>" +
    '<a href="https://github.com/AmitPal-CyberBuddy/CyberBuddy" target="_blank" rel="noopener noreferrer">GitHub</a>' +
    '<a href="' + base + '/.well-known/security.txt">Security policy</a>' +
    // Documentation is a first-class page, not a hop to the repo README: the
    // README is mostly contributor material (file tree, engine internals).
    '<a href="' + base + '/documentation/">Documentation</a>' +
    "</nav>" +
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

/* One-line plain-language descriptions of the methodology IDs, so a
   visitor who has never heard of WSTG or CWE can hover and learn. */
const STD_TITLES = {
  "OWASP WSTG-CLNT-09": "OWASP Web Security Testing Guide — Testing for Clickjacking",
  "CWE-1021": "CWE-1021 — Improper Restriction of Rendered UI Layers or Frames",
  "OWASP WSTG-CONF-07": "OWASP Web Security Testing Guide — Testing for Weak Transport Layer Security",
  "WSTG-CONF-12": "OWASP Web Security Testing Guide — Testing for Content Security Policy Weaknesses",
  "OWASP WSTG-CONF-12": "OWASP Web Security Testing Guide — Testing for Content Security Policy Weaknesses",
  "CWE-79": "CWE-79 — Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
  "CWE-693": "CWE-693 — Protection Mechanism Failure",
  "OWASP WSTG-CLNT-07": "OWASP Web Security Testing Guide — Testing for Cross-Origin Resource Sharing",
  "CWE-942": "CWE-942 — Permissive Cross-domain Policy with Untrusted Domains",
  "OWASP WSTG-SESS-05": "OWASP Web Security Testing Guide — Testing for Cross Site Request Forgery",
  "CWE-352": "CWE-352 — Cross-Site Request Forgery (CSRF)"
};

function stdBadgeHtml(code) {
  const t = STD_TITLES[code] ? ' title="' + esc(STD_TITLES[code]) + '"' : "";
  return '<span class="std-id"' + t + ">" + esc(code) + "</span>";
}

/* One shared card builder so the hub and the catalog can never drift apart. */
function toolCardHtml(t, i, base, ghostAction) {
  const icon = ICONS[t.icon] || ICONS.plus;
  const tags = (t.tags || []).map((tag) => '<span class="tool-tag">' + esc(tag) + "</span>").join("");
  const std = (t.std || []).map(stdBadgeHtml).join("");
  const led = t.status === "live" ? "status-led" : "status-led " + t.status;
  return '<a class="tool-card card corner-card reveal" style="--d: ' + (0.05 + i * 0.07) + 's" href="' +
    base + t.href + '">' +
    '<div class="tool-card-top"><span class="tool-card-icon">' + icon +
    '</span><span class="' + led + '">' + esc(t.status) + "</span></div>" +
    "<div><h3>" + esc(t.label) + '</h3><p class="tool-card-desc">' + esc(t.desc) + "</p></div>" +
    '<div class="tool-card-tags">' + tags + "</div>" +
    '<div class="tool-card-std">' + std + "</div>" +
    '<span class="tool-card-open">' + (ghostAction || "Run check") + " " + ICONS.chevron + "</span></a>";
}

function renderToolCards() {
  const assessGrid = document.getElementById("assessGrid");
  const localGrid = document.getElementById("localGrid");
  if (!assessGrid || !localGrid) return;
  const base = appBase();
  const live = TOOLS_MENU.filter((t) => t.status === "live").length;
  const count = document.getElementById("toolCount");
  if (count) count.textContent = String(live).padStart(2, "0") + " live";

  const assess = TOOLS_MENU.filter((t) => t.category === "assess");
  const local = TOOLS_MENU.filter((t) => t.category === "local");

  const soonTags = TOOLS_SOON.map((s) => '<span class="tool-tag">' + esc(s.split(" ")[0]) + "</span>").join("");
  const ghost =
    '<div class="tool-card card tool-card--ghost reveal" style="--d: .26s">' +
    '<div class="tool-card-top"><span class="tool-card-icon">' + ICONS.plus +
    '</span><span class="status-led soon">soon</span></div>' +
    "<div><h3>More tools coming soon</h3>" +
    '<p class="tool-card-desc">' + esc(TOOLS_SOON.join(", ")) +
    " and more are on the bench — this slot is reserved for the next check to ship.</p></div>" +
    '<div class="tool-card-tags">' + soonTags + "</div></div>";

  assessGrid.innerHTML = assess.map((t, i) => toolCardHtml(t, i, base)).join("") + ghost;
  localGrid.innerHTML = local.map((t, i) => toolCardHtml(t, i, base)).join("");
  initCardSpotlights(assessGrid);
  initCardSpotlights(localGrid);
}

/* Renders the dedicated tools catalog (/tools/) from the same registry as the
   menu, hub cards and footer. One card per tool: purpose, category, input,
   target vs local, evidence, and OWASP/CWE mapping. */
function renderToolCatalog() {
  const wrap = document.getElementById("toolCatalog");
  if (!wrap) return;
  const base = appBase();
  const live = TOOLS_MENU.filter((t) => t.status === "live").length;
  const count = document.getElementById("toolCount");
  if (count) count.textContent = String(live).padStart(2, "0") + " live";

  const card = (t, i) => {
    const icon = ICONS[t.icon] || ICONS.plus;
    const std = (t.std || []).map(stdBadgeHtml).join("");
    const cat = TOOL_CATEGORIES[t.category] || { label: t.category };
    return '<article class="card tool-catalog-card reveal" style="--d: ' + (0.05 + i * 0.06) + 's">' +
      '<div class="tool-catalog-head">' +
      '<span class="tool-card-icon">' + icon + "</span>" +
      '<h3>' + esc(t.label) + "</h3>" +
      '<span class="cat-badge cat-' + esc(t.category) + '">' + esc(cat.label) + "</span>" +
      "</div>" +
      '<p class="tool-catalog-purpose">' + esc(t.desc) + "</p>" +
      '<dl class="catalog-meta">' +
      "<dt>Input</dt><dd>" + esc(t.input) + "</dd>" +
      "<dt>Mode</dt><dd>" + esc(t.mode) + "</dd>" +
      "<dt>Evidence</dt><dd>" + esc(t.evidence) + "</dd>" +
      "<dt>Standards</dt><dd class=\"catalog-std\">" + (std || "—") + "</dd>" +
      "</dl>" +
      '<a class="btn btn-primary btn-sm" href="' + base + t.href + '">Launch ' + esc(t.label) + "</a>" +
      "</article>";
  };

  const groups = ["assess", "local"].map((category) => {
    const tools = TOOLS_MENU.filter((t) => t.category === category);
    if (!tools.length) return "";
    const cat = TOOL_CATEGORIES[category];
    return '<section class="catalog-group" id="' + (category === "assess" ? "assess-targets" : "local-utilities") + '" aria-labelledby="' + (category === "assess" ? "assess-heading" : "local-heading") + '">' +
      '<div class="category-head">' +
      '<h2 id="' + (category === "assess" ? "assess-heading" : "local-heading") + '">' + esc(cat.hubLabel) + "</h2>" +
      (cat.suite ? '<span class="cat-badge cat-suite">part of Run suite</span>' : '<span class="cat-badge cat-local">not in Run suite</span>') +
      '<p>' + esc(cat.blurb) + "</p>" +
      "</div>" +
      '<div class="tool-catalog-grid">' + tools.map(card).join("") + "</div>" +
      "</section>";
  });

  wrap.innerHTML = groups.join("");
}

/* ---------- Engine detection -------------------------------------------- */

window.__cbEngine = { mode: "checking" };

/* The chip's popover is how a first-time visitor learns what the cryptic
   "browser · no engine" state means — every mode gets a plain-language
   sentence, and the chip stays a button so the explanation is one click
   away on every page. */
function setEnginePopStatus(cls, label) {
  const status = document.getElementById("enginePopStatus");
  if (!status) return;
  status.className = "ep-status" + (cls ? " " + cls : "");
  const text = status.querySelector("span:last-child");
  if (text) text.textContent = label;
}

function initEnginePopover() {
  const chip = document.getElementById("engineChip");
  const pop = document.getElementById("enginePopover");
  if (!chip || !pop) return;
  // Escape the header's backdrop-filter, which would otherwise become the
  // containing block for position:fixed (breaking the mobile bottom sheet).
  document.body.appendChild(pop);
  const close = () => {
    pop.classList.add("hidden");
    chip.setAttribute("aria-expanded", "false");
  };
  const open = () => {
    if (window.innerWidth > 760) {
      const r = chip.getBoundingClientRect();
      const w = Math.min(420, window.innerWidth - 28);
      pop.style.cssText = "position:fixed;width:" + w + "px;" +
        "left:" + Math.max(14, Math.min(r.right - w, window.innerWidth - w - 14)) + "px;" +
        "top:" + (r.bottom + 8) + "px;";
    } else {
      // Small screens: clear inline styles and let the stylesheet's
      // bottom-sheet media query position it.
      pop.style.cssText = "";
    }
    pop.classList.remove("hidden");
    chip.setAttribute("aria-expanded", "true");
  };
  chip.addEventListener("click", (e) => {
    e.stopPropagation();
    if (pop.classList.contains("hidden")) open();
    else close();
  });
  document.addEventListener("click", (e) => {
    if (!pop.classList.contains("hidden") && !pop.contains(e.target) &&
        e.target !== chip && !chip.contains(e.target)) close();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") close();
  });
  window.addEventListener("scroll", close, { passive: true, capture: true });
}

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
          chip.title = "Python engine online — scans run on this host. Click for details.";
          chip.classList.add("is-on");
          dot.classList.add("on");
          text.textContent = "python · online";
          setEnginePopStatus("is-on", "python engine online — same-origin scans on this host, complete evidence");
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
    "Run server.py locally for a same-origin scan. Click for details.";
  chip.classList.add("is-live");
  dot.classList.add("on", "live");
  text.textContent = "browser · no engine";
  setEnginePopStatus("is-live", "in-browser graders — no python engine detected; header reads for other sites may use public relays after your consent");
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
  if (kind === "csp") return data.status_code != null && Array.isArray(data.checks) && data.risk;
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

async function apiCsp(url) {
  const local = await apiCall("/api/csp", url);
  if (isUsableScan(local, "csp")) {
    local._source = "python";
    return local;
  }
  if (isUnreachable(local, "checks")) return markUnreachable(local, "python");
  const cached = await cachedReportFor(url);
  if (cached && cached.csp && cached.csp.status_code != null &&
      isUsableScan(cached.csp, "csp")) {
    cached.csp._source = "cache";
    cached.csp._cached_at = cached.generated_at || "";
    return cached.csp;
  }
  // Backwards-compatible with a report built before the dedicated CSP entry
  // existed: the Security Headers cache already carries both CSP fields.
  if (cached && cached.headers && cached.headers.status_code != null && cached.headers.headers) {
    const derived = gradeCspFromMap(
      url,
      cached.headers.status_code,
      cached.headers.final_url || url,
      cached.headers.headers,
      "cache"
    );
    derived._cached_at = cached.generated_at || "";
    return derived;
  }
  return gradeCspLive(url);
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
  const reachable = [entry.clickjacking, entry.headers, entry.cors, entry.csp]
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
  if (s === "relay-cached") return "third-party relay (cached 10 min)";
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

function cleanPastedUrl(raw) {
  let value = String(raw == null ? "" : raw).trim();
  // Chat, email and spreadsheets commonly wrap pasted URLs in straight or
  // curly quotes. They are presentation punctuation, not part of the URL.
  value = value.replace(/^["'“”‘’]+|["'“”‘’]+$/g, "").trim();
  // A sentence-ending full stop is another common paste artefact. Strip it,
  // then make a second quote pass for input copied as `"example.com".`.
  value = value.replace(/\.$/, "");
  value = value.replace(/^["'“”‘’]+|["'“”‘’]+$/g, "").trim();
  return value;
}

function looksLikeHostPort(value) {
  // A domain/localhost followed by a numeric port is an authority, not an
  // unknown scheme. Keep this narrow so javascript:, data:, ftp: and typos
  // such as httpss:// still hit the unsupported-scheme guard below.
  return /^(?:localhost|(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)):\d+(?:[/?#]|$)/i.test(value);
}

function normalizeUrl(raw) {
  let value = cleanPastedUrl(raw);
  if (!value) return "";
  const hasHttp = /^https?:\/\//i.test(value);
  const scheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value);
  if (scheme && !hasHttp && !looksLikeHostPort(value)) return "";
  if (!hasHttp) {
    // server.py is an HTTP development server. Default loopback names to
    // HTTP so the documented localhost workflow works without manual edits;
    // public hostnames continue to default to HTTPS.
    const local = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?(?:[/?#]|$)/i.test(value);
    value = (local ? "http://" : "https://") + value;
  }
  return value;
}

function urlValidation(raw) {
  const cleaned = cleanPastedUrl(raw);
  if (!cleaned) {
    return { valid: false, url: "", code: "empty", message: "Enter a URL to scan." };
  }
  if (/\s/.test(cleaned) && !/^https?:\/\//i.test(cleaned)) {
    return {
      valid: false, url: "", code: "search",
      message: "This looks like a search term. Enter a hostname such as example.com."
    };
  }
  const scheme = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(cleaned);
  if (scheme && !/^https?:\/\//i.test(cleaned) && !looksLikeHostPort(cleaned)) {
    return {
      valid: false, url: "", code: "scheme",
      message: "Only http:// and https:// URLs can be scanned."
    };
  }

  const normalized = normalizeUrl(cleaned);
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (_) {
    return {
      valid: false, url: "", code: "malformed",
      message: "Enter a valid URL, such as https://example.com."
    };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      valid: false, url: "", code: "scheme",
      message: "Only http:// and https:// URLs can be scanned."
    };
  }
  if (parsed.username || parsed.password) {
    return {
      valid: false, url: "", code: "credentials",
      message: "Remove the username and password from the URL before scanning."
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return {
      valid: false, url: "", code: "hostname",
      message: "The URL needs a hostname."
    };
  }
  const isIpv6 = hostname.startsWith("[") && hostname.endsWith("]");
  const ipv4Parts = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)
    ? hostname.split(".").map(Number) : null;
  const isIpv4 = !!(ipv4Parts && ipv4Parts.every((part) => part >= 0 && part <= 255));
  const isLocalhost = hostname === "localhost";

  if (!isIpv4 && !isIpv6 && !isLocalhost) {
    const labels = hostname.replace(/\.$/, "").split(".");
    if (labels.some((label) => !label)) {
      return {
        valid: false, url: "", code: "empty-label",
        message: "Hostname labels cannot be empty (for example, a..b is invalid)."
      };
    }
    if (labels.length < 2) {
      return {
        valid: false, url: "", code: "public-tld",
        message: "Public hostnames need a dot and a plausible TLD (for example, example.com)."
      };
    }
    if (hostname.length > 253 || labels.some((label) =>
      label.length > 63 || !/^[a-z0-9-]+$/i.test(label))) {
      return {
        valid: false, url: "", code: "hostname",
        message: "The hostname contains an invalid label."
      };
    }
    if (labels.some((label) => label.startsWith("-") || label.endsWith("-"))) {
      return {
        valid: false, url: "", code: "hyphen",
        message: "Hostname labels cannot start or end with a hyphen."
      };
    }
    const tld = labels[labels.length - 1];
    if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i.test(tld)) {
      return {
        valid: false, url: "", code: "public-tld",
        message: "Public hostnames need a plausible TLD, such as .com or .org."
      };
    }
  }

  return { valid: true, url: normalized, code: "ok", message: "" };
}

function validUrl(raw) {
  return urlValidation(raw).valid;
}

function urlErrorElement(input) {
  if (!input) return null;
  const id = input.id + "Error";
  let error = document.getElementById(id);
  if (!error) {
    error = document.createElement("p");
    error.id = id;
    error.className = "field-error hidden";
    error.setAttribute("role", "alert");
    input.insertAdjacentElement("afterend", error);
  }
  const described = (input.getAttribute("aria-describedby") || "").split(/\s+/).filter(Boolean);
  if (!described.includes(id)) described.push(id);
  input.setAttribute("aria-describedby", described.join(" "));
  return error;
}

function clearUrlError(input) {
  const error = urlErrorElement(input);
  if (error) {
    error.textContent = "";
    error.classList.add("hidden");
  }
  input.removeAttribute("aria-invalid");
}

function showUrlError(input, message) {
  const error = urlErrorElement(input);
  if (error) {
    error.classList.remove("hidden");
    error.textContent = message;
  }
  input.setAttribute("aria-invalid", "true");
}

function validateUrlField(input, focusOnError) {
  if (!input) return "";
  const result = urlValidation(input.value);
  if (!result.valid) {
    showUrlError(input, result.message);
    if (focusOnError !== false) input.focus();
    return "";
  }
  input.value = result.url;
  clearUrlError(input);
  return result.url;
}

function initUrlInput(input) {
  if (!input || input.dataset.urlValidationBound === "1") return;
  input.dataset.urlValidationBound = "1";
  urlErrorElement(input);
  input.addEventListener("input", () => clearUrlError(input));
  input.addEventListener("blur", () => {
    if (cleanPastedUrl(input.value)) validateUrlField(input, false);
  });
  input.addEventListener("paste", () => {
    setTimeout(() => {
      if (cleanPastedUrl(input.value)) validateUrlField(input, false);
    }, 0);
  });
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

/* ---------- Score gauge ------------------------------------------------
   The 0–100 result rendered as an SVG ring that animates to the real score.
   The number stays as SVG <text> (not only an arc), so screenshots and
   assistive tech always read the actual value; the arc is decoration. */

const GAUGE_BANDS = [
  [90, "excellent"],
  [75, "good"],
  [60, "fair"],
  [45, "weak"],
  [0, "critical"]
];

function gaugeBand(score) {
  score = Number(score) || 0;
  for (let i = 0; i < GAUGE_BANDS.length; i++) {
    if (score >= GAUGE_BANDS[i][0]) return GAUGE_BANDS[i][1];
  }
  return "critical";
}

/* `filled` renders the final arc immediately (used where the gauge replaces
   an already-computed result rather than animating in). */
function gaugeHtml(score, grade, filled) {
  const s = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
  const g = String(grade || gradeLetter(s)).toLowerCase();
  const offset = filled ? String(100 - s) : "100";
  return '<div class="score-gauge gauge-' + g + '" role="img" aria-label="Score ' + s +
    " out of 100 — " + gaugeBand(s) + '"' +
    ' title="Security headers score out of 100. Grade bands: A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 45 · F below.">' +
    '<svg viewBox="0 0 120 120" aria-hidden="true">' +
    '<circle class="gauge-track" cx="60" cy="60" r="52" pathLength="100"/>' +
    '<circle class="gauge-arc" cx="60" cy="60" r="52" pathLength="100" ' +
    'stroke-dasharray="100" stroke-dashoffset="' + offset + '" transform="rotate(-90 60 60)"/>' +
    '<text class="gauge-num" x="60" y="57">' + s + "</text>" +
    '<text class="gauge-den" x="60" y="75">/ 100</text>' +
    '</svg><span class="gauge-band">' + gaugeBand(s).toUpperCase() + "</span></div>";
}

function renderGauge(el, score, grade) {
  if (!el) return;
  const s = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
  el.innerHTML = gaugeHtml(s, grade);
  const arc = el.querySelector(".gauge-arc");
  if (!arc) return;
  if (prefersReduced() || !("requestAnimationFrame" in window)) {
    arc.style.strokeDashoffset = String(100 - s);
    return;
  }
  // Two frames: insert with a full gap, then animate to the real score.
  requestAnimationFrame(() => {
    requestAnimationFrame(() => { arc.style.strokeDashoffset = String(100 - s); });
    const num = el.querySelector(".gauge-num");
    if (num) countUp(num, s, "");
  });
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
    "<span>" + esc(redactUrlCredentials((data && data.url) || "—")) + "</span>",
    '<span class="prov-sep">|</span>',
    "<span>" + esc(fmtStampUtc()) + "</span>",
    '<span class="prov-sep">|</span>',
    "<span>source: " + esc(sourceLabel(data)) + "</span>"
  ];
  if (data && data.confirmation === "manual") {
    bits.push('<span class="prov-sep">|</span>',
      '<span class="prov-manual" title="Recorded from your visual confirmation of the frame — not a measured header value">analyst-attested</span>');
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
    '<label class="evidence-toggle" title="After a scan, collapses the page sections around the report so the whole result fits one screenshot">' +
    '<input type="checkbox" id="evidenceChk"' + (evidenceEnabled() ? " checked" : "") + " /> " +
    "Evidence mode — after a scan, collapse the page around the report so it fits one screenshot" +
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
  const inView = (el) => {
    const r = el.getBoundingClientRect();
    return r.top < window.innerHeight && r.bottom > 0;
  };
  let io = null;
  if ("IntersectionObserver" in window) {
    io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add("in");
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.05 });
  }
  const track = (root) => {
    if (!root || root.nodeType !== 1 && root.nodeType !== 9) return;
    const list = Array.prototype.slice.call(root.querySelectorAll(".reveal"));
    if (root.classList && root.classList.contains("reveal")) list.push(root);
    list.forEach((el) => {
      if (el.classList.contains("in")) return;
      if (io) {
        if (inView(el)) el.classList.add("in");
        else io.observe(el);
      } else {
        el.classList.add("in");
      }
    });
  };
  track(document);
  // The hub injects its tool cards and blog grid AFTER boot
  // (renderToolCards / renderBlog). Without this watch, those .reveal nodes
  // stay at opacity: 0 forever — present and clickable, but invisible.
  if (window.MutationObserver) {
    const mo = new MutationObserver((muts) => {
      muts.forEach((m) => {
        m.addedNodes.forEach((n) => { if (n.nodeType === 1) track(n); });
      });
    });
    mo.observe(document.body, { childList: true, subtree: true });
  }
  // Safety net: re-query at fire time so anything the observers missed
  // (including late-injected content) is visible after 2s, guaranteed.
  setTimeout(() => {
    document.querySelectorAll(".reveal:not(.in)").forEach((el) => el.classList.add("in"));
  }, 2000);
}

function exportReport() {
  window.print();
}

/* ==========================================================================
   Export menu — print, evidence card, clipboard
   ========================================================================== */

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

function redactUrlCredentials(raw) {
  const value = String(raw == null ? "" : raw);
  try {
    const parsed = new URL(value);
    if (!parsed.username && !parsed.password) return value;
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch (_) {
    // Defensive fallback for malformed imported scan data. User-entered
    // credential URLs are rejected before a scan, but exports must still
    // never echo a pasted password.
    return value.replace(/^(https?:\/\/)[^/@\s]+@/i, "$1");
  }
}

function reportSafeCopy(data) {
  if (!data || typeof data !== "object") return data;
  if (Array.isArray(data)) return data.map(reportSafeCopy);
  const out = {};
  Object.keys(data).forEach((key) => {
    const value = data[key];
    out[key] = (key === "url" || key === "final_url")
      ? redactUrlCredentials(value)
      : reportSafeCopy(value);
  });
  return out;
}

function safeSlug(url) {
  try {
    return (new URL(redactUrlCredentials(url)).hostname || "target").replace(/[^a-z0-9.-]/gi, "-");
  } catch (_) {
    return "target";
  }
}

function stampName(prefix, url, ext) {
  const t = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
  return prefix + "-" + safeSlug(url) + "-" + t + "." + ext;
}

/* Deterministic, dependency-free evidence card drawn from the scan JSON.
   Same-origin canvas only, so it never taints and always downloads — the
   trade-off is that it cannot show the live framed site. */
function evidenceCardKind(data, toolName) {
  const name = String(toolName || "").toLowerCase();
  if (name.includes("clickjack") || Array.isArray(data && data.findings)) return "clickjacking";
  if (name.includes("cors") || (data && Array.isArray(data.origins_tested))) return "cors";
  if (name.includes("csp") || (data && Object.prototype.hasOwnProperty.call(data, "policy"))) return "csp";
  if (name.includes("header") || (data && data.grade)) return "headers";
  return "generic";
}

/* A small per-tool specification keeps the canvas renderer shared while each
   card leads with the evidence that actually answers that tool's question. */
function buildEvidenceCardSpec(data, toolName) {
  data = data || {};
  const kind = evidenceCardKind(data, toolName);
  const risk = String(data.risk || "unknown").toLowerCase();
  const target = redactUrlCredentials(data.url || "—");
  const finalUrl = redactUrlCredentials(data.final_url || data.url || "—");
  const commonMeta = [
    ["Target", target],
    ["Final URL", finalUrl],
    ["HTTP status", data.status_code != null ? String(data.status_code) : "—"],
    ["Source", sourceLabel(data)],
    ["Generated", fmtStampUtc()]
  ];
  const caveats = [];
  if (data.confirmation === "manual") caveats.push(["Confirmation", "analyst-attested visual observation"]);
  if (isUnverified(data)) caveats.push(["Caveat", "relay data — not independently verified"]);

  if (kind === "clickjacking") {
    const protection = risk === "low" ? "PROTECTION ENABLED"
      : risk === "medium" ? "PROTECTION PARTIAL"
      : risk === "high" ? "PROTECTION NOT ENABLED"
      : "MANUAL FRAME CHECK";
    const observed = data.frame_observation || {};
    let rendered = "NOT YET OBSERVED";
    if (observed.rendered === true) {
      rendered = "YES — target UI rendered (analyst-attested)";
    } else if (observed.rendered === false && data.confirmation === "manual") {
      rendered = "NO — blank or refused (analyst-attested)";
    } else if (observed.event === "error") {
      rendered = "NO RENDER OBSERVED — frame error event fired";
    } else if (observed.event === "load") {
      rendered = "NOT MACHINE-VERIFIABLE — iframe load event fired; inspect the live stage";
    }
    const overlay = data.poc_overlay || {};
    const context = [
      {
        name: "Observed frame rendering", status: observed.rendered === true ? "weak" : "info",
        detail: rendered,
        evidence: data.confirmation === "manual" ? "Manual visual confirmation" : "Cross-origin pixels are not readable by this page"
      },
      {
        name: "Frame-load peek", status: "info",
        detail: observed.peek || "No frame-load observation was recorded.",
        evidence: "A cross-origin document is intentionally unreadable"
      },
      {
        name: "PoC evidence", status: "info",
        detail: "The live cross-origin frame cannot be drawn to canvas. This card records the observed outcome in words rather than implying a captured frame.",
        evidence: overlay.visible
          ? "Illustrative attacker layer shown at " + (overlay.opacity_percent || 72) + "% opacity"
          : "Illustrative attacker layer was not shown when this card was generated"
      }
    ];
    return {
      kind: kind,
      title: "CLICKJACKING VALIDATOR",
      hero: protection + " · " + risk.toUpperCase(),
      risk: risk,
      meta: commonMeta.concat(caveats),
      summary: data.summary || "",
      contextTitle: "FRAME OUTCOME",
      context: context,
      rowsTitle: "FRAMING CONTROLS",
      rows: data.findings || []
    };
  }

  if (kind === "cors") {
    const headers = data.headers || {};
    const origins = data.origins_tested || [];
    const genuineProof = origins.length >= 2;
    const outcome = risk === "high" ? "REFLECTION + CREDENTIALS CONFIRMED"
      : risk === "medium" ? "PERMISSIVE CORS OUTCOME"
      : "NO ARBITRARY-ORIGIN REFLECTION OBSERVED";
    return {
      kind: kind,
      title: "CORS VALIDATOR",
      hero: outcome + " · " + risk.toUpperCase(),
      risk: risk,
      meta: commonMeta.concat([
        ["Probe coverage", genuineProof
          ? "TWO-ORIGIN REFLECTION PROOF (python engine / published scan)"
          : "SINGLE-ORIGIN BROWSER PROBE (not proof of reflection)"],
        ["Origins tested", origins.length ? origins.join(" · ") : "—"]
      ], caveats),
      summary: data.summary || "",
      contextTitle: "CORS RESPONSE TRIPLE",
      context: [
        { name: "ACAO", status: "info", detail: headers["access-control-allow-origin"] || "(absent)", evidence: "Access-Control-Allow-Origin" },
        { name: "ACAC", status: "info", detail: headers["access-control-allow-credentials"] || "(absent)", evidence: "Access-Control-Allow-Credentials" },
        { name: "Vary", status: "info", detail: headers.vary || "(absent)", evidence: "Expected token for origin-specific responses: Origin" }
      ],
      rowsTitle: "PROBE FINDINGS",
      rows: data.checks || []
    };
  }

  if (kind === "csp") {
    const directives = Object.keys(data.directives || {}).sort();
    return {
      kind: kind,
      title: "CSP POLICY AUDITOR",
      hero: (risk === "low" ? "ENFORCED POLICY IS RESTRICTIVE" : "POLICY NEEDS ATTENTION") + " · " + risk.toUpperCase(),
      risk: risk,
      meta: commonMeta.concat(caveats),
      summary: data.summary || "",
      contextTitle: "POLICY EVIDENCE",
      context: [
        {
          name: "Enforced policy", status: data.policy ? "ok" : "missing",
          detail: data.policy || "(not present)",
          evidence: data.policy ? "Content-Security-Policy response header" : "No enforced policy was returned"
        },
        {
          name: "Report-only policy", status: "info",
          detail: data.report_only_policy || "(not present)",
          evidence: "Report-Only records violations but does not enforce them"
        },
        {
          name: "Directives evaluated", status: "info",
          detail: directives.length ? directives.join(", ") : "(none)",
          evidence: directives.length + " parsed directive" + (directives.length === 1 ? "" : "s")
        }
      ],
      rowsTitle: "DIRECTIVE FINDINGS",
      rows: data.checks || []
    };
  }

  const grade = data.grade
    ? "GRADE " + String(data.grade).toUpperCase() + " · " + (data.score != null ? data.score : "?") + "/100 · "
    : "";
  return {
    kind: kind,
    title: kind === "headers" ? "SECURITY HEADERS" : String(toolName || "CYBERBUDDY").toUpperCase(),
    hero: grade + risk.toUpperCase(),
    risk: risk,
    meta: commonMeta.concat(caveats),
    summary: data.summary || "",
    contextTitle: "",
    context: [],
    rowsTitle: "HEADER CHECKS",
    rows: data.checks || data.findings || []
  };
}

function buildEvidenceCard(data, toolName) {
  const W = 1200;
  const pad = 48;
  const lineH = 21;
  const canvas = document.createElement("canvas");
  canvas.width = W;
  const ctx = canvas.getContext("2d");
  const mono = '13px "IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace';
  const spec = buildEvidenceCardSpec(data, toolName);

  ctx.font = mono;
  const wrapText = (text, maxW) => {
    const source = String(text == null ? "" : text).replace(/\s+/g, " ").trim();
    if (!source) return [];
    const words = source.split(" ");
    const out = [];
    let line = "";
    words.forEach((word) => {
      const next = line ? line + " " + word : word;
      if (ctx.measureText(next).width > maxW && line) {
        out.push(line);
        line = word;
      } else {
        line = next;
      }
    });
    if (line) out.push(line);
    return out;
  };

  const measureRows = (rows) => (rows || []).map((row) => ({
    row: row,
    detail: wrapText(row.detail, W - pad * 2 - 210),
    evidence: row.evidence ? wrapText(row.evidence, W - pad * 2 - 210).slice(0, 5) : []
  }));
  const measuredContext = measureRows(spec.context);
  const measuredRows = measureRows(spec.rows);
  const meta = spec.meta.map(([key, value]) => ({ key: key, lines: wrapText(value, W - pad * 2 - 160) }));
  const summary = wrapText(spec.summary, W - pad * 2);
  const rowsHeight = (items) => items.reduce((height, item) =>
    height + lineH * (1 + Math.max(1, item.detail.length) + item.evidence.length) + 15, 0);
  const H = Math.max(430,
    205 + meta.reduce((height, item) => height + lineH * Math.max(1, item.lines.length), 0) +
    (summary.length ? summary.length * lineH + 34 : 0) +
    (measuredContext.length ? 35 + rowsHeight(measuredContext) : 0) +
    (measuredRows.length ? 35 + rowsHeight(measuredRows) : 0) + 78);
  canvas.height = H;

  const C = {
    bg: "#07090d", card: "#0e121a", line: "#232a36", ink: "#eef3f8",
    ink2: "#c5ced8", faint: "#7d8798", brand: "#3ee0c2",
    high: "#ff6b7a", med: "#ffc857", low: "#3ee0a6", info: "#7aa2ff"
  };
  const statusColour = (status) => ({
    ok: C.low, protected: C.low, missing: C.high, error: C.high,
    weak: C.med, info: C.info
  }[status] || C.faint);

  ctx.fillStyle = C.bg;
  ctx.fillRect(0, 0, W, H);
  ctx.fillStyle = C.card;
  ctx.fillRect(pad - 18, pad - 18, W - (pad - 18) * 2, H - (pad - 18) * 2);
  ctx.strokeStyle = C.line;
  ctx.strokeRect(pad - 18, pad - 18, W - (pad - 18) * 2, H - (pad - 18) * 2);

  let y = pad + 12;
  ctx.fillStyle = C.brand;
  ctx.font = '600 13px "IBM Plex Mono", ui-monospace, monospace';
  ctx.fillText("CYBERBUDDY · " + spec.title, pad, y);
  y += 34;
  ctx.fillStyle = C.ink;
  ctx.font = '700 25px "Sora", system-ui, sans-serif';
  ctx.fillText(spec.hero, pad, y);
  ctx.fillStyle = spec.risk === "high" ? C.high : spec.risk === "medium" ? C.med
    : spec.risk === "low" ? C.low : C.info;
  ctx.fillRect(pad, y + 10, Math.min(W - pad * 2, ctx.measureText(spec.hero).width), 3);
  y += 41;

  ctx.font = mono;
  meta.forEach((item) => {
    ctx.fillStyle = C.faint;
    ctx.fillText(item.key, pad, y);
    ctx.fillStyle = C.ink2;
    const lines = item.lines.length ? item.lines : ["—"];
    lines.forEach((line, index) => {
      ctx.fillText(line, pad + 150, y + index * lineH);
    });
    y += lineH * lines.length;
  });

  y += 12;
  ctx.strokeStyle = C.line;
  ctx.beginPath();
  ctx.moveTo(pad, y);
  ctx.lineTo(W - pad, y);
  ctx.stroke();
  y += 25;

  if (summary.length) {
    ctx.font = mono;
    ctx.fillStyle = C.ink2;
    summary.forEach((line) => { ctx.fillText(line, pad, y); y += lineH; });
    y += 13;
  }

  const drawRows = (title, items) => {
    if (!items.length) return;
    ctx.fillStyle = C.faint;
    ctx.font = '700 11px "IBM Plex Mono", ui-monospace, monospace';
    ctx.fillText(title, pad, y);
    y += 25;
    items.forEach((item) => {
      const status = item.row.status || "info";
      ctx.fillStyle = statusColour(status);
      ctx.font = '700 11px "IBM Plex Mono", ui-monospace, monospace';
      ctx.fillText(String(status).toUpperCase(), pad, y);
      ctx.fillStyle = C.ink;
      ctx.font = '600 13px "IBM Plex Mono", ui-monospace, monospace';
      ctx.fillText(String(item.row.name || ""), pad + 110, y);
      y += lineH;
      ctx.font = mono;
      ctx.fillStyle = C.ink2;
      (item.detail.length ? item.detail : ["—"]).forEach((line) => {
        ctx.fillText(line, pad + 110, y);
        y += lineH;
      });
      ctx.fillStyle = C.faint;
      item.evidence.forEach((line) => {
        ctx.fillText(line, pad + 110, y);
        y += lineH;
      });
      y += 15;
    });
  };

  drawRows(spec.contextTitle, measuredContext);
  drawRows(spec.rowsTitle, measuredRows);

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
  wrap.innerHTML =
    '<details class="export-menu" id="exportDetails">' +
    '<summary aria-haspopup="menu">Export ' + ICONS.chevron + "</summary>" +
    '<div class="export-menu-panel" role="menu">' +
    '<button type="button" class="export-menu-item" role="menuitem" data-act="print">' +
    "Print / Save as PDF<span>Full report card, paper layout</span></button>" +
    '<button type="button" class="export-menu-item" role="menuitem" data-act="card">' +
    "Download evidence card (PNG)<span>Tool-specific evidence drawn from scan data</span></button>" +
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
  if (Array.isArray(data.checks) && Object.prototype.hasOwnProperty.call(data, "policy")) return "csp";
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
    : kind === "csp" ? "CSP Policy Auditor"
    : kind === "cors" ? "CORS Validator"
    : kind === "clickjacking" ? "Clickjacking Validator"
    : "CyberBuddy";
  const risk = (data.risk || "unknown").toUpperCase();
  const grade = data.grade ? " — Grade " + data.grade.toUpperCase() + " (" + (data.score ?? "?") + "/100)" : "";
  const lines = [
    "# CyberBuddy — " + title + " Report",
    "",
    "- **Target:** " + mdCell(redactUrlCredentials(data.url)),
    "- **Final URL:** " + mdCell(redactUrlCredentials(data.final_url || data.url)),
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
  const ok = await copyText(JSON.stringify(reportSafeCopy(data), null, 2));
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

/* ---------- Findings presentation (report-style, display-only) ---------
   The graders above are untouched: severity chips, recommendations and the
   copy-to-clipboard block are derived from the check name/status the
   engines already produce — never from new scoring — so the Python/JS
   parity contract is unaffected. */

const FINDING_FIX = {
  "Content-Security-Policy": "Serve Content-Security-Policy with a restrictive default-src 'self' (plus explicit script/style sources) and frame-ancestors 'none' or 'self'.",
  "X-Frame-Options": "Set X-Frame-Options: DENY (or SAMEORIGIN). Prefer adding CSP frame-ancestors — the modern control — alongside it.",
  "CSP frame-ancestors": "Add frame-ancestors 'none' (or 'self') to the Content-Security-Policy header.",
  "Strict-Transport-Security": "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses.",
  "X-Content-Type-Options": "Send X-Content-Type-Options: nosniff on all responses to stop MIME-sniffing.",
  "Referrer-Policy": "Set an explicit Referrer-Policy such as strict-origin-when-cross-origin.",
  "Permissions-Policy": "Ship a Permissions-Policy that restricts powerful features, e.g. camera=(), microphone=(), geolocation=(self).",
  "Cross-Origin-Opener-Policy": "Set Cross-Origin-Opener-Policy: same-origin to isolate the top-level context from cross-origin popups.",
  "Cross-Origin-Embedder-Policy": "Set Cross-Origin-Embedder-Policy: require-corp (with CORP/CORS on subresources) to enable cross-origin isolation.",
  "Cross-Origin-Resource-Policy": "Set Cross-Origin-Resource-Policy: same-origin (or same-site) to restrict which origins may load resources.",
  "Set-Cookie flags": "Add Secure; HttpOnly; SameSite=Lax (or Strict) to all session cookies.",
  "Transport": "Serve the application over HTTPS so response headers cannot be stripped or injected on the wire.",
  "Access-Control-Allow-Origin": "Never reflect arbitrary origins. Echo the caller only when it is on an explicit origin allowlist.",
  "Allow-Credentials": "Avoid Access-Control-Allow-Credentials: true unless a strict allowlist of trusted origins is enforced.",
  "Vary: Origin": "When the CORS policy varies by caller origin, send Vary: Origin so shared caches key on it.",
  "Fetch result": "Re-run the probe with the Python engine (server.py) for a two-origin reflection proof.",
  "Frame test": "Apply an effective framing control (CSP frame-ancestors or X-Frame-Options) and re-test."
};

function findingSeverity(c) {
  const s = c && c.status;
  // Dedicated graders may provide an evidence-based severity directly.
  // Existing tools omit it and continue through the display-only mapping.
  if (c && ["high", "medium", "low", "info", "pass"].includes(c.severity)) {
    return { key: c.severity, label: c.severity === "pass" ? "PASS" : c.severity.toUpperCase() };
  }
  if (s === "ok" || s === "protected") return { key: "pass", label: "PASS" };
  if (s === "info") return { key: "info", label: "INFO" };
  if (s === "error") return { key: "high", label: "HIGH" };
  const name = c && c.name ? String(c.name) : "";
  const framing = /frame/i.test(name);
  if (s === "missing") {
    if (framing) return { key: "high", label: "HIGH" };
    const w = WEIGHTS[name] || 0;
    if (w >= 15) return { key: "high", label: "HIGH" };
    if (w >= 10) return { key: "medium", label: "MEDIUM" };
    return { key: "low", label: "LOW" };
  }
  // status "weak"
  if (framing) {
    return /frame-ancestors/i.test(name)
      ? { key: "high", label: "HIGH" }
      : { key: "medium", label: "MEDIUM" };
  }
  const d = c.deduction || 0;
  if (d >= 15) return { key: "high", label: "HIGH" };
  if (d >= 10) return { key: "medium", label: "MEDIUM" };
  return { key: "low", label: "LOW" };
}

/* One shared findings-row renderer for every tool page, so a status
   chip, severity, recommendation, evidence and (where the check has a
   weight) an earned-points bar can never drift apart between tools. */
function findingRowHtml(c, opts) {
  opts = opts || {};
  const sev = findingSeverity(c);
  const ev = c.evidence ? '<code class="f-evidence">' + esc(c.evidence) + "</code>" : "";
  const needsFix = c.status === "missing" || c.status === "weak" || c.status === "error";
  const recommendation = c.recommendation || FINDING_FIX[c.name] || "";
  const fix = needsFix && recommendation
    ? '<p class="f-fix"><strong>Recommendation</strong>' + esc(recommendation) + "</p>"
    : "";
  const w = WEIGHTS[c.name] || 0;
  let weight = "";
  if (w) {
    const earned = Math.max(0, Math.min(w, w - (c.deduction || 0)));
    const pct = Math.round(100 * earned / w);
    weight = '<div class="f-weight"><span class="f-weight-bar"><i style="width:' + pct +
      '%"></i></span><span class="f-weight-label">' + earned + "/" + w + " pts</span></div>";
  }
  const copy = opts.copy
    ? '<button type="button" class="copy-finding" data-i="' + (opts.index || 0) +
      '" title="Copy this finding as report text">Copy finding</button>'
    : "";
  return "<tr><td class='k'>" + esc(c.name) + "</td><td>" +
    "<span class='f-status " + esc(c.status) + "'>" + esc(c.status) + "</span>" +
    '<span class="f-severity sev-' + sev.key + '">' + sev.label + "</span>" +
    "<div class='f-detail'>" + esc(c.detail) + "</div>" + ev + fix + weight + copy + "</td></tr>";
}

function findingCopyText(c, toolName, target) {
  const sev = findingSeverity(c);
  return [
    "CyberBuddy — " + (toolName || "finding"),
    "",
    c.name,
    "Status: " + String(c.status).toUpperCase() + " · Severity: " + sev.label,
    c.evidence ? "Evidence: " + c.evidence : "Evidence: " + c.name + " not present",
    "",
    "Recommendation:",
    c.recommendation || FINDING_FIX[c.name] || "Review the finding and remediate before re-testing.",
    "",
    "Target: " + (target || "—"),
    "Generated: " + fmtStampUtc(),
    "Authorized testing only — read-only GET."
  ].join("\n");
}

function bindFindingCopy(container, rows, toolName, target) {
  if (!container) return;
  container.querySelectorAll(".copy-finding").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const i = parseInt(btn.getAttribute("data-i") || "-1", 10);
      const row = rows[i];
      if (!row) return;
      const ok = await copyText(findingCopyText(row, toolName, target));
      if (ok) {
        const label = btn.textContent;
        btn.textContent = "Copied ✓";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = label; btn.classList.remove("copied"); }, 1400);
      }
    });
  });
}

/* Posture rollup: severity-band counts straight from the check statuses. */
function postureHtml(checks) {
  const roll = { missing: 0, weak: 0, error: 0, ok: 0, protected: 0, info: 0 };
  (checks || []).forEach((c) => {
    const s = c && c.status;
    if (roll[s] != null) roll[s]++;
    else roll.info++;
  });
  const chip = (key, label, cls) =>
    roll[key] ? '<span class="posture-chip ' + cls + '">' + label + " · " + roll[key] + "</span>" : "";
  const html =
    chip("missing", "Missing", "high") + chip("weak", "Weak", "medium") +
    chip("error", "Error", "high") + chip("ok", "OK", "low") +
    chip("protected", "Protected", "low") + chip("info", "Info", "info");
  return '<span class="posture-label">Findings</span>' +
    (html || '<span class="posture-chip info">No checks</span>');
}

/* Every result carries a LIVE / CACHED tag. The hosted site serves CI-built
   demo reports for urls.txt targets — a cached result must never be
   mistaken for a fresh scan, and the tag says which one you are reading. */
function scanTag(data) {
  if (!data || !data._source) return "";
  const cached = data._source === "cache";
  return '<span class="scan-tag ' + (cached ? "cached" : "live") + '" title="' +
    (cached
      ? "Pre-scanned demo result from the CI-built cache — not a fresh scan"
      : "Result computed during this scan") + '">' +
    (cached ? "Cached" : "Live") + "</span>";
}

function parseCsp(csp) {
  const directives = {};
  String(csp || "").replace(/[\r\n]+/g, ";").split(";").forEach((part) => {
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

/* ---------- Content-Security-Policy audit ------------------------------
   Dedicated CSP audit used by /tools/csp/. This is a pure grader: the
   Python API, published cache and browser fallback all feed it the same
   header map, and tests/csp_fixtures.json locks the two implementations
   together. No synthetic numeric score is invented for CSP. */

const CSP_SUGGESTED_POLICY =
  "default-src 'self'; base-uri 'self'; object-src 'none'; " +
  "frame-ancestors 'none'; form-action 'self'; script-src 'self'; " +
  "style-src 'self'; img-src 'self' data:; font-src 'self'; " +
  "connect-src 'self'; upgrade-insecure-requests";

function splitCspPolicies(value) {
  return String(value || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function parseCspPolicy(value) {
  const directives = {};
  const duplicates = [];
  String(value || "").split(";").forEach((raw) => {
    const tokens = raw.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) return;
    const name = tokens.shift().toLowerCase();
    if (Object.prototype.hasOwnProperty.call(directives, name)) {
      duplicates.push(name);
      return;
    }
    directives[name] = tokens.map((token) => token.toLowerCase());
  });
  return { directives: directives, duplicates: duplicates };
}

function cspFinding(name, status, detail, evidence, severity, recommendation) {
  return {
    name: name,
    status: status,
    detail: detail,
    evidence: evidence || "",
    severity: severity || "info",
    recommendation: recommendation || ""
  };
}

function cspEffective(directives, names) {
  for (let i = 0; i < names.length; i++) {
    if (Object.prototype.hasOwnProperty.call(directives, names[i])) {
      return { tokens: directives[names[i]], from: names[i] };
    }
  }
  return { tokens: null, from: "" };
}

function cspTrustToken(token) {
  return ["'nonce-", "'sha256-", "'sha384-", "'sha512-"].some((prefix) =>
    String(token).startsWith(prefix));
}

function cspSourceLabel(name, tokens) {
  if (tokens == null) return "not set";
  return name + (tokens.length ? " " + tokens.join(" ") : " (empty source list)");
}

function cspIssueFinding(name, issues, evidence, recommendation, okDetail, info) {
  if (issues.length) {
    const order = { low: 1, medium: 2, high: 3 };
    const severity = issues.reduce((worst, issue) =>
      (order[issue[1]] || 0) > (order[worst] || 0) ? issue[1] : worst, "low");
    return cspFinding(name, "weak", issues.map((issue) => issue[0]).join("; ") + ".",
      evidence, severity, recommendation);
  }
  if (info && info.length) {
    return cspFinding(name, "info", okDetail + " " + info.join(" "), evidence, "info");
  }
  return cspFinding(name, "ok", okDetail, evidence, "pass");
}

function cspCheckScripts(directives) {
  const element = cspEffective(directives, ["script-src-elem", "script-src", "default-src"]);
  const evaluation = cspEffective(directives, ["script-src", "default-src"]);
  const attributes = cspEffective(directives, ["script-src-attr", "script-src", "default-src"]);
  const fix = "Restrict script-src to trusted hosts or, preferably, per-response nonces/hashes. " +
    "Remove wildcards, data:, 'unsafe-eval', and unprotected 'unsafe-inline'.";
  if (element.tokens == null) {
    return cspFinding("Script execution", "missing",
      "No script-src, script-src-elem, or default-src fallback; script loading is unrestricted.",
      "", "high", fix);
  }

  const sources = new Set(element.tokens);
  const issues = [];
  const info = [];
  const hasTrust = Array.from(sources).some(cspTrustToken);
  if (sources.has("*")) issues.push(["the effective script source allows * (any matching origin)", "high"]);
  if (sources.has("data:")) issues.push(["the effective script source allows data: scripts", "high"]);
  if (sources.has("http:") || Array.from(sources).some((token) => token.startsWith("http://"))) {
    issues.push(["the effective script source allows cleartext HTTP", "high"]);
  }
  if (sources.has("https:")) {
    issues.push(["the effective script source allows scripts from any HTTPS origin", "medium"]);
  }
  if (Array.from(sources).some((token) => token.startsWith("*.") || token.includes("://*.") )) {
    issues.push(["the effective script source trusts a wildcard subdomain", "medium"]);
  } else if (Array.from(sources).some((token) => token.includes("://*"))) {
    issues.push(["the effective script source trusts a wildcard host", "medium"]);
  }
  if (sources.has("'unsafe-inline'")) {
    if (hasTrust) {
      info.push("'unsafe-inline' is ignored by modern nonce/hash-aware browsers and acts only as a legacy fallback.");
    } else {
      issues.push(["'unsafe-inline' permits inline script execution", "high"]);
    }
  }

  const evalTokens = new Set(evaluation.tokens || []);
  if (evalTokens.has("'unsafe-eval'")) issues.push(["'unsafe-eval' permits string-to-code execution", "high"]);
  if (evalTokens.has("'wasm-unsafe-eval'")) {
    issues.push(["'wasm-unsafe-eval' permits WebAssembly compilation from bytes", "medium"]);
  }
  const attrTokens = new Set(attributes.tokens || []);
  if (attributes.from === "script-src-attr" && attrTokens.has("'unsafe-inline'")) {
    issues.push(["script-src-attr 'unsafe-inline' permits inline event handlers", "high"]);
  }
  if (sources.has("'strict-dynamic'") && !hasTrust) {
    issues.push(["'strict-dynamic' has no nonce or hash trust anchor", "medium"]);
  }
  if (sources.has("'none'") && sources.size > 1) {
    issues.push(["'none' is mixed with other script sources and is ignored", "medium"]);
  }

  const evidence = [cspSourceLabel(element.from, element.tokens)];
  if (evaluation.from && evaluation.from !== element.from) {
    evidence.push(cspSourceLabel(evaluation.from, evaluation.tokens));
  }
  if (attributes.from && attributes.from !== element.from && attributes.from !== evaluation.from) {
    evidence.push(cspSourceLabel(attributes.from, attributes.tokens));
  }
  return cspIssueFinding("Script execution", issues, evidence.join(" · "), fix,
    "Script execution has an explicit restrictive source list.", info);
}

function cspCheckStyles(directives) {
  const effective = cspEffective(directives, ["style-src", "default-src"]);
  const fix = "Set style-src to required origins only. Prefer nonces or hashes for inline styles; " +
    "remove *, data:, cleartext HTTP, and 'unsafe-inline' where the application permits.";
  if (effective.tokens == null) {
    return cspFinding("Style sources", "missing",
      "No style-src or default-src fallback; stylesheet loading is unrestricted.", "", "medium", fix);
  }
  const sources = new Set(effective.tokens);
  const issues = [];
  if (sources.has("*")) issues.push(["the effective style source allows *", "medium"]);
  if (sources.has("data:")) issues.push(["the effective style source allows data:", "low"]);
  if (sources.has("http:") || Array.from(sources).some((token) => token.startsWith("http://"))) {
    issues.push(["the effective style source allows cleartext HTTP", "medium"]);
  }
  if (sources.has("'unsafe-inline'") && !Array.from(sources).some(cspTrustToken)) {
    issues.push(["'unsafe-inline' permits arbitrary inline CSS", "medium"]);
  }
  if (sources.has("'none'") && sources.size > 1) {
    issues.push(["'none' is mixed with other style sources and is ignored", "low"]);
  }
  return cspIssueFinding("Style sources", issues,
    cspSourceLabel(effective.from, effective.tokens), fix,
    "Stylesheets have an explicit restrictive source list.");
}

function cspCheckObject(directives) {
  const effective = cspEffective(directives, ["object-src", "default-src"]);
  const fix = "Set object-src 'none' to disable legacy plugin/object embedding.";
  if (effective.tokens == null) {
    return cspFinding("Object embedding", "missing",
      "No object-src or default-src fallback; object/embed content is unrestricted.", "", "medium", fix);
  }
  const evidence = cspSourceLabel(effective.from, effective.tokens);
  if (!effective.tokens.length || (effective.tokens.length === 1 && effective.tokens[0] === "'none'")) {
    return cspFinding("Object embedding", "ok", "Object/embed loading is blocked.", evidence, "pass");
  }
  return cspFinding("Object embedding", "weak",
    "Object/embed content is still allowed. CSP hardening guidance recommends blocking it.",
    evidence, "medium", fix);
}

function cspCheckNavigation(directives, name, label, missingSeverity, recommendation) {
  if (!Object.prototype.hasOwnProperty.call(directives, name)) {
    return cspFinding(label, "missing", name + " is absent and is not inherited from default-src.",
      "", missingSeverity, recommendation);
  }
  const tokens = directives[name];
  const evidence = cspSourceLabel(name, tokens);
  if (!tokens.length || (tokens.length === 1 && (tokens[0] === "'none'" || tokens[0] === "'self'"))) {
    return cspFinding(label, "ok", name + " uses a restrictive source list.", evidence, "pass");
  }
  const issues = [];
  if (tokens.includes("*")) {
    issues.push([name + " allows *", name === "frame-ancestors" ? "high" : "medium"]);
  }
  if (tokens.some((token) => token === "http:" || token === "https:")) {
    issues.push([name + " allows every origin on a URL scheme", "medium"]);
  }
  if (tokens.includes("'none'") && tokens.length > 1) {
    issues.push([name + " mixes 'none' with other sources, so 'none' is ignored", "medium"]);
  }
  if (issues.length) return cspIssueFinding(label, issues, evidence, recommendation, "");
  return cspFinding(label, "ok",
    name + " has an explicit allowlist; verify each origin is required and trusted.", evidence, "pass");
}

function cspCheckMixed(directives, finalUrl) {
  let protocol = "";
  try { protocol = new URL(finalUrl).protocol; } catch (_) { /* leave empty */ }
  if (protocol !== "https:") {
    return cspFinding("Mixed-content control", "weak",
      "The final page is delivered over HTTP, so the CSP itself can be stripped or modified in transit.",
      finalUrl, "high",
      "Serve the page over HTTPS, then use upgrade-insecure-requests while migrating legacy HTTP resources.");
  }
  if (Object.prototype.hasOwnProperty.call(directives, "upgrade-insecure-requests") ||
      Object.prototype.hasOwnProperty.call(directives, "block-all-mixed-content")) {
    const name = Object.prototype.hasOwnProperty.call(directives, "upgrade-insecure-requests")
      ? "upgrade-insecure-requests" : "block-all-mixed-content";
    return cspFinding("Mixed-content control", "ok", name + " is present.", name, "pass");
  }
  const insecure = Object.keys(directives).filter((name) => {
    if (name === "report-uri" || name === "report-to") return false;
    const tokens = directives[name];
    return tokens.includes("http:") || tokens.some((token) => token.startsWith("http://"));
  }).sort();
  if (insecure.length) {
    return cspFinding("Mixed-content control", "weak",
      "Cleartext HTTP sources appear in: " + insecure.join(", ") + ".",
      insecure.join("; "), "medium",
      "Remove HTTP source expressions or add upgrade-insecure-requests during migration.");
  }
  return cspFinding("Mixed-content control", "ok",
    "No explicit cleartext HTTP sources were found.", "", "pass");
}

function auditOneCspPolicy(directives, finalUrl) {
  const checks = [
    cspCheckScripts(directives),
    cspCheckStyles(directives),
    cspCheckObject(directives),
    cspCheckNavigation(directives, "base-uri", "Base URL control", "medium",
      "Set base-uri 'self' (or 'none') to prevent injected <base> tags from rewriting relative URLs."),
    cspCheckNavigation(directives, "frame-ancestors", "Framing control", "medium",
      "Set frame-ancestors 'none' or 'self' in the response header. This directive does not work in a meta CSP."),
    cspCheckNavigation(directives, "form-action", "Form submissions", "low",
      "Set form-action 'self' or a narrow allowlist so injected forms cannot submit to arbitrary origins."),
    cspCheckMixed(directives, finalUrl)
  ];
  if (directives["require-trusted-types-for"] &&
      directives["require-trusted-types-for"].includes("'script'")) {
    checks.push(cspFinding("Trusted Types", "ok", "DOM XSS sinks require Trusted Types.",
      "require-trusted-types-for 'script'", "pass"));
  } else {
    checks.push(cspFinding("Trusted Types", "info",
      "Trusted Types is not required. This is optional defense-in-depth for DOM XSS sinks.",
      "", "info"));
  }
  return checks;
}

function cspIssueRank(check) {
  if (check.status !== "missing" && check.status !== "weak" && check.status !== "error") {
    return [0, check.status === "ok" ? 0 : 1];
  }
  return [{ low: 1, medium: 2, high: 3 }[check.severity] || 1, 0];
}

function compareCspRank(a, b) {
  const ar = cspIssueRank(a), br = cspIssueRank(b);
  return ar[0] - br[0] || ar[1] - br[1];
}

function combineCspPolicyChecks(perPolicy) {
  if (perPolicy.length === 1) return perPolicy[0];
  return perPolicy[0].map((_, index) => {
    const candidates = perPolicy.map((checks) => checks[index]);
    const best = candidates.slice().sort(compareCspRank)[0];
    const copy = Object.assign({}, best);
    if (candidates.some((candidate) => compareCspRank(candidate, best) > 0)) {
      copy.detail += " Multiple enforced policies combine; another policy supplies this restriction.";
    }
    return copy;
  });
}

function gradeCspFromMap(url, status, finalUrl, headers, source) {
  const normalized = {};
  Object.keys(headers || {}).forEach((key) => { normalized[String(key).toLowerCase()] = String(headers[key]); });
  const policy = (normalized["content-security-policy"] || "").trim();
  const reportOnly = (normalized["content-security-policy-report-only"] || "").trim();
  const policies = splitCspPolicies(policy);
  const final = finalUrl || url;
  const checks = [];
  let directives = {};
  let perPolicy = [];

  if (!policies.length) {
    let detail = "No enforced Content-Security-Policy response header was found.";
    if (reportOnly) detail += " A Report-Only policy records violations but does not block them.";
    checks.push(cspFinding("Enforced response policy", "missing", detail, "", "high",
      "Serve an enforced Content-Security-Policy HTTP response header. Start with the suggested policy and tailor sources before deployment."));
    perPolicy = [auditOneCspPolicy({}, final)];
  } else {
    const parsed = policies.map(parseCspPolicy);
    directives = parsed[0].directives;
    let https = false;
    try { https = new URL(final).protocol === "https:"; } catch (_) { /* false */ }
    checks.push(cspFinding("Enforced response policy", https ? "ok" : "weak",
      "Found " + policies.length + " enforced CSP response " +
      (policies.length === 1 ? "policy." : "policies. Multiple policies combine restrictively."),
      policy.slice(0, 500), https ? "pass" : "high",
      https ? "" : "Serve the page and its CSP over HTTPS so the policy cannot be stripped in transit."));
    const duplicates = Array.from(new Set(parsed.flatMap((item) => item.duplicates))).sort();
    if (duplicates.length) {
      checks.push(cspFinding("Policy syntax", "weak",
        "Duplicate directives found; browsers use the first occurrence and ignore later ones: " +
        duplicates.join(", ") + ".", duplicates.join(", "), "medium",
        "Remove duplicate directives and merge intended source lists into the first occurrence."));
    } else {
      checks.push(cspFinding("Policy syntax", "ok", "No duplicate directives were found.", "", "pass"));
    }
    perPolicy = parsed.map((item) => auditOneCspPolicy(item.directives, final));
  }
  checks.push.apply(checks, combineCspPolicyChecks(perPolicy));

  if (reportOnly) {
    checks.push(cspFinding("Report-only policy", "info",
      "A Report-Only policy is present. It reports violations but does not enforce restrictions.",
      reportOnly.slice(0, 500), "info"));
  }
  let reporting = null;
  let reportingName = "";
  if (directives["report-to"] && directives["report-to"].length) {
    reporting = directives["report-to"];
    reportingName = "report-to";
  } else if (directives["report-uri"] && directives["report-uri"].length) {
    reporting = directives["report-uri"];
    reportingName = "report-uri";
  }
  if (reporting) {
    checks.push(cspFinding("Violation reporting", "ok",
      "The policy declares a violation reporting destination. Confirm the endpoint is monitored and does not receive sensitive URL data.",
      reportingName + " " + reporting.join(" "), "pass"));
  } else {
    checks.push(cspFinding("Violation reporting", "info",
      "No CSP reporting destination is configured. Reporting is optional but helps detect breakage and attacks.",
      "", "info"));
  }

  const issueOrder = { low: 1, medium: 2, high: 3 };
  const worst = checks.reduce((level, item) => {
    if (!["missing", "weak", "error"].includes(item.status)) return level;
    return Math.max(level, issueOrder[item.severity] || 0);
  }, 0);
  const risk = worst >= 3 ? "high" : worst === 2 ? "medium" : "low";
  const actionable = checks.filter((item) => ["missing", "weak", "error"].includes(item.status)).length;
  let summary = "";
  if (risk === "high") {
    summary = "High-risk CSP gaps found (" + actionable + " actionable finding" +
      (actionable === 1 ? "" : "s") + "). Prioritize script execution and policy delivery.";
  } else if (risk === "medium") {
    summary = "CSP is enforced but has " + actionable + " hardening gap" +
      (actionable === 1 ? "" : "s") + ". Review the findings before relying on it for XSS defense-in-depth.";
  } else {
    summary = "No obvious exploitable CSP source pattern was found. Validate the policy in report-only mode against real application flows before tightening it further.";
  }
  const interesting = {};
  ["content-security-policy", "content-security-policy-report-only"].forEach((key) => {
    if (Object.prototype.hasOwnProperty.call(normalized, key)) interesting[key] = normalized[key];
  });
  return {
    url: url,
    final_url: final,
    status_code: status,
    checks: checks,
    risk: risk,
    summary: summary,
    policy: policy,
    report_only_policy: reportOnly,
    directives: directives,
    suggested_policy: CSP_SUGGESTED_POLICY,
    headers: interesting,
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
  if (xfoOk) {
    return ["low", "Framing is prevented by X-Frame-Options in current browsers. Add CSP frame-ancestors as modern defense-in-depth, but its absence does not make this protected response a medium-risk outcome."];
  }
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
    const repeatable = k === "set-cookie" || k === "content-security-policy" ||
      k === "content-security-policy-report-only";
    if (repeatable && headers[k]) headers[k] += "\n" + m[2];
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
/* Concurrent scans of the same URL (the hub suite runs every tool at once)
   share one lookup, and repeat scans reuse a 10-minute local cache —
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
  // A cached RELAY read is still relayed data: keep the relay source so the
  // report stays flagged `unverified` instead of claiming "this browser"
  // read the headers first-hand on the second scan within the TTL.
  if (cached) {
    return Object.assign({}, cached, {
      source: cached.source === "relay" ? "relay-cached" : "cache-lookup"
    });
  }
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

async function gradeCspLive(url) {
  const looked = await lookupHeadersLive(url);
  if (!looked) {
    return {
      url: url, final_url: url, status_code: null,
      checks: [cspFinding("request", "error", "Could not read CSP response headers from this hosted page. The target may be unreachable, the lookup may have been declined or rate-limited, or the Python engine is offline.", "", "high")],
      risk: "unknown",
      summary: "No CSP header data. Run python3 server.py for a same-origin scan, or retry.",
      policy: "", report_only_policy: "", directives: {},
      suggested_policy: CSP_SUGGESTED_POLICY, headers: {}, _source: "none"
    };
  }
  return gradeCspFromMap(
    url,
    looked.status_code,
    looked.final_url || url,
    looked.headers,
    looked.source
  );
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

function browserCorsRisk(acao, acac) {
  // A single browser Origin cannot establish reflection. The only measured
  // misconfiguration promoted here is the invalid wildcard+credentials pair.
  return acao === "*" && String(acac || "").trim().toLowerCase() === "true"
    ? "medium" : "low";
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
    // One browser Origin cannot prove arbitrary reflection. Keep a missing
    // Vary recommendation on its own row, but do not promote that secondary
    // cache gap into a measured MEDIUM CORS outcome.
    return {
      url: url, final_url: res.url || url, status_code: status,
      checks: checks,
      risk: browserCorsRisk(acao, acac),
      summary: "HTTP " + status + " from this browser origin (" + origin + "). Single-origin probe only — use server.py for a genuine two-origin reflection proof.",
      headers: {
        "access-control-allow-origin": acao || "",
        "access-control-allow-credentials": acac || "",
        "vary": vary || ""
      },
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
  initUrlInput(input);

  let lastSuite = null;
  const toolbar = document.getElementById("suiteToolbar");
  const shareBtn = document.getElementById("suiteShare");
  const copyBtn = document.getElementById("suiteCopy");

  async function run() {
    const url = validateUrlField(input);
    if (!url) return;
    pushUrlParam(url);
    addRecentScan(url);
    renderRecentScans();
    setLoading(go, true);
    out.classList.remove("hidden");
    if (toolbar) toolbar.classList.add("hidden");

    out.innerHTML = pipelineHtml(url);
    const setStage = pipelineController(out.querySelector(".scan-pipeline"));
    setStage("normalize", "done");

    // Engine detection ran at page load; surface its verdict as a stage so
    // the analyst sees WHICH engine will answer before the scan proceeds.
    let engineNote = "browser engine — hosted Pages mode";
    try {
      const eng = await Promise.resolve(window.__cbEngineReady);
      if (eng && eng.online) engineNote = "python engine online — same-origin scan";
    } catch (_) { /* keep default */ }
    setStage("engine", "done", engineNote);

    // Ask before anything can reach a third-party relay. Without this the
    // hub silently degraded to "no header data" for every target on the
    // hosted site, with no way for the analyst to opt in.
    const consent = await ensureRelayConsent(url);
    if (consent === "deny") {
      setStage("consent", "failed", "declined — header grading skipped");
      out.insertAdjacentHTML("beforeend",
        '<div class="notice"><h3>Relay lookups declined</h3>' +
        "<p>Header grading needs either a local <code>server.py</code> or a " +
        "third-party relay. Run the Clickjacking tool for a frame-based visual " +
        "proof that needs neither, or start <code>python3 server.py</code> for " +
        "a full scan that never leaves your machine.</p></div>");
      setLoading(go, false);
      return;
    }
    setStage("consent", consent === "skip" ? "skipped" : "done",
      consent === "skip" ? "not needed — engine-side fetch" : "approved for this session");

    setStage("collect", "active", "headers · CSP · CORS · framing — read-only GETs");
    // CSP needs the same response fields as Security Headers. Reuse that
    // result in the suite instead of sending a duplicate GET to the target.
    const headersTask = apiHeaders(url).catch(() => null);
    const cspTask = headersTask.then((headersResult) => {
      if (headersResult && headersResult.status_code != null && headersResult.headers) {
        const cspResult = gradeCspFromMap(
          url,
          headersResult.status_code,
          headersResult.final_url || url,
          headersResult.headers,
          headersResult._source || "live"
        );
        cspResult._cached_at = headersResult._cached_at || "";
        return cspResult;
      }
      if (headersResult && headersResult._unreachable) {
        return markUnreachable({
          url: headersResult.url,
          final_url: headersResult.final_url,
          status_code: null,
          checks: headersResult.checks || [],
          risk: "unknown",
          summary: headersResult.summary || "Target not reachable.",
          policy: "",
          report_only_policy: "",
          directives: {},
          suggested_policy: CSP_SUGGESTED_POLICY,
          headers: {}
        }, headersResult._source);
      }
      return apiCsp(url).catch(() => null);
    });
    const [cj, hd, cr, cp] = await Promise.all([
      apiScan(url).catch(() => null),
      headersTask,
      apiCors(url).catch(() => null),
      cspTask
    ]);
    setStage("collect", "done");
    setStage("evaluate", "done", "OWASP-aligned checks applied");

    lastSuite = { url: url, clickjacking: cj, headers: hd, cors: cr, csp: cp };
    const base = appBase();
    out.innerHTML = suiteSummaryHtml(lastSuite, engineNote) +
      '<div class="suite-grid">' +
      suiteCard("Clickjacking", cj, "findings", base + "/tools/clickjacking/?url=" + encodeURIComponent(url)) +
      suiteCard("Headers", hd, "checks", base + "/tools/headers/?url=" + encodeURIComponent(url)) +
      suiteCard("CORS", cr, "checks", base + "/tools/cors/?url=" + encodeURIComponent(url)) +
      suiteCard("CSP", cp, "checks", base + "/tools/csp/?url=" + encodeURIComponent(url)) +
      "</div>";
    addRecentScan(url, recentScanSummary(lastSuite));
    renderRecentScans();
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
        toMarkdown(lastSuite.cors),
        "",
        toMarkdown(lastSuite.csp)
      ];
      const ok = await copyText(parts.join("\n"));
      flashBtn(copyBtn, ok, "Suite copied ✓");
    });
  }
  initSuggestedTargets();
  const initial = new URLSearchParams(location.search).get("url");
  if (initial) {
    input.value = initial;
    if (validateUrlField(input, false)) run();
  }
}

/* ---------- Scan pipeline ----------------------------------------------
   The hub renders the real stages a suite run passes through instead of a
   bare "Scanning…" spinner: normalize → engine → consent → collect →
   evaluate → report. Progress is stage-based (never a fake byte count). */

const PIPELINE_STAGES = [
  { id: "normalize", label: "Normalize URL" },
  { id: "engine", label: "Detect engine" },
  { id: "consent", label: "Relay consent" },
  { id: "collect", label: "Collect evidence" },
  { id: "evaluate", label: "Evaluate & score" },
  { id: "report", label: "Evidence report" }
];

function pipelineHtml(target) {
  return '<div class="scan-pipeline" role="status" aria-live="polite">' +
    '<div class="sp-head"><span class="sp-target">' + esc(target) + "</span>" +
    '<span class="sp-stage-num" data-role="count">stage 1 / ' + PIPELINE_STAGES.length + "</span></div>" +
    '<ol class="sp-stages">' +
    PIPELINE_STAGES.map((s) =>
      '<li class="sp-stage pending" data-stage="' + s.id + '">' +
      '<span class="sp-ico" aria-hidden="true">○</span>' +
      '<span class="sp-body"><span class="sp-label">' + s.label + '</span>' +
      '<span class="sp-note" data-role="note"></span></span></li>'
    ).join("") +
    "</ol>" +
    '<div class="sp-progress" aria-hidden="true"><span data-role="fill" style="width: 0%"></span></div>' +
    "</div>";
}

function pipelineController(root) {
  if (!root) return function () {};
  const order = PIPELINE_STAGES.map((s) => s.id);
  const state = {};
  const icons = { pending: "○", active: "●", done: "✓", skipped: "—", failed: "✕" };
  return function set(id, st, note) {
    state[id] = st;
    const li = root.querySelector('.sp-stage[data-stage="' + id + '"]');
    if (li) {
      li.classList.remove("pending", "active", "done", "skipped", "failed");
      li.classList.add(st);
      const ico = li.querySelector(".sp-ico");
      if (ico) ico.textContent = icons[st] || "○";
      const noteEl = li.querySelector(".sp-note");
      if (noteEl) noteEl.textContent = note ? "· " + note : "";
    }
    const done = order.filter((o) => state[o] === "done" || state[o] === "skipped").length;
    const fill = root.querySelector('[data-role="fill"]');
    if (fill) fill.style.width = Math.round(100 * done / order.length) + "%";
    const count = root.querySelector('[data-role="count"]');
    if (count) count.textContent = "stage " + Math.min(order.length, done + 1) + " / " + order.length;
  };
}

/* ---------- Suite summary ----------------------------------------------
   One honest headline per run: worst-case risk across the four scan tools
   (the CSRF PoC Generator is a generator, not a scanner, so it is not part
   of this suite), the headers score as the only numeric gauge, and per-tool
   chips. There is no invented aggregate score — clickjacking, CORS and CSP
   have no shared numeric scale, so they are shown as risks, never as a fake
   /100. */

const RISK_ORDER = { high: 3, medium: 2, low: 1, unknown: 0 };

function worstSuiteTool(s) {
  const ds = [
    ["Clickjacking", s.clickjacking],
    ["Security Headers", s.headers],
    ["CORS", s.cors],
    ["CSP", s.csp]
  ].filter((d) => d[1]);
  if (!ds.length) return null;
  return ds.reduce((w, d) =>
    (RISK_ORDER[d[1].risk] || 0) > (RISK_ORDER[w[1].risk] || 0) ? d : w);
}

/* Minimal digest stored next to the recent-scan URL (localStorage, 24h TTL,
   cleared by "Clear history") so chips can show the last grade without
   persisting full scan JSON. */
function recentScanSummary(s) {
  const out = {};
  ["clickjacking", "cors", "csp"].forEach((k) => {
    if (s[k] && s[k].risk) out[k] = { risk: s[k].risk };
  });
  if (s.headers && s.headers.grade) {
    out.headers = {
      grade: s.headers.grade,
      score: s.headers.score != null ? s.headers.score : null
    };
  }
  return out;
}

function suiteToolChip(label, data, withScore) {
  if (!data) return '<span class="suite-tool-chip unknown">' + esc(label) + " —</span>";
  const risk = (data.risk || "unknown").toLowerCase();
  let text = esc(label) + " · <b>" + esc((data.risk || "unknown").toUpperCase()) + "</b>";
  if (withScore && data.score != null) text += " · <b>" + esc(String(data.score)) + "/100</b>";
  if (data.grade) text += " · <b>" + esc(String(data.grade).toUpperCase()) + "</b>";
  return '<span class="suite-tool-chip ' + esc(risk) + '">' + text + "</span>";
}

function suiteSummaryHtml(s, engineNote) {
  const hd = s.headers;
  const worst = worstSuiteTool(s);
  const gauge = hd && hd.score != null
    ? gaugeHtml(hd.score, hd.grade, true)
    : '<div class="score-gauge gauge-f"><svg viewBox="0 0 120 120" aria-hidden="true">' +
      '<circle class="gauge-track" cx="60" cy="60" r="52" pathLength="100"/>' +
      '<text class="gauge-num" x="60" y="58" style="font-size:15px">no</text>' +
      '<text class="gauge-num" x="60" y="76" style="font-size:15px">data</text>' +
      '</svg><span class="gauge-band">headers unavailable</span></div>';
  const verdict = worst
    ? '<span class="risk ' + esc(worst[1].risk || "unknown") + '">' +
      esc((worst[1].risk || "unknown").toUpperCase()) + "</span>" +
      '<span class="suite-summary-worst">worst-case risk across the four scan tools — ' +
      esc(worst[0]) + "</span>"
    : '<span class="risk unknown">UNKNOWN</span>' +
      '<span class="suite-summary-worst">no tool returned a result</span>';
  const chips =
    suiteToolChip("Clickjacking", s.clickjacking, false) +
    suiteToolChip("Headers", s.headers, true) +
    suiteToolChip("CORS", s.cors, false) +
    suiteToolChip("CSP", s.csp, false);
  return '<div class="suite-summary">' +
    '<div class="suite-summary-gauge">' + gauge + "</div>" +
    '<div class="suite-summary-body">' +
    '<p class="card-title">Assessment of ' + esc(s.url) + "</p>" +
    '<div class="suite-summary-verdict">' + verdict + "</div>" +
    '<div class="suite-summary-tools">' + chips + "</div>" +
    '<p class="suite-src">' + esc(engineNote || "") + " · evidence-grade output · read-only GETs</p>" +
    "</div></div>";
}

function suiteCard(title, data, listKey, href) {
  if (!data) {
    return '<article class="card suite-card"><p class="card-title">' + esc(title) +
      '</p><span class="risk unknown">UNAVAILABLE</span><p class="verdict-text">No result.</p></article>';
  }
  if (data._unreachable) {
    return '<article class="card suite-card">' +
      '<div class="suite-card-top"><p class="card-title">' + esc(title) + '</p>' +
      '<span class="suite-tags">' + scanTag(data) +
      '<span class="risk unreachable">UNREACHABLE</span></span></div>' +
      '<p class="verdict-text">Target did not respond — ' + esc(unreachableDetail(data)) + '</p>' +
      '<p class="suite-src" title="' + esc(sourceExplain(data)) + '">via ' + esc(sourceLabel(data)) + '</p>' +
      '<a class="tool-card-open" href="' + href + '">Open full report ' + ICONS.chevron + '</a></article>';
  }
  const risk = (data.risk || "unknown").toLowerCase();
  const grade = data.grade ? '<span class="grade ' + gradeFor(data.score) + '">' + esc(data.grade) + "</span>" : "";
  const items = (data[listKey] || []).slice(0, 3).map((c) =>
    '<li><span class="f-status ' + esc(c.status) + '">' + esc(c.status) + "</span> " + esc(c.name) + "</li>"
  ).join("");
  return '<article class="card suite-card">' +
    '<div class="suite-card-top"><p class="card-title">' + esc(title) + '</p>' +
    '<span class="suite-tags">' + scanTag(data) +
    '<span class="risk ' + esc(risk) + '">' + esc((data.risk || "unknown").toUpperCase()) + "</span></span></div>" +
    '<div class="suite-card-body">' + grade +
    '<p class="verdict-text">' + esc(data.summary || "") + "</p></div>" +
    (items ? "<ul class=\"suite-list\">" + items + "</ul>" : "") +
    '<p class="suite-src" title="' + esc(sourceExplain(data)) + '">via ' + esc(sourceLabel(data)) + "</p>" +
    '<a class="tool-card-open" href="' + href + '">Open full report ' + ICONS.chevron + "</a></article>";
}

/* ---------- Tool chrome ------------------------------------------------- */

const SOURCE_EXPLAIN = {
  python: "The Python engine answered — server-side scan with complete evidence.",
  cache: "Pre-scanned demo target served from the CI-built cache — not a fresh scan.",
  relay: "Header values proxied by a third-party relay — not independently verified.",
  browser: "Graded in this browser from a direct read of the target.",
  "cache-lookup": "Reused this browser's 10-minute header cache from an earlier scan.",
  "relay-cached": "Relayed header values reused from this browser's 10-minute cache — still not independently verified.",
  none: "No engine answered this scan."
};

function sourceExplain(data) {
  const s = data && data._source;
  return SOURCE_EXPLAIN[s] || "Where this result came from.";
}

function setSourceChip(data) {
  const el = document.getElementById("sourceChip");
  if (!el) return;
  el.textContent = "via " + sourceLabel(data);
  el.title = sourceExplain(data);
  el.classList.remove("hidden");
}

/* ---------- Relay consent gate -----------------------------------------
   Shown before the first scan that would need a public relay. Rendered
   into #relayGate on each tool page (and the hub). Resolves once the
   analyst chooses, so the scan can continue or abort. */

async function relayGateNeeded(url) {
  // Wait for engine detection to settle before deciding.
  try { await window.__cbEngineReady; } catch (_) { /* fall through */ }
  // Python engine present? Then relays are never reached.
  if (window.__cbEngine && window.__cbEngine.mode === "python") return false;
  // A fresh same-origin Pages report also answers without disclosing the
  // target to a relay. This keeps all cached demo tools usable immediately.
  if (url) {
    try {
      const cached = await cachedReportFor(url);
      if (cached) return false;
    } catch (_) { /* absent cache — consent may be needed */ }
  }
  return !relayConsent();
}

function renderRelayGate() {
  const wrap = document.getElementById("relayGate");
  if (!wrap) return Promise.resolve("skip");
  wrap.classList.remove("hidden");
  // Every option spells out what leaves the browser, what comes back, and
  // what it costs. Reviewers reported the old three-button row read as
  // "already answered" because one button was styled btn-primary — none of
  // them is preselected now, and each carries its own explanation rather
  // than a tooltip nobody hovers.
  const option = (mode, label, rec, what, sends, gets) =>
    '<button type="button" class="relay-option" data-consent="' + mode + '">' +
    '<span class="relay-option-head"><span class="relay-option-label">' + label + "</span>" +
    (rec ? '<span class="relay-option-rec">Recommended</span>' : "") + "</span>" +
    '<span class="relay-option-what">' + what + "</span>" +
    '<span class="relay-option-meta"><span><strong>Sends:</strong> ' + sends + "</span>" +
    '<span><strong>You get:</strong> ' + gets + "</span></span></button>";

  wrap.innerHTML =
    '<div class="relay-consent" role="alertdialog" aria-labelledby="relayGateTitle" aria-describedby="relayGateBody" tabindex="-1">' +
    '<div class="relay-consent-head">' +
    '<span class="relay-consent-badge">Action needed</span>' +
    '<h3 id="relayGateTitle">Choose how to read this target\u2019s headers</h3>' +
    "</div>" +
    '<div id="relayGateBody">' +
    '<p class="relay-consent-lead"><strong>The scan is paused until you pick one of the three options below.</strong> ' +
    "This hosted page has no local engine, so it cannot read cross-origin response " +
    "headers on its own.</p>" +
    "<p>To grade them it would proxy the request through public services, which " +
    "discloses what you are testing to operators outside your engagement " +
    "(<code>" + RELAY_HOSTS.join("</code>, <code>") + "</code>). They would see the " +
    "target and your IP address, and many assessment NDAs prohibit that. For a " +
    "fully private scan, stop and run <code>python3 server.py</code> locally instead.</p>" +
    "</div>" +
    '<div class="relay-consent-actions" role="group" aria-label="Relay options">' +
    option("host", "Allow \u2014 hostname only", true,
      "Proxies <em>only</em> the hostname. Best balance of evidence and privacy, and enough for almost every header check \u2014 CSP, HSTS, X-Frame-Options and the cookie/isolation family are all set per origin.",
      "<code>example.com</code>", "A full A\u2013F header grade, flagged <em>unverified</em>") +
    option("full", "Allow \u2014 full URL", false,
      "Also proxies the path and query string. Only needed when headers differ per path (a login route, a tenant-specific page). This is the option most likely to leak a token or customer ID from a URL.",
      "<code>example.com/admin?token=\u2026</code>", "Same grade, scoped to that exact URL") +
    option("deny", "No \u2014 do not use relays", false,
      "Nothing is sent to any third party. Header grading is skipped; the Clickjacking tool still gives a real frame-based visual proof, because that runs entirely in your browser.",
      "Nothing", "No header grade on this page") +
    "</div>" +
    '<p class="relay-consent-foot">Your choice applies to this browser tab only and is forgotten when you close it. ' +
    'Relayed values are always labelled <span class="unverified-flag">unverified</span>.</p>' +
    "</div>";

  const panel = wrap.querySelector(".relay-consent");
  // The gate can render below the fold on a phone (measured top: 681px in an
  // 844px viewport), where it reads as "the scan is just slow". Bring it into
  // view and move focus so keyboard and screen-reader users land on it too.
  // Align the TOP, not the centre: the panel is taller than a phone viewport
  // (~1100px at 390px wide), so centring pushes its heading off-screen.
  // Offset by the sticky header so the title is not hidden behind it.
  try {
    const header = document.querySelector(".site-header");
    const offset = (header && getComputedStyle(header).position === "sticky")
      ? header.getBoundingClientRect().height + 12 : 12;
    const top = panel.getBoundingClientRect().top + window.pageYOffset - offset;
    window.scrollTo({ top: Math.max(0, top), behavior: prefersReduced() ? "auto" : "smooth" });
  } catch (_) { panel.scrollIntoView(); }
  try { panel.focus({ preventScroll: true }); } catch (_) { /* older browsers */ }

  return new Promise((resolve) => {
    const choose = (mode) => {
      setRelayConsent(mode);
      wrap.classList.add("hidden");
      wrap.innerHTML = "";
      resolve(mode);
    };
    wrap.querySelectorAll("[data-consent]").forEach((btn) => {
      btn.addEventListener("click", () => choose(btn.getAttribute("data-consent")));
    });
    // Escape is the safe default: decline rather than silently relay.
    panel.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.stopPropagation(); choose("deny"); }
    });
  });
}

/* Call before any scan that may fall through to a relay.

   While the gate is open the scan is BLOCKED on a human decision, so any
   spinner started by the caller must stop: reviewers reported that a
   still-spinning Scan button made the gate read as "the scan is running,
   maybe stuck" rather than "you need to answer this". The button is parked
   in an explicit waiting state and restored once a choice is made. */
async function ensureRelayConsent(url) {
  const needed = await relayGateNeeded(url);
  if (!needed) return relayConsent() || "skip";

  const busy = [...document.querySelectorAll(".btn.is-loading")];
  const parked = busy.map((btn) => {
    const label = btn.textContent.trim();
    setLoading(btn, false);
    btn.disabled = true;
    btn.classList.add("is-waiting");
    btn.dataset.cbWaitLabel = label;
    btn.textContent = "Waiting for your choice\u2026";
    return btn;
  });

  const mode = await renderRelayGate();

  parked.forEach((btn) => {
    btn.classList.remove("is-waiting");
    if (btn.dataset.cbWaitLabel) btn.textContent = btn.dataset.cbWaitLabel;
    delete btn.dataset.cbWaitLabel;
    btn.disabled = false;
    // Declining ends the scan; the caller re-enables on any other path.
    if (mode !== "deny") setLoading(btn, true);
  });
  return mode;
}

function isUnverified(data) {
  const s = data && data._source;
  // `relay-cached` is a relayed read served again from the 10-minute local
  // cache — same provenance, so it keeps the same unverified flag.
  return s === "relay" || s === "relay-cached";
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
    "measured header value. Note: a few sites render blank because they need " +
    "third-party cookies or storage, or run frame-busting scripts — not because " +
    "of framing headers. Confirm manually if unsure." +
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

function addRecentScan(url, summary) {
  if (!url) return;
  try {
    let items = getRecentScans().filter((it) => it.url !== url);
    const entry = { url: url, at: Date.now() };
    // summary is a small {headers:{grade,score}, clickjacking:{risk},
    // cors:{risk}, csp:{risk}} digest — never full scan JSON.
    if (summary) entry.summary = summary;
    items.unshift(entry);
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
  const chips = items.map((it) => {
    let badge = "";
    const s = it.summary;
    if (s && s.headers && s.headers.grade) {
      const sc = s.headers.score != null ? " " + s.headers.score : "";
      badge = '<span class="chip-grade grade-' + esc(String(s.headers.grade).toLowerCase()) + '">' +
        esc(String(s.headers.grade).toUpperCase()) + esc(String(sc)) + "</span>";
    }
    return '<button type="button" class="recent-chip" data-url="' + esc(it.url) + '">' +
      esc(it.url) + badge + "</button>";
  }).join("");
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
  const shortcutBtn = document.getElementById("kbdShortcut");
  if (shortcutBtn) shortcutBtn.addEventListener("click", toggleHelp);
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
