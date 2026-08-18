/* Shared harness for the real-browser regression suites.
 *
 * These suites need a real engine and a real Chromium; they are NOT part of
 * `python3 -m unittest test_engines.py` (which stays stdlib-only and runs in
 * CI). Run them locally against a live server:
 *
 *   python3 server.py --port 8080 --allow-private   # in another shell
 *   for suite in layout dropdown overlays relay-gate responsive csrf jwt; do
 *     CB_CHROME=/path/to/chrome node "tests/browser/${suite}.js" || exit 1
 *   done
 *
 * Install outside the repo with
 * `npm install --prefix /tmp/cyberbuddy-browser puppeteer-core`, then export
 * `NODE_PATH=/tmp/cyberbuddy-browser/node_modules`. Each suite exits
 * non-zero on the first failed assertion so it can gate a release.
 */
"use strict";

const puppeteer = require("puppeteer-core");

const BASE = process.env.CB_BASE || "http://127.0.0.1:8080";
// Any reachable HTTP target works; a local one keeps the suite offline.
const TARGET = process.env.CB_TARGET || "http://127.0.0.1:8099/";
const CHROME = process.env.CB_CHROME || "/usr/bin/chromium";

const VIEWPORTS = [
  ["monitor", 2560, 1440],
  ["desktop", 1920, 1080],
  ["laptop", 1366, 768],
  ["tabletL", 1024, 768],
  ["tabletP", 768, 1024],
  ["phone", 390, 844]
];

async function launch() {
  return puppeteer.launch({
    executablePath: CHROME,
    headless: "shell",
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--use-gl=swiftshader",
      "--hide-scrollbars"
    ]
  });
}

async function newPage(browser, { w = 1366, h = 768, theme = "dark" } = {}) {
  const page = await browser.newPage();
  await page.setViewport({ width: w, height: h, deviceScaleFactor: 1 });
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
  page.on("requestfailed", (r) => {
    if (r.url().startsWith(BASE)) errors.push("requestfailed: " + r.url());
  });
  await page.evaluateOnNewDocument((t) => {
    try { localStorage.setItem("cb-theme", t); } catch (_) { /* private mode */ }
  }, theme);
  page._cbErrors = errors;
  return page;
}

/* Run a real Security Headers scan and wait for the report to render. */
async function scanHeaders(page, url = TARGET) {
  await page.goto(BASE + "/tools/headers/", { waitUntil: "networkidle2" });
  await page.type("#url", url);
  await page.click("#go");
  await page.waitForFunction(
    () => !document.getElementById("results").classList.contains("hidden"),
    { timeout: 25000 }
  );
  await sleep(500);
}

/* Reveal animations are time-based: a mid-animation opacity is not an
   invisibility bug. Poll until every .reveal settles (or give up, so the
   caller's assertion still catches genuinely stuck content). */
async function settleReveals(page) {
  await page.evaluate(async () => {
    const stuck = () => [...document.querySelectorAll(".reveal")]
      .filter((e) => parseFloat(getComputedStyle(e).opacity) < 0.99);
    for (let i = 0; i < 40 && stuck().length; i++) {
      await new Promise((r) => setTimeout(r, 150));
    }
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const overflow = (page) => page.evaluate(() => ({
  doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  body: document.body.scrollWidth - document.documentElement.clientWidth
}));

/* Console errors that are environmental rather than site bugs. */
const realErrors = (page) =>
  page._cbErrors.filter((e) => !/ERR_CONNECTION_CLOSED/.test(e));

function reporter(name) {
  let pass = 0, fail = 0;
  return {
    check(ok, msg) { console.log((ok ? "ok   " : "FAIL ") + msg); ok ? pass++ : fail++; return ok; },
    skip(msg) { console.log("skip  " + msg); },
    done() {
      console.log(`\n${name}: ${pass} passed, ${fail} failed`);
      process.exitCode = fail ? 1 : 0;
      return fail;
    }
  };
}

module.exports = {
  BASE, TARGET, CHROME, VIEWPORTS,
  launch, newPage, scanHeaders, settleReveals, sleep, overflow, realErrors, reporter
};
