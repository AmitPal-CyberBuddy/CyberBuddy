/* Public landing/reference screens, no scans or external PoC requests.
 * npm install --prefix /tmp/cyberbuddy-browser puppeteer-core @axe-core/puppeteer pngjs
 * NODE_PATH=/tmp/cyberbuddy-browser/node_modules CB_CHROME=/path/to/chromium node tests/browser/site-contrast.js
 * Optional: CB_WIDTHS=1366,390 and CB_ROUTES=/,/404.html for a focused rerun.
 */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { AxePuppeteer } = require("@axe-core/puppeteer");
const { BASE, launch, newPage } = require("./lib");
const { sampleTextContrast } = require("./contrast-pixels");

// Keep coverage aligned with shipped HTML, not a hand-maintained tool count.
const root = path.resolve(__dirname, "../..");
function htmlFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const file = path.join(dir, entry.name);
    return entry.isDirectory() ? htmlFiles(file) : file.endsWith(".html") ? [file] : [];
  });
}
const discovered = ["index.html", "404.html", ...["tools", "guides", "documentation", "methodology"]
  .flatMap(dir => htmlFiles(path.join(root, dir)).map(file => path.relative(root, file)))];
const routes = process.env.CB_ROUTES ? process.env.CB_ROUTES.split(",") :
  discovered.map(file => "/" + file.replace(/index\.html$/, ""));
const widths = (process.env.CB_WIDTHS || "1366,390").split(",").map(Number);

(async () => {
  const browser = await launch();
  let screens = 0, samples = 0, axeIncomplete = 0, interactiveStates = 0;
  try {
    // Positive and negative controls: a silent/empty sampler is not a pass.
    const control = await browser.newPage();
    await control.setViewport({ width: 600, height: 400, deviceScaleFactor: 1 });
    await control.setContent('<style>body{background:#fff;color:#111;font:16px sans-serif}.bad{color:#ddd}</style><p class="bad">Deliberately unreadable text</p><p>Readable text</p>');
    const calibration = await sampleTextContrast(control);
    assert.equal(calibration.measured, 2);
    assert.equal(calibration.failures.length, 1);
    assert.equal(calibration.failures[0].element, "p.bad");
    await control.close();
    for (const width of widths) for (const theme of ["light", "dark"]) for (const route of routes) {
      const page = await newPage(browser, { theme, w: width, h: 900 });
      const errors = [];
      page.on("pageerror", error => errors.push(error.message));
      try {
        await page.emulateMediaFeatures([{ name: "prefers-reduced-motion", value: "reduce" }]);
        await page.goto(BASE + route, { waitUntil: "networkidle2" });
        await page.evaluate(() => document.fonts.ready);
        const label = `${width}px ${theme} ${route}`;
        assert(await page.$("#themeToggle"), label + " missing theme toggle");
        // Exercise the real toggle, not just a forced attribute, then return to
        // the chosen theme for sampling. Do not activate scan/submit controls.
        for (let i = 0; i < 2; i++) {
          await page.$eval("#themeToggle", e => e.click());
          const actual = await page.evaluate(() => document.documentElement.dataset.theme || "dark");
          assert.equal(actual, i === 0 ? (theme === "light" ? "dark" : "light") : theme);
        }
        async function axe(scope) {
          let builder = new AxePuppeteer(page).withRules(["color-contrast"]);
          if (scope) builder = builder.include(scope);
          const result = await builder.analyze();
          axeIncomplete += result.incomplete.reduce((sum, v) => sum + v.nodes.length, 0);
          assert.deepEqual(result.violations.flatMap(v => v.nodes.map(n => ({ target: n.target, detail: n.failureSummary }))), [], label);
        }
        async function pixels(scope) {
          const result = await sampleTextContrast(page, scope);
          samples += result.measured;
          assert.deepEqual(result.failures, [], label + " rendered background: " + (scope || "body"));
        }
        await axe();
        await pixels();
        // Explain/how-it-works/privacy panels contain text not on the initial
        // screen. Do not open export popovers over the content being measured.
        const count = await page.evaluate(() => {
          const details = [...document.querySelectorAll("main details:not(.export-menu)")];
          details.forEach(e => { e.open = true; });
          return details.length;
        });
        if (count) { await axe(); await pixels(); interactiveStates++; }

        // Pointer/keyboard states on the same public components in both themes.
        const candidates = ["main .btn-primary", "main .blog-monogram", "main .tool-card", "main a.card", "main .prose a", ".prose a:not(.btn)", ".jwt-preview-note a"];
        for (const selector of candidates) {
          if (!await page.$(selector)) continue;
          if (!await page.$eval(selector, e => e.checkVisibility({ opacityProperty: true, visibilityProperty: true }))) continue;
          // Scope uses the existing element; no new persistent markup is added.
          await page.$eval(selector, e => e.setAttribute("data-contrast-target", ""));
          await page.hover(selector);
          const focusable = await page.$eval(selector, e => e.matches("a,button,input,select,textarea,[tabindex]"));
          if (focusable) {
            await page.keyboard.press("Tab");
            await page.$eval(selector, e => e.focus({ preventScroll: true }));
            assert(await page.$eval(selector, e => {
              const s = getComputedStyle(e);
              return parseFloat(s.outlineWidth) >= 2 && s.outlineStyle !== "none";
            }), label + " visible focus: " + selector);
          }
          await pixels('[data-contrast-target]');
          await page.$eval(selector, e => { e.removeAttribute("data-contrast-target"); e.blur(); });
          await page.mouse.move(width - 1, 899);
          interactiveStates++;
        }
        if (await page.$(".header-inner details.nav-menu")) {
          await page.evaluate(() => {
            window.scrollTo({ top: 0, behavior: "instant" });
            document.querySelector(".header-inner details.nav-menu").open = true;
          });
          const item = ".header-inner .nav-menu-panel a.nav-menu-item";
          await page.hover(item);
          await page.keyboard.press("Tab");
          await page.$eval(item, e => e.focus({ preventScroll: true }));
          await axe(".header-inner .nav-menu-panel");
          await pixels(".header-inner .nav-menu-panel");
          interactiveStates++;
        }
        assert.deepEqual(errors, [], label + " runtime errors");
        console.log("ok " + label + " — initial, disclosures, hover/focus and navigation");
        screens++;
      } finally { await page.close(); }
    }
    console.log(`\nSITE CONTRAST: ${screens} page/theme/width combinations; ${interactiveStates} additional states; ${samples} text/control samples passed.`);
    console.log(`axe returned ${axeIncomplete} incomplete node observations (principally gradients/pseudo-elements); these are not axe passes. Rendered-pixel sampling supplements them.`);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
