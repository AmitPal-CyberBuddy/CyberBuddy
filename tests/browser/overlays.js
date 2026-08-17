/* Real-browser regression suite for every other overlay on the site.
 *
 * The Tools dropdown was not the only element that could paint behind the
 * report or fall outside the viewport. This suite exercises the same three
 * failure modes — stacking, viewport containment, pointer interception — on:
 *   - the Export split menu (its panel used to start at x = -122px on a
 *     tablet-portrait width, and the footer swallowed clicks on its last
 *     item because `.container` and `.site-footer` were both z-index: 1);
 *   - the engine popover;
 *   - the keyboard-shortcuts dialog;
 *   - the share/copy controls.
 *
 * See tests/browser/lib.js for how to run this.
 */
"use strict";

const { BASE, VIEWPORTS, launch, newPage, scanHeaders, sleep, reporter } = require("./lib");

(async () => {
  const browser = await launch();
  const r = reporter("OVERLAYS");

  for (const [vn, w, h] of VIEWPORTS) {
    for (const theme of ["dark", "light"]) {
      const page = await newPage(browser, { w, h, theme });
      // Scan first: overlays must work on a rendered report, in evidence mode.
      await scanHeaders(page);

      /* ---- Export split menu ------------------------------------------- */
      let m = await page.evaluate(async () => {
        const details = document.querySelector("details.export-menu");
        const summary = details.querySelector("summary");
        summary.scrollIntoView({ block: "center", behavior: "instant" });
        await new Promise((r) => setTimeout(r, 150));
        summary.click();
        await new Promise((r) => setTimeout(r, 400));
        const panel = details.querySelector(".export-menu-panel");
        const items = [...panel.querySelectorAll(".export-menu-item")].map((i) => {
          const b = i.getBoundingClientRect();
          const el = document.elementFromPoint(
            Math.round(b.left + b.width / 2), Math.round(b.top + b.height / 2));
          return {
            label: i.textContent.trim().slice(0, 16),
            insideViewport: b.left >= -1 && b.right <= innerWidth + 1 && b.top >= -1 && b.bottom <= innerHeight + 1,
            disabled: i.disabled,
            hit: el ? (i.contains(el) || i === el ? "SELF" : String(el.className || el.tagName).slice(0, 24)) : "null"
          };
        });
        const out = {
          items,
          evidenceMode: document.body.classList.contains("evidence"),
          overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth
        };
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
        await new Promise((r) => setTimeout(r, 150));
        out.escapeCloses = !details.open;
        details.open = false;
        return out;
      });
      r.check(
        m.items.every((i) => i.insideViewport && (i.disabled || i.hit === "SELF")) && m.overflow === 0,
        `export-menu ${vn} ${theme} evidence=${m.evidenceMode} ` +
        `bad=${JSON.stringify(m.items.filter((i) => !i.insideViewport || (!i.disabled && i.hit !== "SELF")))}`
      );

      /* ---- Engine popover ----------------------------------------------- */
      m = await page.evaluate(async () => {
        document.getElementById("engineChip").click();
        await new Promise((r) => setTimeout(r, 350));
        const pop = document.getElementById("enginePopover");
        const b = pop.getBoundingClientRect();
        const el = document.elementFromPoint(Math.round(b.left + b.width / 2), Math.round(b.top + 20));
        const out = {
          shown: !pop.classList.contains("hidden"),
          visibility: getComputedStyle(pop).visibility,
          insideViewport: b.left >= -1 && b.right <= innerWidth + 1 && b.top >= -1 && b.bottom <= innerHeight + 1,
          hit: el ? (pop.contains(el) ? "SELF" : String(el.className).slice(0, 22)) : "null",
          overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth
        };
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
        await new Promise((r) => setTimeout(r, 200));
        out.escapeCloses = pop.classList.contains("hidden");
        return out;
      });
      r.check(
        m.shown && m.insideViewport && m.hit === "SELF" && m.escapeCloses && m.overflow === 0,
        `engine-popover ${vn} ${theme} ${JSON.stringify(m)}`
      );

      /* ---- Keyboard-shortcuts dialog ------------------------------------ */
      m = await page.evaluate(async () => {
        document.getElementById("kbdShortcut").click();
        await new Promise((r) => setTimeout(r, 350));
        const visible = () => [...document.querySelectorAll("[role=dialog]")]
          .filter((e) => e.id !== "enginePopover" && e.getBoundingClientRect().width > 0);
        const dlg = visible()[0];
        if (!dlg) return { missing: true };
        const b = dlg.getBoundingClientRect();
        const el = document.elementFromPoint(Math.round(b.left + b.width / 2), Math.round(b.top + b.height / 2));
        const out = {
          insideViewport: b.left >= -1 && b.right <= innerWidth + 1,
          hit: el ? (dlg.contains(el) ? "SELF" : String(el.className).slice(0, 20)) : "null",
          overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth
        };
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
        await new Promise((r) => setTimeout(r, 250));
        out.escapeCloses = !visible().length;
        return out;
      });
      r.check(
        !m.missing && m.insideViewport && m.hit === "SELF" && m.escapeCloses && m.overflow === 0,
        `kbd-dialog ${vn} ${theme} ${JSON.stringify(m)}`
      );

      /* Per-tool share buttons were removed: URLs are not report artifacts. */
      m = await page.evaluate(() => !document.getElementById("shareLink"));
      r.check(m, `no-misleading-share-control ${vn} ${theme}`);

      await page.close();
    }
  }

  r.done();
  await browser.close();
})();
