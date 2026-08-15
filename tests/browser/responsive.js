/* Real-browser responsiveness suite — every page and every result state,
 * measured per element rather than per document.
 *
 * Why per element: `body { overflow-x: clip }` deliberately hides document
 * overflow so decorative blobs never cause a scrollbar. That also means a
 * document-level overflow check can pass while an individual panel, menu or
 * report row still spills off the side of the screen. Every assertion here
 * measures painted elements against the viewport directly.
 *
 * Covers, at seven widths from a 2560px monitor down to a 360px phone:
 *   - static pages: no element spills, no clipped text, tap targets >= 24px;
 *   - live reports for all four tools;
 *   - the hub suite;
 *   - a deliberately hostile target whose headers carry 400-char unbreakable
 *     tokens (the classic "one long value blows out the grid" regression);
 *   - the clickjacking stage/frame/PoC overlay;
 *   - the relay-consent gate and its option cards;
 *   - the Tools menu, Export menu, engine popover and shortcuts dialog.
 *
 * Elements inside a closed <details> are skipped: they are laid out but not
 * painted, so their scrollWidth is meaningless (a closed Tools menu reports
 * clientWidth 63 vs scrollWidth 155 and is not a bug).
 *
 * See tests/browser/lib.js for how to run this. Set CB_STRESS to the URL of
 * a long-header target to enable the hostile-target section.
 */
"use strict";

const { BASE, TARGET, launch, newPage, settleReveals, sleep, reporter } = require("./lib");

const STRESS = process.env.CB_STRESS || "";

const VPS = [
  ["monitor", 2560, 1440],
  ["desktop", 1920, 1080],
  ["laptop", 1366, 768],
  ["tabletL", 1024, 768],
  ["tabletP", 768, 1024],
  ["phone", 390, 844],
  ["small", 360, 740]
];
const PAGES = [
  ["hub", "/"],
  ["clickjacking", "/tools/clickjacking/"],
  ["headers", "/tools/headers/"],
  ["cors", "/tools/cors/"],
  ["csp", "/tools/csp/"],
  ["csrf", "/tools/csrf/"],
  ["methodology", "/methodology/"],
  ["404", "/404.html"],
  ["catalog", "/tools/"],
  // Appended after index 4 on purpose: TOOLS below is PAGES.slice(1, 5).
  ["guides", "/guides/"],
  ["guide-clickjacking", "/guides/clickjacking/"],
  ["guide-headers", "/guides/headers/"],
  ["guide-cors", "/guides/cors/"],
  ["guide-csp", "/guides/csp/"],
  ["guide-csrf", "/guides/csrf/"]
];
const TOOLS = PAGES.slice(1, 5);

/* Runs in the page. Returns elements that break out of the viewport, have
   genuinely clipped (non-scrollable) content, or are too small to tap. */
const AUDIT = () => {
  const vw = innerWidth;
  const out = { spill: [], clip: [], tiny: [] };
  const seen = new Set();
  const painted = (el) => !el.checkVisibility || el.checkVisibility({
    contentVisibilityAuto: true, opacityProperty: true, visibilityProperty: true
  });
  const name = (el) => el.id ? "#" + el.id
    : (typeof el.className === "string" && el.className.trim())
      ? "." + el.className.trim().split(/\s+/).slice(0, 2).join(".")
      : el.tagName;

  document.querySelectorAll("main *, header *, footer *, #relayGate *, .kbd-help *").forEach((el) => {
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden" || parseFloat(cs.opacity) === 0) return;
    if (!painted(el) || el.closest("details:not([open])")) return;
    // Intentionally off-screen or intentionally wider than the viewport.
    if (el.classList.contains("skip-link") || el.closest(".skip-link")) return;
    if (el.closest(".aurora") || el.closest(".ticker-track")) return;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return;
    const n = name(el);

    if ((r.right > vw + 1 || r.left < -1) && cs.position !== "fixed" && !seen.has("s" + n)) {
      seen.add("s" + n);
      out.spill.push({ el: n, left: Math.round(r.left), right: Math.round(r.right), vw });
    }
    // Content wider than its own box, with no way to scroll to it.
    if (el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 0 &&
        cs.overflowX !== "auto" && cs.overflowX !== "scroll" && cs.overflowX !== "hidden") {
      // Absolutely-positioned children legitimately paint outside the box
      // (score gauges, chips). Only flag when the element's own TEXT is cut.
      const range = document.createRange();
      range.selectNodeContents(el);
      const ink = range.getBoundingClientRect();
      if (ink.width && ink.right > r.right + 1 && !seen.has("c" + n)) {
        seen.add("c" + n);
        out.clip.push({ el: n, scrollW: el.scrollWidth, clientW: el.clientWidth,
          inkOverflow: Math.round(ink.right - r.right) });
      }
    }
  });

  if (vw <= 860) {
    const sel = "button,summary,input[type=checkbox],[data-consent],.recent-chip,#clearRecent,.engine-chip";
    document.querySelectorAll(sel).forEach((el) => {
      const cs = getComputedStyle(el);
      if (cs.display === "none" || cs.visibility === "hidden") return;
      if (!painted(el) || el.closest("details:not([open])")) return;
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height) return;
      if (r.bottom < 0 || r.top > innerHeight) return;
      // Dense footer link lists are a deliberate exception, and a checkbox
      // wrapped in a <label> is only as small as its label.
      if (el.closest("footer")) return;
      const label = el.closest("label");
      const hit = label ? label.getBoundingClientRect() : r;
      if (hit.height < 24 || hit.width < 24) {
        out.tiny.push({ el: name(el), w: Math.round(hit.width), h: Math.round(hit.height),
          txt: (el.textContent || "").trim().slice(0, 20) });
      }
    });
  }
  return out;
};

const summarize = (a) =>
  `spill=${JSON.stringify(a.spill)} clip=${JSON.stringify(a.clip)} tiny=${JSON.stringify(a.tiny)}`;
const clean = (a) => !a.spill.length && !a.clip.length && !a.tiny.length;

async function scan(page, path, url) {
  await page.goto(BASE + path, { waitUntil: "networkidle2" });
  await page.type("#url", url);
  await page.click("#go");
  await page.waitForFunction(
    () => !document.getElementById("results").classList.contains("hidden"),
    { timeout: 25000 }
  );
  await sleep(700);
}

(async () => {
  const browser = await launch();
  const r = reporter("RESPONSIVE");

  /* ---- 1. Static pages, every width, both themes ------------------------ */
  for (const [pn, path] of PAGES) {
    for (const [vn, w, h] of VPS) {
      for (const theme of ["dark", "light"]) {
        const page = await newPage(browser, { w, h, theme });
        await page.goto(BASE + path, { waitUntil: "networkidle2" });
        await page.evaluate(async () => {
          const H = document.documentElement.scrollHeight;
          for (let y = 0; y < H; y += Math.max(300, innerHeight / 2)) {
            window.scrollTo(0, y);
            await new Promise((r) => setTimeout(r, 50));
          }
          window.scrollTo(0, 0);
        });
        await settleReveals(page);
        const a = await page.evaluate(AUDIT);
        r.check(clean(a), `page ${pn} ${vn} ${theme} ${summarize(a)}`);
        await page.close();
      }
    }
  }

  /* ---- 2. Live reports for all four tools ------------------------------- */
  for (const [tn, path] of TOOLS) {
    for (const [vn, w, h] of VPS) {
      for (const theme of ["dark", "light"]) {
        const page = await newPage(browser, { w, h, theme });
        let a, ok = true;
        try {
          await scan(page, path, TARGET);
          a = await page.evaluate(AUDIT);
          ok = clean(a);
        } catch (_) { ok = false; a = { spill: [{ el: "NO RESULTS" }], clip: [], tiny: [] }; }
        r.check(ok, `report ${tn} ${vn} ${theme} ${summarize(a)}`);
        await page.close();
      }
    }
  }

  /* ---- 3. Hostile target: 400-char unbreakable header tokens ------------ */
  if (STRESS) {
    for (const [tn, path] of TOOLS) {
      for (const [vn, w, h] of VPS) {
        const page = await newPage(browser, { w, h });
        let ok = true, note = "";
        try {
          await scan(page, path, STRESS);
          const a = await page.evaluate(AUDIT);
          // The real symptom of a blown-out grid: the user can pan sideways.
          const pan = await page.evaluate(() =>
            document.scrollingElement.scrollWidth > document.scrollingElement.clientWidth + 1);
          ok = !a.spill.length && !pan;
          note = `spill=${JSON.stringify(a.spill)} canPanX=${pan}`;
        } catch (_) { ok = false; note = "no results"; }
        r.check(ok, `stress ${tn} ${vn} ${note}`);
        await page.close();
      }
    }
  } else {
    r.skip("stress target (set CB_STRESS to a long-header URL to enable)");
  }

  /* ---- 4. Clickjacking stage, frame and PoC overlay --------------------- */
  for (const [vn, w, h] of VPS) {
    const page = await newPage(browser, { w, h });
    let ok = true, note = "";
    try {
      await scan(page, "/tools/clickjacking/", TARGET);
      const m = await page.evaluate(async () => {
        const stage = document.querySelector(".stage");
        const sr = stage.getBoundingClientRect();
        const frame = stage.querySelector("iframe");
        const out = {
          stageIn: sr.left >= -1 && sr.right <= innerWidth + 1,
          frameIn: true, overlayIn: true
        };
        if (frame) {
          const f = frame.getBoundingClientRect();
          out.frameIn = f.left >= sr.left - 1 && f.right <= sr.right + 1 && f.right <= innerWidth + 1;
        }
        const toggle = [...document.querySelectorAll("button")].find((b) => /overlay/i.test(b.textContent));
        if (toggle) {
          toggle.click();
          await new Promise((r) => setTimeout(r, 400));
          const ov = document.querySelector(".overlay");
          if (ov && getComputedStyle(ov).display !== "none") {
            const o = ov.getBoundingClientRect();
            out.overlayIn = o.left >= sr.left - 2 && o.right <= sr.right + 2 && o.right <= innerWidth + 1;
          }
        }
        return out;
      });
      const audit = await page.evaluate(AUDIT);
      ok = m.stageIn && m.frameIn && m.overlayIn && clean(audit);
      note = JSON.stringify(m) + " " + summarize(audit);
    } catch (_) { ok = false; note = "no results"; }
    r.check(ok, `clickjacking stage/frame/overlay ${vn} ${note}`);
    await page.close();
  }

  /* ---- 5. Relay-consent gate (simulate Pages: no /api) ------------------ */
  for (const [vn, w, h] of VPS) {
    for (const theme of ["dark", "light"]) {
      const page = await newPage(browser, { w, h, theme });
      await page.setRequestInterception(true);
      page.on("request", (q) => { if (/\/api\//.test(q.url())) return q.abort(); q.continue(); });
      await page.goto(BASE + "/tools/headers/", { waitUntil: "networkidle2" });
      await page.type("#url", "https://example.com");
      await page.click("#go");
      await sleep(3200);
      const m = await page.evaluate(() => {
        const el = document.querySelector(".relay-consent");
        if (!el) return { missing: true };
        const g = el.getBoundingClientRect();
        const opts = [...el.querySelectorAll(".relay-option")].map((o) => {
          const b = o.getBoundingClientRect();
          return {
            in: b.left >= -1 && b.right <= innerWidth + 1,
            clipped: o.scrollWidth > o.clientWidth + 2
          };
        });
        return {
          gateIn: g.left >= -1 && g.right <= innerWidth + 1,
          opts,
          cols: getComputedStyle(el.querySelector(".relay-consent-actions")).gridTemplateColumns
            .split(" ").filter(Boolean).length
        };
      });
      const ok = !m.missing && m.gateIn && m.opts.length === 3 &&
        m.opts.every((o) => o.in && !o.clipped) &&
        // Three across on wide screens, stacked on narrow ones.
        (w > 860 ? m.cols === 3 : m.cols === 1);
      r.check(ok, `relay-gate ${vn} ${theme} ${JSON.stringify(m)}`);
      await page.close();
    }
  }

  /* ---- 6. Overlays must stay inside the viewport at every width --------- */
  for (const [vn, w, h] of VPS) {
    const page = await newPage(browser, { w, h });
    await scan(page, "/tools/headers/", TARGET);
    const m = await page.evaluate(async () => {
      const fits = (el) => {
        const b = el.getBoundingClientRect();
        return b.left >= -1 && b.right <= innerWidth + 1;
      };
      const out = {};
      const nav = document.querySelector(".header-inner details.nav-menu");
      nav.querySelector("summary").click();
      await new Promise((r) => setTimeout(r, 350));
      out.toolsMenu = fits(nav.querySelector(".nav-menu-panel"));
      out.toolsItems = [...nav.querySelectorAll(".nav-menu-item")].every(fits);
      nav.open = false;

      const exp = document.querySelector("details.export-menu");
      exp.querySelector("summary").click();
      await new Promise((r) => setTimeout(r, 350));
      out.exportMenu = fits(exp.querySelector(".export-menu-panel"));
      out.exportItems = [...exp.querySelectorAll(".export-menu-item")].every(fits);
      exp.open = false;

      document.getElementById("engineChip").click();
      await new Promise((r) => setTimeout(r, 300));
      out.enginePopover = fits(document.getElementById("enginePopover"));
      document.body.click();
      await new Promise((r) => setTimeout(r, 200));

      document.getElementById("kbdShortcut").click();
      await new Promise((r) => setTimeout(r, 300));
      const dlg = [...document.querySelectorAll("[role=dialog]")]
        .find((e) => e.id !== "enginePopover" && e.getBoundingClientRect().width > 0);
      out.kbdDialog = dlg ? fits(dlg) : false;
      return out;
    });
    r.check(Object.values(m).every(Boolean), `overlays ${vn} ${JSON.stringify(m)}`);
    await page.close();
  }

  r.done();
  await browser.close();
})();
