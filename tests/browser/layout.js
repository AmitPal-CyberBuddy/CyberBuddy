/* Real-browser layout regression suite.
 *
 * Guards the Round 6 fixes:
 *   - the Security Headers report stacks Findings above Raw headers at every
 *     width (it used to sit in a 2-column grid where Findings was 2735px and
 *     Raw headers 236px, leaving a huge blank right column);
 *   - no page overflows horizontally in either theme at six viewport sizes;
 *   - no `.reveal` section stays invisible;
 *   - no visible control is clipped outside the viewport;
 *   - all four tools render a real report with balanced panels;
 *   - evidence mode toggles both ways without breaking layout;
 *   - print media keeps the report single-column with evidence expanded.
 *
 * See tests/browser/lib.js for how to run this.
 */
"use strict";

const {
  BASE, TARGET, VIEWPORTS, launch, newPage, settleReveals, sleep, realErrors, reporter
} = require("./lib");

const PAGES = [
  ["hub", "/"],
  ["clickjacking", "/tools/clickjacking/"],
  ["headers", "/tools/headers/"],
  ["cors", "/tools/cors/"],
  ["csp", "/tools/csp/"],
  ["methodology", "/methodology/"],
  ["404", "/404.html"]
];
const TOOLS = [
  ["clickjacking", "/tools/clickjacking/"],
  ["headers", "/tools/headers/"],
  ["cors", "/tools/cors/"],
  ["csp", "/tools/csp/"]
];

async function runScan(page, path) {
  await page.goto(BASE + path, { waitUntil: "networkidle2" });
  await page.type("#url", TARGET);
  await page.click("#go");
  await page.waitForFunction(
    () => !document.getElementById("results").classList.contains("hidden"),
    { timeout: 25000 }
  );
  await sleep(800);
}

(async () => {
  const browser = await launch();
  const r = reporter("LAYOUT");

  /* ---- 1. Headers report: vertical stack, full width, no overflow ------- */
  for (const [vn, w, h] of VIEWPORTS) {
    for (const theme of ["dark", "light"]) {
      const page = await newPage(browser, { w, h, theme });
      await runScan(page, "/tools/headers/");
      const m = await page.evaluate(() => {
        const stack = document.querySelector(".headers-report-stack");
        const [findings, raw] = [...stack.children];
        const fr = findings.getBoundingClientRect();
        const rr = raw.getBoundingClientRect();
        const sw = stack.getBoundingClientRect().width;
        const pre = document.getElementById("headers");
        return {
          columns: getComputedStyle(stack).gridTemplateColumns.split(" ").filter(Boolean).length,
          findingsFullWidth: Math.abs(fr.width - sw) < 2,
          rawFullWidth: Math.abs(rr.width - sw) < 2,
          rawBelowFindings: rr.top >= fr.bottom - 1,
          sameLeftEdge: Math.abs(fr.left - rr.left) < 1,
          order: [
            findings.querySelector(".card-title").textContent.trim(),
            raw.querySelector(".card-title").textContent.trim()
          ],
          // Long unbreakable tokens must wrap, not expand the track.
          rawOverflow: pre.scrollWidth - pre.clientWidth,
          findingRows: document.querySelectorAll("#checks tbody tr").length,
          // Evidence must never hide behind a click.
          hasAccordion: !!stack.querySelector("details"),
          pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth
        };
      });
      const ok = m.columns === 1 && m.findingsFullWidth && m.rawFullWidth &&
        m.rawBelowFindings && m.sameLeftEdge && m.rawOverflow <= 0 &&
        m.findingRows > 0 && !m.hasAccordion &&
        m.order[0] === "Findings" && m.order[1] === "Raw headers" &&
        m.pageOverflow === 0;
      r.check(ok, `headers-stack ${vn} ${theme} ${JSON.stringify(m)}`);
      await page.close();
    }
  }

  /* ---- 2. Every page, viewport and theme -------------------------------- */
  for (const [pn, path] of PAGES) {
    for (const [vn, w, h] of VIEWPORTS) {
      for (const theme of ["dark", "light"]) {
        const page = await newPage(browser, { w, h, theme });
        await page.goto(BASE + path, { waitUntil: "networkidle2" });
        await page.evaluate(async () => {
          const H = document.documentElement.scrollHeight;
          for (let y = 0; y < H; y += Math.max(300, innerHeight / 2)) {
            window.scrollTo(0, y);
            await new Promise((r) => setTimeout(r, 60));
          }
          window.scrollTo(0, 0);
        });
        await settleReveals(page);
        const m = await page.evaluate(() => {
          const out = {
            overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
            invisible: [],
            clipped: []
          };
          document.querySelectorAll(".reveal").forEach((e) => {
            if (parseFloat(getComputedStyle(e).opacity) < 0.99) out.invisible.push(e.className.slice(0, 32));
          });
          document.querySelectorAll("button,a.btn,input,select,summary").forEach((e) => {
            const cs = getComputedStyle(e);
            if (cs.display === "none" || cs.visibility === "hidden") return;
            const b = e.getBoundingClientRect();
            if (!b.width) return;
            if (b.right > innerWidth + 1 || b.left < -1) {
              out.clipped.push(String(e.id || e.className || e.tagName).slice(0, 26));
            }
          });
          return out;
        });
        const errs = realErrors(page);
        r.check(
          m.overflow === 0 && !m.invisible.length && !m.clipped.length && !errs.length,
          `page ${pn} ${vn} ${theme} overflow=${m.overflow} invisible=${m.invisible.length} ` +
          `clipped=${JSON.stringify(m.clipped)} errors=${JSON.stringify(errs.slice(0, 2))}`
        );
        await page.close();
      }
    }
  }

  /* ---- 3. Real reports for all four tools ------------------------------- */
  for (const [tn, path] of TOOLS) {
    for (const [vn, w, h] of [["desktop", 1920, 1080], ["phone", 390, 844]]) {
      for (const theme of ["dark", "light"]) {
        const page = await newPage(browser, { w, h, theme });
        let ok = true, note = "";
        try {
          await runScan(page, path);
        } catch (_) {
          ok = false; note = "no results rendered";
        }
        if (ok) {
          const m = await page.evaluate(() => {
            const out = {
              overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
              imbalanced: [],
              invisible: [],
              provenance: !!(document.getElementById("reportProvenance") || {}).textContent
            };
            // A 2-column report panel whose siblings differ wildly in height
            // is the blank-column bug this round fixed.
            document.querySelectorAll("#results .grid-2, #results .poc-grid, #results .headers-report-stack")
              .forEach((g) => {
                const cols = getComputedStyle(g).gridTemplateColumns.split(" ").filter(Boolean).length;
                if (cols < 2) return;
                const hs = [...g.children].map((c) => c.getBoundingClientRect().height);
                const mx = Math.max(...hs), mn = Math.min(...hs);
                if (mx - mn > 260 && mx / Math.max(mn, 1) > 2.2) {
                  out.imbalanced.push(g.className.slice(0, 30) + " " + hs.map(Math.round).join("/"));
                }
              });
            document.querySelectorAll("#results .reveal").forEach((e) => {
              if (parseFloat(getComputedStyle(e).opacity) < 0.99) out.invisible.push(e.className.slice(0, 24));
            });
            return out;
          });
          const ev = await page.evaluate(async () => {
            const t = document.querySelector(".evidence-toggle input");
            if (!t) return { missing: true };
            const before = document.body.classList.contains("evidence");
            t.click();
            await new Promise((r) => setTimeout(r, 350));
            const flipped = document.body.classList.contains("evidence") !== before;
            // Evidence mode must un-stick the header without un-positioning
            // it, or its z-index stops applying and menus paint behind.
            const headerPosition = getComputedStyle(document.querySelector(".site-header")).position;
            t.click();
            await new Promise((r) => setTimeout(r, 350));
            return {
              flipped,
              headerPosition,
              restored: document.body.classList.contains("evidence") === before,
              overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth
            };
          });
          const errs = realErrors(page);
          ok = m.overflow === 0 && !m.imbalanced.length && !m.invisible.length &&
            m.provenance && ev.flipped && ev.restored && ev.headerPosition !== "static" &&
            ev.overflow === 0 && !errs.length;
          note = JSON.stringify(m) + " evidence=" + JSON.stringify(ev) +
            " errors=" + JSON.stringify(errs.slice(0, 2));
        }
        r.check(ok, `report ${tn} ${vn} ${theme} ${note}`);
        await page.close();
      }
    }
  }

  /* ---- 4. Print / PDF evidence layout ----------------------------------- */
  {
    const page = await newPage(browser, { w: 1366, h: 768 });
    await runScan(page, "/tools/headers/");
    await page.emulateMediaType("print");
    await sleep(400);
    const m = await page.evaluate(() => {
      const stack = document.querySelector(".headers-report-stack");
      const pre = document.getElementById("headers");
      const rows = [...document.querySelectorAll("#checks tbody tr")];
      return {
        columns: getComputedStyle(stack).gridTemplateColumns.split(" ").filter(Boolean).length,
        rawMaxHeight: getComputedStyle(pre).maxHeight,
        rawVisible: getComputedStyle(pre).display !== "none",
        rows: rows.length,
        hiddenRows: rows.filter((t) => getComputedStyle(t).display === "none").length,
        chromeHidden: getComputedStyle(document.querySelector(".site-header")).display === "none"
      };
    });
    r.check(
      m.columns === 1 && m.rawMaxHeight === "none" && m.rawVisible &&
      m.rows > 0 && m.hiddenRows === 0 && m.chromeHidden,
      `print headers report ${JSON.stringify(m)}`
    );
    await page.close();
  }

  r.done();
  await browser.close();
})();
