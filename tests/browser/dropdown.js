/* Real-browser regression suite for the header Tools dropdown.
 *
 * Reproduced bugs this guards against:
 *   - Evidence mode set `.site-header { position: static }`, which drops the
 *     header out of the z-index game — the open Tools menu then painted
 *     BEHIND the report card and `elementFromPoint` over each tool link
 *     resolved to `.page-hero` / `.bar` / an `<input>` instead of the link.
 *     Every item was visible but unclickable on hosted result pages.
 *   - At phone/tablet widths a 300px panel anchored to the small Tools
 *     <details> ran past the right edge of the viewport (and contributed
 *     46px of horizontal overflow at 390px).
 *   - GitHub project-path (`/CyberBuddy/...`) links must stay correct.
 *
 * See tests/browser/lib.js for how to run this.
 */
"use strict";

const {
  BASE, TARGET, VIEWPORTS, launch, newPage, scanHeaders, sleep, reporter
} = require("./lib");

const PAGES = [
  ["hub", "/"],
  ["methodology", "/methodology/"],
  ["clickjacking", "/tools/clickjacking/"],
  ["headers", "/tools/headers/"],
  ["cors", "/tools/cors/"],
  ["csp", "/tools/csp/"],
  ["csrf", "/tools/csrf/"],
  ["404", "/404.html"]
];

async function scrollTo(page, where) {
  await page.evaluate((w) => {
    const H = document.documentElement.scrollHeight;
    window.scrollTo({
      top: w === "top" ? 0 : w === "middle" ? Math.round(H / 2) : H,
      behavior: "instant"
    });
  }, where);
  await sleep(250);
}

/* Open the menu the way a user does and assert it is genuinely usable. */
async function checkMenu(page, label, r) {
  const m = await page.evaluate(async () => {
    const details = document.querySelector(".header-inner details.nav-menu");
    if (!details) return { absent: true };
    const summary = details.querySelector("summary");
    summary.scrollIntoView({ block: "center", behavior: "instant" });
    await new Promise((r) => setTimeout(r, 150));
    summary.click();
    await new Promise((r) => setTimeout(r, 450));
    if (!details.open) return { failure: "menu did not open" };

    const panel = details.querySelector(".nav-menu-panel");
    const cs = getComputedStyle(panel);
    const pr = panel.getBoundingClientRect();
    const items = [...panel.querySelectorAll(".nav-menu-item")].map((i) => {
      const b = i.getBoundingClientRect();
      const el = document.elementFromPoint(
        Math.round(b.left + b.width / 2),
        Math.round(b.top + b.height / 2)
      );
      return {
        label: i.textContent.trim().replace(/(live|soon)$/, ""),
        isLink: i.tagName === "A",
        insideViewport: b.left >= -1 && b.top >= -1 && b.right <= innerWidth + 1 && b.bottom <= innerHeight + 1,
        // The item (or a child of it) must be the topmost element at its
        // centre — anything else means an overlay is eating the click.
        hit: el ? (i.contains(el) || i === el ? "SELF" : String(el.className || el.tagName).slice(0, 26)) : "null"
      };
    });

    const out = {
      visibility: cs.visibility,
      opacity: cs.opacity,
      zIndex: cs.zIndex,
      rect: [pr.left, pr.top, pr.right, pr.bottom].map(Math.round),
      viewport: [innerWidth, innerHeight],
      headerPosition: getComputedStyle(document.querySelector(".site-header")).position,
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      items
    };
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    await new Promise((r) => setTimeout(r, 150));
    out.escapeCloses = !details.open;
    summary.click();
    await new Promise((r) => setTimeout(r, 200));
    document.body.click();
    await new Promise((r) => setTimeout(r, 150));
    out.outsideClickCloses = !details.open;
    return out;
  });

  if (m.absent) { r.skip(`${label} (page has no header nav)`); return true; }
  if (m.failure) return r.check(false, `${label} — ${m.failure}`);

  const bad = [];
  if (m.visibility !== "visible" || parseFloat(m.opacity) < 0.99) bad.push("not visible");
  if (!m.escapeCloses) bad.push("Escape does not close");
  if (!m.outsideClickCloses) bad.push("outside click does not close");
  if (m.overflow > 0) bad.push("horizontal overflow " + m.overflow);
  m.items.forEach((i) => {
    if (!i.insideViewport) bad.push("outside viewport: " + i.label);
    if (i.hit !== "SELF") bad.push("click intercepted on '" + i.label + "' by " + i.hit);
  });
  return r.check(
    !bad.length,
    `${label} header=${m.headerPosition} panel=${m.rect} vw=${m.viewport[0]}` +
    (bad.length ? " :: " + bad.join("; ") : "")
  );
}

(async () => {
  const browser = await launch();
  const r = reporter("DROPDOWN");

  /* ---- 1. Every page, viewport and theme, before any scan --------------- */
  for (const [pn, path] of PAGES) {
    for (const [vn, w, h] of VIEWPORTS) {
      for (const theme of ["dark", "light"]) {
        const page = await newPage(browser, { w, h, theme });
        await page.goto(BASE + path, { waitUntil: "networkidle2" });
        await sleep(500);
        await checkMenu(page, `${pn} ${vn} ${theme} pre-scan`, r);
        await page.close();
      }
    }
  }

  /* ---- 2. After results render: evidence on/off, top/middle/bottom ------ */
  for (const [vn, w, h] of VIEWPORTS) {
    for (const evidence of [true, false]) {
      for (const where of ["top", "middle", "bottom"]) {
        const page = await newPage(browser, { w, h });
        await scanHeaders(page);
        if (!evidence) {
          await page.evaluate(() => {
            const t = document.querySelector(".evidence-toggle input");
            if (t && t.checked) t.click();
          });
          await sleep(400);
        }
        await scrollTo(page, where);
        await checkMenu(page, `headers-report ${vn} evidence=${evidence} ${where}`, r);
        await page.close();
      }
    }
  }

  /* ---- 3. GitHub project-path mount ------------------------------------- */
  for (const [vn, w, h] of [["desktop", 1920, 1080], ["phone", 390, 844]]) {
    const page = await newPage(browser, { w, h });
    await page.goto(BASE + "/CyberBuddy/tools/headers/", { waitUntil: "networkidle2" });
    await sleep(500);
    const hrefs = await page.evaluate(() =>
      [...document.querySelectorAll(".header-inner .nav-menu-panel a")]
        .map((a) => new URL(a.getAttribute("href"), location.href).pathname));
    r.check(
      hrefs.length === 5 && hrefs.every((h) => h.startsWith("/CyberBuddy/tools/")),
      `project-mount links ${vn} ${JSON.stringify(hrefs)}`
    );
    await checkMenu(page, `project-mount ${vn}`, r);
    await page.close();
  }

  /* ---- 4. Every live link actually navigates, from a result page -------- */
  {
    const page = await newPage(browser, { w: 1366, h: 768 });
    for (const target of ["/tools/clickjacking/", "/tools/headers/", "/tools/cors/", "/tools/csp/", "/tools/csrf/"]) {
      await scanHeaders(page);
      await scrollTo(page, "top");
      await page.evaluate(async (t) => {
        const details = document.querySelector(".header-inner details.nav-menu");
        const summary = details.querySelector("summary");
        summary.scrollIntoView({ block: "center", behavior: "instant" });
        await new Promise((r) => setTimeout(r, 150));
        summary.click();
        await new Promise((r) => setTimeout(r, 300));
        const link = [...details.querySelectorAll("a.nav-menu-item")]
          .find((a) => a.getAttribute("href").endsWith(t));
        const b = link.getBoundingClientRect();
        const el = document.elementFromPoint(
          Math.round(b.left + b.width / 2), Math.round(b.top + b.height / 2));
        if (!link.contains(el) && el !== link) throw new Error("intercepted by " + el.className);
        el.click();
      }, target);
      await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 15000 }).catch(() => {});
      const got = new URL(page.url()).pathname;
      r.check(got === target, `navigate to ${target} -> ${got}`);
    }

    /* Upcoming tools must be visibly disabled and NOT behave as links; CSRF
       is now live so it must appear as a real link, never as a disabled item. */
    const disabled = await page.evaluate(() =>
      [...document.querySelectorAll(".header-inner .nav-menu-item.disabled")].map((e) => ({
        tag: e.tagName, href: e.getAttribute("href"),
        ariaDisabled: e.getAttribute("aria-disabled"), text: e.textContent.trim().slice(0, 24)
      })));
    r.check(
      disabled.length >= 2 &&
      disabled.every((d) => d.tag !== "A" && !d.href && d.ariaDisabled === "true") &&
      !disabled.some((d) => /CSRF PoC Generator/.test(d.text)) &&
      disabled.some((d) => /TLS \/ SSL Analyzer/.test(d.text)),
      `upcoming tools stay disabled ${JSON.stringify(disabled)}`
    );

    /* Keyboard: focus, Enter/Space open, item focus order. */
    await page.goto(BASE + "/tools/headers/", { waitUntil: "networkidle2" });
    const kb = await page.evaluate(async () => {
      const summary = document.querySelector(".header-inner details.nav-menu summary");
      summary.focus();
      const summaryFocusable = document.activeElement === summary;
      summary.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      summary.click();
      await new Promise((r) => setTimeout(r, 250));
      const opened = summary.parentElement.open;
      const first = summary.parentElement.querySelector("a.nav-menu-item");
      first.focus();
      return { summaryFocusable, opened, itemFocusable: document.activeElement === first };
    });
    r.check(kb.summaryFocusable && kb.opened && kb.itemFocusable, `keyboard ${JSON.stringify(kb)}`);

    /* The active tool stays visually identified. */
    const active = await page.evaluate(() => {
      const a = document.querySelector(".header-inner .nav-menu-item.active");
      return a && a.getAttribute("href");
    });
    r.check(!!active && active.endsWith("/tools/headers/"), `active tool marked ${active}`);
    await page.close();
  }

  r.done();
  await browser.close();
})();
