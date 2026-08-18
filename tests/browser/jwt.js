/* Real-browser accessibility and interaction regressions for the JWT Workbench.
 *
 * Covers the nested ARIA tablists that choose verification/signing key types,
 * plus the standard-claim helpers. These checks need browser focus behavior;
 * the stdlib suite separately pins the static markup and controller contract.
 *
 * See tests/browser/lib.js for how to run this.
 */
"use strict";

const { BASE, launch, newPage, realErrors, reporter } = require("./lib");

const KEY_LISTS = [
  ".jwt-key-tabs:not(.jwt-edit-key-tabs):not(.jwt-var-key-tabs)",
  ".jwt-edit-key-tabs",
  ".jwt-var-key-tabs"
];

(async () => {
  const browser = await launch();
  const r = reporter("JWT");
  const page = await newPage(browser, { w: 1366, h: 900 });
  await page.goto(BASE + "/tools/jwt/", { waitUntil: "networkidle2" });

  /* Every claim row exposes two distinct controls with two distinct names. */
  const labels = await page.evaluate(() => {
    const claims = ["Iss", "Sub", "Aud", "Exp", "Nbf", "Iat", "Jti"];
    return claims.map((claim) => {
      const use = document.getElementById("jwtHelp" + claim + "Use");
      const value = document.getElementById("jwtHelp" + claim);
      return {
        claim,
        useName: use.getAttribute("aria-label") || "",
        useLabels: use.labels ? use.labels.length : 0,
        valueLabels: value.labels ? [...value.labels].map((label) => label.textContent.trim()) : []
      };
    });
  });
  r.check(
    labels.every((item) => item.useName && item.valueLabels.length === 1),
    `claim helper names ${JSON.stringify(labels)}`
  );

  /* Clicking the visible claim label focuses its value input; it must not
     accidentally toggle the adjacent “set” checkbox. */
  const helperClick = await page.evaluate(() => {
    const checkbox = document.getElementById("jwtHelpIssUse");
    const label = document.querySelector('label[for="jwtHelpIss"]');
    checkbox.checked = false;
    label.click();
    return {
      checkboxStayedOff: !checkbox.checked,
      valueFocused: document.activeElement === document.getElementById("jwtHelpIss")
    };
  });
  r.check(
    helperClick.checkboxStayedOff && helperClick.valueFocused,
    `claim helper click target ${JSON.stringify(helperClick)}`
  );

  /* Main panel tabs and all three key-type tablists use one tab stop, update
     aria-selected/hidden, wrap arrows, and support Home/End. */
  for (const selector of [".jwt-tablist", ...KEY_LISTS]) {
    if (selector.includes("edit-key")) await page.click("#jwt-tab-edit");
    else if (selector.includes("var-key")) await page.click("#jwt-tab-variants");
    else if (selector.includes("jwt-key-tabs")) await page.click("#jwt-tab-analyze");
    const initial = await page.$eval(selector, (list) => {
      const tabs = [...list.querySelectorAll('[role="tab"]')];
      return {
        count: tabs.length,
        tabStops: tabs.filter((tab) => tab.tabIndex === 0).length,
        selected: tabs.filter((tab) => tab.getAttribute("aria-selected") === "true").length
      };
    });
    r.check(
      initial.count >= 3 && initial.tabStops === 1 && initial.selected === 1,
      `${selector} initial roving state ${JSON.stringify(initial)}`
    );

    await page.$eval(selector, (list) => list.querySelector('[tabindex="0"]').focus());
    await page.keyboard.press("ArrowRight");
    const arrow = await page.$eval(selector, (list) => {
      const tabs = [...list.querySelectorAll('[role="tab"]')];
      const active = document.activeElement;
      const panel = document.getElementById(active.getAttribute("aria-controls"));
      return {
        focusInList: tabs.includes(active),
        selected: active.getAttribute("aria-selected"),
        tabIndex: active.tabIndex,
        panelVisible: !!panel && !panel.hidden,
        oneTabStop: tabs.filter((tab) => tab.tabIndex === 0).length === 1
      };
    });
    r.check(
      arrow.focusInList && arrow.selected === "true" && arrow.tabIndex === 0 &&
        arrow.panelVisible && arrow.oneTabStop,
      `${selector} ArrowRight activates ${JSON.stringify(arrow)}`
    );

    await page.keyboard.press("End");
    const end = await page.$eval(selector, (list) => ({
      focused: document.activeElement.id,
      expected: [...list.querySelectorAll('[role="tab"]')].at(-1).id
    }));
    r.check(end.focused === end.expected, `${selector} End ${JSON.stringify(end)}`);

    await page.keyboard.press("Home");
    await page.keyboard.press("ArrowLeft");
    const wrap = await page.$eval(selector, (list) => ({
      focused: document.activeElement.id,
      expected: [...list.querySelectorAll('[role="tab"]')].at(-1).id
    }));
    r.check(wrap.focused === wrap.expected, `${selector} ArrowLeft wraps ${JSON.stringify(wrap)}`);
  }

  const errors = realErrors(page);
  r.check(!errors.length, `console errors ${JSON.stringify(errors)}`);
  await page.close();
  r.done();
  await browser.close();
})();
