/* Real-browser regression suite for the CSRF PoC Generator.
 *
 * The generator is deliberately unlike the four scanners: it takes a pasted
 * Burp request and produces HTML without ever talking to the network. This
 * suite pins the contract:
 *   - paste → generate renders the report (READY/LIMITED/NOT DIRECTLY
 *     REPRESENTABLE) with parsed method/URL/content-type;
 *   - malformed input shows announced validation feedback;
 *   - Copy HTML / Copy Markdown / Download all act on the generated source;
 *   - the auto-submit toggle changes the generated source and shows a warning;
 *   - no network request to the pasted host, and the raw request never lands
 *     in the URL or in localStorage/sessionStorage;
 *   - the source preview is inert (text only, never executed);
 *   - the result stays responsive at seven widths in both themes.
 *
 * See tests/browser/lib.js for how to run this.
 */
"use strict";

const { BASE, launch, newPage, sleep, reporter } = require("./lib");

const VPS = [
  ["monitor", 2560, 1440],
  ["desktop", 1920, 1080],
  ["laptop", 1366, 768],
  ["tabletL", 1024, 768],
  ["tabletP", 768, 1024],
  ["phone", 390, 844],
  ["small", 360, 740]
];

const SAMPLE =
  "POST /account/change-email HTTP/1.1\r\n" +
  "Host: app.example.com\r\n" +
  "Content-Type: application/x-www-form-urlencoded\r\n" +
  "Cookie: session=UNIQUE-MARKER-123\r\n" +
  "\r\n" +
  "email=attacker%40example.com&csrf_token=TOK-MARKER";

async function fillAndGenerate(page, raw) {
  await page.$eval("#request", (el, v) => { el.value = v; }, raw);
  await page.click("#generate");
  await page.waitForFunction(
    () => !document.getElementById("results").classList.contains("hidden"),
    { timeout: 10000 }
  );
  await sleep(250);
}

const audit = () => {
  const vw = innerWidth;
  const out = {
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    spill: [],
    tiny: []
  };
  document.querySelectorAll("#results *").forEach((el) => {
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden") return;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return;
    if ((r.right > vw + 1 || r.left < -1) && cs.position !== "fixed") {
      const name = el.id ? "#" + el.id : (el.className || "").toString().slice(0, 20);
      out.spill.push(name);
    }
  });
  if (vw <= 860) {
    document.querySelectorAll("#results button, #results input[type=checkbox]").forEach((el) => {
      const label = el.closest("label");
      const hit = label ? label.getBoundingClientRect() : el.getBoundingClientRect();
      if (hit.height < 24 || hit.width < 24) {
        out.tiny.push((el.id || el.textContent || "").toString().slice(0, 14));
      }
    });
  }
  return out;
};

(async () => {
  const browser = await launch();
  const r = reporter("CSRF");

  /* ---- 1. Paste → generate renders the report -------------------------- */
  {
    const page = await newPage(browser, { w: 1366, h: 768 });
    await page.goto(BASE + "/tools/csrf/", { waitUntil: "networkidle2" });
    await fillAndGenerate(page, SAMPLE);
    const m = await page.evaluate(() => ({
      verdict: document.getElementById("verdict").textContent.trim(),
      method: document.getElementById("mMethod").textContent.trim(),
      url: document.getElementById("mUrl").textContent.trim(),
      contentType: document.getElementById("mContentType").textContent.trim(),
      repro: document.getElementById("mRepro").textContent.trim(),
      source: document.getElementById("pocSource").textContent,
      variants: [...document.querySelectorAll("#variants input[name=csrfVariant]")].length,
      tokenPanelShown: !document.getElementById("tokensPanel").classList.contains("hidden"),
      tokenNames: [...document.querySelectorAll("#tokenList code")].map((c) => c.textContent.trim()),
      downloadEnabled: !document.getElementById("download").disabled,
      copyEnabled: !document.getElementById("copyHtml").disabled
    }));
    r.check(
      m.verdict === "READY" && m.method === "POST" && /app\.example\.com/.test(m.url) &&
      m.contentType === "application/x-www-form-urlencoded" &&
      m.repro === "simple request · no preflight" &&
      m.source.includes('name="email"') && m.source.includes("app.example.com") &&
      m.variants >= 1 && m.tokenPanelShown && m.tokenNames.includes("csrf_token") &&
      m.downloadEnabled && m.copyEnabled,
      `generate ${JSON.stringify({
        verdict: m.verdict, method: m.method, contentType: m.contentType,
        repro: m.repro, variants: m.variants, tokens: m.tokenNames
      })}`
    );
    await page.close();
  }

  /* ---- 2. Malformed input → announced validation feedback --------------- */
  {
    const page = await newPage(browser, { w: 390, h: 844 });
    await page.goto(BASE + "/tools/csrf/", { waitUntil: "networkidle2" });
    await page.$eval("#request", (el) => { el.value = "this is not an http request"; });
    await page.click("#generate");
    await sleep(150);
    const m = await page.evaluate(() => ({
      visible: !document.getElementById("requestError").classList.contains("hidden") &&
        document.getElementById("requestError").getBoundingClientRect().height > 0,
      text: document.getElementById("requestError").textContent.trim(),
      invalid: document.getElementById("request").getAttribute("aria-invalid"),
      resultsHidden: document.getElementById("results").classList.contains("hidden")
    }));
    r.check(
      m.visible && /request line/i.test(m.text) && m.invalid === "true" && m.resultsHidden,
      `validation ${JSON.stringify(m)}`
    );
    await page.close();
  }

  /* ---- 3. Copy HTML copies the generated source ------------------------ */
  {
    const page = await newPage(browser, { w: 1366, h: 768 });
    await page.goto(BASE + "/tools/csrf/", { waitUntil: "networkidle2" });
    await fillAndGenerate(page, SAMPLE);
    await page.evaluate(() => {
      window.__copied = null;
      const w = (text) => { window.__copied = text; return Promise.resolve(); };
      if (!navigator.clipboard) {
        Object.defineProperty(navigator, "clipboard", { value: { writeText: w }, configurable: true });
      } else {
        navigator.clipboard.writeText = w;
      }
    });
    await page.click("#copyHtml");
    await sleep(150);
    const m = await page.evaluate(() => ({
      copied: window.__copied,
      source: document.getElementById("pocSource").textContent,
      label: document.getElementById("copyHtml").textContent.trim()
    }));
    r.check(
      m.copied === m.source && m.source.length > 100 && /Copied|✓/.test(m.label),
      `copy-html ${JSON.stringify({ len: m.copied && m.copied.length, label: m.label })}`
    );
    await page.close();
  }

  /* ---- 4. Copy Markdown: assessment with references, no secrets --------- */
  {
    const page = await newPage(browser, { w: 1366, h: 768 });
    await page.goto(BASE + "/tools/csrf/", { waitUntil: "networkidle2" });
    await fillAndGenerate(page, SAMPLE);
    await page.evaluate(() => {
      window.__copied = null;
      const w = (text) => { window.__copied = text; return Promise.resolve(); };
      if (!navigator.clipboard) {
        Object.defineProperty(navigator, "clipboard", { value: { writeText: w }, configurable: true });
      } else {
        navigator.clipboard.writeText = w;
      }
    });
    await page.click("#copyMd");
    await sleep(150);
    const md = await page.evaluate(() => window.__copied);
    r.check(
      !!md && /CSRF PoC Generator/.test(md) && /WSTG-SESS-05/.test(md) && /CWE-352/.test(md) &&
      !/UNIQUE-MARKER-123/.test(md) && !/TOK-MARKER/.test(md),
      `copy-markdown ${JSON.stringify({ len: md && md.length, hasRef: !!(md && /WSTG-SESS-05/.test(md)) })}`
    );
    await page.close();
  }

  /* ---- 5. Download constructs a blob + hostname-based filename --------- */
  {
    const page = await newPage(browser, { w: 1366, h: 768 });
    await page.goto(BASE + "/tools/csrf/", { waitUntil: "networkidle2" });
    await fillAndGenerate(page, SAMPLE);
    await page.evaluate(() => {
      window.__dl = { blobCalls: 0, filename: "" };
      const orig = URL.createObjectURL;
      URL.createObjectURL = function (b) {
        window.__dl.blobCalls++;
        return orig ? orig.call(URL, b) : "blob:fake";
      };
      HTMLAnchorElement.prototype.click = function () {
        window.__dl.filename = this.getAttribute("download") || "";
      };
    });
    await page.click("#download");
    await sleep(150);
    const dl = await page.evaluate(() => window.__dl);
    r.check(
      dl.blobCalls >= 1 && /^csrf-post-app\.example\.com/.test(dl.filename),
      `download ${JSON.stringify(dl)}`
    );
    await page.close();
  }

  /* ---- 6. Auto-submit toggle changes source + shows warning ------------- */
  {
    const page = await newPage(browser, { w: 1366, h: 768 });
    await page.goto(BASE + "/tools/csrf/", { waitUntil: "networkidle2" });
    await fillAndGenerate(page, SAMPLE);
    const before = await page.evaluate(() => document.getElementById("pocSource").textContent);
    const warnHiddenBefore = await page.evaluate(() =>
      document.getElementById("autoSubmitWarn").classList.contains("hidden"));
    await page.click("#autoSubmit");
    await sleep(200);
    const after = await page.evaluate(() => ({
      source: document.getElementById("pocSource").textContent,
      warnVisible: !document.getElementById("autoSubmitWarn").classList.contains("hidden")
    }));
    r.check(
      !/AUTO-SUBMIT ENABLED/.test(before) && /Send request/.test(before) &&
      /AUTO-SUBMIT ENABLED/.test(after.source) &&
      after.source.includes('document.getElementById("csrf-form").submit();') &&
      warnHiddenBefore && after.warnVisible,
      `auto-submit ${JSON.stringify({ warnHiddenBefore, warnVisibleAfter: after.warnVisible })}`
    );
    await page.close();
  }

  /* ---- 7. No network request, no URL/storage leak ----------------------- */
  {
    const page = await newPage(browser, { w: 1366, h: 768 });
    await page.setRequestInterception(true);
    const requests = [];
    page.on("request", (q) => { requests.push(q.url()); q.continue(); });
    await page.goto(BASE + "/tools/csrf/", { waitUntil: "networkidle2" });
    await fillAndGenerate(page, SAMPLE);
    await sleep(300);
    const m = await page.evaluate(() => {
      const vals = [];
      try {
        Object.keys(localStorage).forEach((k) => vals.push(localStorage.getItem(k)));
        Object.keys(sessionStorage).forEach((k) => vals.push(sessionStorage.getItem(k)));
      } catch (_) { /* private mode */ }
      return {
        href: location.href,
        storageLeaks: vals.join("\n").includes("UNIQUE-MARKER-123")
      };
    });
    const victim = requests.filter((u) => /app\.example\.com/.test(u));
    r.check(
      victim.length === 0 && !/UNIQUE-MARKER-123/.test(m.href) && !m.storageLeaks,
      `no-network ${JSON.stringify({ victimRequests: victim, hrefHasMarker: /UNIQUE-MARKER-123/.test(m.href), storageLeaks: m.storageLeaks })}`
    );
    await page.close();
  }

  /* ---- 8. Source preview is inert --------------------------------------- */
  {
    const page = await newPage(browser, { w: 1366, h: 768 });
    await page.goto(BASE + "/tools/csrf/", { waitUntil: "networkidle2" });
    await fillAndGenerate(page, SAMPLE);
    const m = await page.evaluate(() => {
      const pre = document.getElementById("pocSource");
      return {
        childElements: pre.children.length,
        hasForm: !!pre.querySelector("form"),
        hasScriptElement: !!pre.querySelector("script"),
        isTextOnly: pre.textContent.length > 100
      };
    });
    r.check(
      m.childElements === 0 && !m.hasForm && !m.hasScriptElement && m.isTextOnly,
      `inert-preview ${JSON.stringify(m)}`
    );
    await page.close();
  }

  /* ---- 9. Seven widths × both themes, generated result ------------------ */
  for (const [vn, w, h] of VPS) {
    for (const theme of ["dark", "light"]) {
      const page = await newPage(browser, { w, h, theme });
      await page.goto(BASE + "/tools/csrf/", { waitUntil: "networkidle2" });
      await fillAndGenerate(page, SAMPLE);
      const a = await page.evaluate(audit);
      r.check(
        a.overflow === 0 && !a.spill.length && !a.tiny.length,
        `responsive ${vn} ${theme} ${JSON.stringify(a)}`
      );
      await page.close();
    }
  }

  r.done();
  await browser.close();
})();
