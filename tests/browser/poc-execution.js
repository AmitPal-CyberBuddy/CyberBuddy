/* Executes generated standalone PoCs only against disposable loopback receivers.
 * Unlike source-string tests this distinguishes a delivered-but-unreadable
 * simple POST from an OPTIONS preflight that prevented the actual POST.
 * Requires puppeteer-core and @axe-core/puppeteer (see README).
 */
"use strict";
const assert = require("node:assert/strict");
const http = require("node:http");
const { once } = require("node:events");
const { AxePuppeteer } = require("@axe-core/puppeteer");
const { launch } = require("./lib");
require("../../js/tool.csrf.js");
require("../../js/tool.cors.js");
const C = globalThis.CyberBuddyCsrf;
const requests = [];
let documentHtml = "";
const receiver = http.createServer((req, res) => {
  let body = "";
  req.on("data", chunk => { body += chunk; });
  req.on("end", () => {
    requests.push({ method: req.method, path: req.url, body, headers: req.headers });
    if (req.url.startsWith("/slow")) return;
    if (!req.url.startsWith("/blocked")) {
      res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, HEAD");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    }
    res.writeHead(req.method === "OPTIONS" ? 204 : req.url.startsWith("/error") ? 403 : 200,
      { "Content-Type": "text/plain" });
    res.end("controlled response");
  });
});
const origin = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(documentHtml);
});
(async () => {
  receiver.listen(0, "127.0.0.1"); origin.listen(0, "127.0.0.1");
  await Promise.all([once(receiver, "listening"), once(origin, "listening")]);
  const target = `http://127.0.0.1:${receiver.address().port}`;
  const attacker = `http://127.0.0.1:${origin.address().port}`;
  const browser = await launch();
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", e => errors.push(e.message));
    // Exercise the real AbortController path without making the suite wait 15s.
    await page.evaluateOnNewDocument(() => {
      const original = window.setTimeout;
      window.setTimeout = (fn, ms, ...args) => original(fn, ms === 15000 ? 400 : ms, ...args);
    });
    async function open(html) {
      documentHtml = html;
      requests.length = 0;
      await page.goto(attacker, { waitUntil: "load" });
    }
    async function contrast(label) {
      const result = await new AxePuppeteer(page).withRules(["color-contrast"]).analyze();
      assert.deepEqual(result.violations.map(v => v.nodes.map(n => n.failureSummary)), [], label);
    }
    const raw = (path, type, body = "value=1") => `POST ${target}${path} HTTP/1.1\r\nContent-Type: ${type}\r\n\r\n${body}`;
    for (const theme of ["light", "dark"]) {
      await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: theme }]);
      for (const autoSubmit of [false, true]) {
        for (const [path, type, state, posted] of [
          ["/allow", "application/json", "complete", true],
          ["/error", "application/json", "error", true],
          ["/blocked-simple", "text/plain", "warning", true],
          ["/blocked-preflight", "application/json", "warning", false],
          ["/slow", "text/plain", "warning", true]
        ]) {
          const html = C.generatePoc(C.parseRequest(raw(path, type)), { autoSubmit }).variants[0].html;
          await open(html);
          if (!autoSubmit) {
            // Pending state and duplicate-click guard, in the same browser task.
            const pending = await page.evaluate(() => {
              document.querySelector("#send").click();
              const b = document.querySelector("#send");
              b.click();
              return { disabled: b.disabled, busy: b.getAttribute("aria-busy"), text: document.querySelector("#status").textContent };
            });
            assert.equal(pending.disabled, true); assert.equal(pending.busy, "true");
            assert.match(pending.text, /Sending/);
          }
          await page.waitForFunction(() => !document.querySelector("#send").disabled && document.querySelector("#status").dataset.state);
          const status = await page.$eval("#status", e => ({ state: e.dataset.state, text: e.textContent }));
          assert.equal(status.state, state, path);
          assert.equal(requests.filter(r => r.method === "POST").length, posted ? 1 : 0, path);
          if (path === "/blocked-preflight") assert(requests.some(r => r.method === "OPTIONS"));
          if (state === "warning") assert.match(status.text, /delivery unknown/i);
          if (path === "/error") assert.match(status.text, /HTTP 403/);
          if (path === "/slow") assert.match(status.text, /Timed out/);
          await contrast(`CSRF ${theme} ${path}`);
          console.log(`ok CSRF ${theme} auto=${autoSubmit} ${path}: ${state}; POST=${posted}`);
        }
      }
      // CORS PoC: readable HTTP errors aren't a network/CORS failure.
      for (const [path, state] of [["/allow", "complete"], ["/error", "error"], ["/blocked-simple", "warning"], ["/slow", "warning"]]) {
        await open(CyberBuddyCorsPoc.generatePocHtml({ url: target + path }).html);
        await page.click("#run");
        await page.waitForFunction(() => !document.querySelector("#run").disabled && document.querySelector("#out").dataset.state);
        assert.equal(await page.$eval("#out", e => e.dataset.state), state);
        assert.equal(requests.filter(r => r.method === "GET").length, 1);
        await contrast(`CORS ${theme} ${path}`);
        console.log(`ok CORS ${theme} ${path}: ${state}`);
      }
    }
    // Native form serialization and navigation, including an input named submit.
    for (const autoSubmit of [false, true]) {
      documentHtml = C.generatePoc(C.parseRequest(raw("/form", "application/x-www-form-urlencoded", "submit=keep&dup=1&dup=2&blank=")), { autoSubmit }).variants[0].html;
      requests.length = 0;
      if (autoSubmit) {
        await page.goto(attacker);
        await page.waitForFunction(url => location.href === url, {}, target + "/form");
      } else {
        await page.goto(attacker);
        await Promise.all([page.waitForNavigation(), page.click("#send")]);
      }
      assert.equal(requests.filter(r => r.method === "POST").length, 1);
      assert.equal(requests.find(r => r.method === "POST").body, "submit=keep&dup=1&dup=2&blank=");
      console.log(`ok form navigation auto=${autoSubmit}: exact field serialization`);
    }
    assert.deepEqual(errors, [], "standalone runtime errors");
  } finally {
    await browser.close();
    receiver.closeAllConnections(); origin.closeAllConnections();
    receiver.close(); origin.close();
  }
})().catch(e => { console.error(e); process.exit(1); });
