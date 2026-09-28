/* CyberBuddy — CORS Validator page controller.
   Externalised from an inline <script> so the site can ship a CSP without
   'unsafe-inline'. Depends on js/app.js.

   CyberBuddyCorsPoc is a pure local HTML generator (no DOM, no network).
   A reflected ACAO header is server behaviour; the downloaded page is a
   TEST ARTIFACT you host on an origin you control. It is not a finding. */
"use strict";

var CyberBuddyCorsPoc = (function () {
  function escHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* A JS string literal that round-trips `value` and cannot terminate its
     <script> element: JSON.stringify plus every `<` escaped. */
  function jsLiteral(value) {
    return JSON.stringify(String(value == null ? "" : value))
      .replace(/</g, "\\u003c")
      .replace(/\u2028/g, "\\u2028")
      .replace(/\u2029/g, "\\u2029");
  }

  function validatePocUrl(raw) {
    var cleaned = String(raw == null ? "" : raw).trim();
    if (!cleaned) return { ok: false, error: "Enter a target URL." };
    var parsed;
    try { parsed = new URL(cleaned); }
    catch (_) { return { ok: false, error: "That is not a usable URL." }; }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { ok: false, error: "Only http(s) targets are allowed." };
    }
    if (parsed.username || parsed.password) {
      return { ok: false, error: "Remove the username and password from the URL." };
    }
    return { ok: true, url: parsed.href };
  }

  function generatePocHtml(opts) {
    opts = opts || {};
    var checked = validatePocUrl(opts.url);
    if (!checked.ok) return { ok: false, error: checked.error };
    var target = checked.url;
    var html = [
      "<!DOCTYPE html>",
      "<html lang=\"en\">",
      "<head>",
      "  <meta charset=\"utf-8\">",
      "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
      "  <title>CORS browser PoC — TEST ARTIFACT</title>",
      "  <style>",
      "    :root{color-scheme:light dark;--bg:#f4f7fb;--panel:#fff;--ink:#172033;--accent:#0b756b;--on:#fff;--info:#175cd3;--warn:#93370d;--error:#b42318;--line:#667085}",
      "    @media(prefers-color-scheme:dark){:root{--bg:#0a0d13;--panel:#10161f;--ink:#eef3f8;--accent:#3ee0c2;--on:#04110e;--info:#9dbbff;--warn:#ffd47c;--error:#ff9ba5;--line:#7d8798}}",
      "    body{font:16px/1.6 system-ui,sans-serif;max-width:800px;margin:32px auto;padding:0 20px;color:var(--ink);background:var(--bg)}",
      "    h1{font-size:1.35rem} h2{font-size:1rem}",
      "    .banner,.note{padding:14px 16px;border:1px solid var(--line);border-left:4px solid var(--warn);background:var(--panel);border-radius:8px}",
      "    button{font:inherit;font-weight:700;padding:12px 20px;cursor:pointer;color:var(--on);background:var(--accent);border:2px solid transparent;border-radius:8px;transition:transform .12s}",
      "    button:active{transform:translateY(2px) scale(.98)} button:focus-visible{outline:3px solid var(--info);outline-offset:3px} button:disabled{cursor:wait}",
      "    button[aria-busy=\"true\"]::before{content:\"\";display:inline-block;width:14px;height:14px;margin-right:10px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .8s linear infinite}",
      "    pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--panel);padding:14px;min-height:6em;border:1px solid var(--line);border-left:5px solid var(--info);border-radius:8px;color:var(--info)}",
      "    pre[data-state=\"warning\"]{color:var(--warn);border-color:var(--warn)} pre[data-state=\"error\"]{color:var(--error);border-color:var(--error)}",
      "    code{overflow-wrap:anywhere} @keyframes spin{to{transform:rotate(360deg)}} @media(prefers-reduced-motion:reduce){*,*::before{animation:none!important;transition:none!important}}",
      "  </style>",
      "</head>",
      "<body>",
      "  <h1>CORS browser proof of concept</h1>",
      "  <p class=\"banner\"><strong>TEST ARTIFACT — not a finding.</strong> Authorized testing only. A readable cross-origin response proves this origin can see the body, not that credentials were attached or sensitive data exposed. A blocked fetch is not a pass for every method. Opening this file locally sends Origin: null — that is a different test.</p>",
      "  <p>Target: <code>" + escHtml(target) + "</code></p>",
      "  <p>Method: GET · credentials: include</p>",
      "  <p><button id=\"run\" type=\"button\">Run credentialed GET</button></p>",
      "  <pre id=\"out\" role=\"status\" aria-live=\"polite\" aria-atomic=\"true\">Ready — no request sent yet.</pre>",
      "  <section class=\"note\"><h2>Verification notes</h2><p>A failed fetch does not prove no request was sent: CORS can block response access after delivery. Check DevTools Network and server logs. Cookies depend on SameSite, Secure and browser privacy settings. Verify the origin is different from the target, that credentials were actually included, and that the response contains account-specific data before claiming an authenticated leak.</p></section>",
      "  <script>",
      "    (function () {",
      "      var target = " + jsLiteral(target) + ";",
      "      document.getElementById(\"run\").addEventListener(\"click\", function () {",
      "        var out = document.getElementById(\"out\"), button = document.getElementById(\"run\");",
      "        if (button.disabled) return;",
      "        button.disabled = true; button.setAttribute(\"aria-busy\", \"true\"); button.textContent = \"Running\u2026\";",
      "        out.dataset.state = \"pending\"; out.textContent = \"Sending credentialed GET \u2014 waiting for a readable response\u2026\";",
      "        var controller = new AbortController();",
      "        var timer = setTimeout(function () { controller.abort(); }, 15000);",
      "        Promise.resolve().then(function () { return fetch(target, { method: \"GET\", credentials: \"include\", cache: \"no-store\", signal: controller.signal }); })",
      "          .then(function (res) { return res.text().then(function (text) {",
      "            out.dataset.state = res.ok ? \"complete\" : \"error\";",
      "            out.textContent = \"Response received \u2014 HTTP \" + res.status + \"\\nReadable: yes (not proof of authenticated data exposure)\\n\\n\" + String(text).slice(0, 8000);",
      "          }); })",
      "          .catch(function (err) {",
      "            out.dataset.state = \"warning\";",
      "            out.textContent = (err.name === \"AbortError\" ? \"Timed out after 15 seconds\" : \"No readable response\") + \" \u2014 delivery unknown.\\nThe browser did not expose the response to this origin. The request may have been sent. See verification notes below.\";",
      "          }).finally(function () {",
      "            clearTimeout(timer); button.disabled = false; button.removeAttribute(\"aria-busy\"); button.textContent = \"Run again\";",
      "          });",
      "      });",
      "    })();",
      "  </script>",
      "</body>",
      "</html>",
      ""
    ].join("\n");
    return {
      ok: true,
      url: target,
      html: html,
      filename: "cyberbuddy-cors-poc.html"
    };
  }

  return {
    validatePocUrl: validatePocUrl,
    generatePocHtml: generatePocHtml
  };
})();

if (typeof globalThis !== "undefined") {
  globalThis.CyberBuddyCorsPoc = CyberBuddyCorsPoc;
}

(function () {
  if (typeof document === "undefined") return;

  let cbLastData = null;
  let lastPoc = null;

  function $(id) { return document.getElementById(id); }

  function setVerdict(risk, text) {
    const r = (risk || "").toLowerCase();
    const isPass = r === "low" || r === "pass";
    const displayRisk = isPass ? "PASS" : (risk === "PROBING" ? "PROBING" : (risk || "UNKNOWN").toUpperCase());
    $("verdict").textContent = displayRisk;
    $("verdict").className = "risk " + (risk === "PROBING" ? "unknown" : (isPass ? "low" : r));
    bump($("verdict"));
    $("summary").textContent = text;
    $("verdictBanner").className = "verdict-banner " +
      (risk === "PROBING" ? "unknown" : (isPass ? "low" : r));
    let label, cls;
    if (r === "probing") { label = "CORS policy: checking…"; cls = "unknown"; }
    else if (isPass) { label = "CORS policy: RESTRICTIVE (PASS) — cross-origin reads are blocked for tested methods"; cls = "low"; }
    else if (r === "medium") { label = "CORS policy: PERMISSIVE — review the findings"; cls = "medium"; }
    else if (r === "high") { label = "CORS policy: HIGH RISK — reflection + credentials; verify browser exposure"; cls = "high"; }
    else { label = "CORS policy: UNABLE TO DETERMINE"; cls = "unknown"; }
    $("protection").textContent = label;
    $("protection").className = "protection-line " + cls;
  }

  function renderChecks(checks, data) {
    const tbody = $("checks").querySelector("tbody");
    tbody.innerHTML = (checks || []).map((c, i) =>
      findingRowHtml(c, { copy: true, index: i })
    ).join("");
    bindFindingCopy(tbody, checks || [], "CORS Validator", data && data.url);
    $("posture").innerHTML = postureHtml(checks);
  }

  function renderCoverage(data) {
    const wrap = $("corsCoverage");
    if (!wrap) return;
    if (!data || !data.method_results || !data.method_results.length) {
      wrap.innerHTML = "";
      wrap.classList.add("hidden");
      return;
    }
    const rows = data.method_results.map((mr) => {
      const label = mr.kind === "preflight" ? "Preflight " + (mr.request_method || "") : mr.method;
      const status = mr.status_code != null ? String(mr.status_code) : "—";
      const risk = (mr.risk || "—").toUpperCase();
      const riskCls = (mr.risk || "unknown").toLowerCase();
      const evidence = esc(mr.evidence || (mr.headers && mr.headers["access-control-allow-origin"] ? mr.headers["access-control-allow-origin"] : "—"));
      const unassessed = mr.unassessed ? " <span class=\"unassessed-badge\">not assessed</span>" : "";
      return "<tr><td>" + esc(label) + unassessed + "</td><td>" + esc(mr.kind || "direct") + "</td><td><span class=\"risk " + esc(riskCls) + "\">" + esc(risk) + "</span></td><td>" + esc(status) + "</td><td><code>" + evidence + "</code></td></tr>";
    }).join("");
    const browserNote = data._source === "browser"
      ? "<p class=\"form-hint\">Browser probe — single origin only. Cannot forge Origin, cannot set Access-Control-Request-Method/Headers, cannot inspect automatic preflight. Run <code>python3 server.py</code> for two-origin/null/preflight proof.</p>"
      : "";
    const preflightNote = data.preflight_methods && data.preflight_methods.length
      ? "<p class=\"form-hint\">Preflight uses OPTIONS + Origin + Access-Control-Request-Method; target must be authorized and may not support every method. Custom Access-Control-Request-Headers is a Python/CLI option, not a field on this page.</p>"
      : "";
    wrap.innerHTML = '<h3 class="card-title">Method coverage</h3>' +
      browserNote + preflightNote +
      '<table class="method-table" aria-label="CORS method coverage"><thead><tr><th>Method</th><th>Kind</th><th>Risk</th><th>HTTP</th><th>Evidence</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      '<p class="form-hint">Selected: ' + esc((data.methods || []).join(", ") || "GET") + (data.preflight_methods && data.preflight_methods.length ? " · preflight: " + esc(data.preflight_methods.join(", ")) + (data.preflight_headers && data.preflight_headers.length ? " headers=" + esc(data.preflight_headers.join(", ")) : "") : "") + ' · Tested: ' + esc((data.tested_methods || []).join(", ") || "—") + (data.unassessed_methods && data.unassessed_methods.length ? " · Unassessed: " + esc(data.unassessed_methods.join(", ")) : "") + '</p>';
    wrap.classList.remove("hidden");
  }

  function finish(data) {
    cbLastData = data;
    const flag = $("reportTitleFlag");
    if (flag) flag.innerHTML = unverifiedFlag(data);
    renderProvenance(data, "CORS Validator");
    enterEvidenceMode();
  }

  function getSelectedCorsOpts() {
    const methods = ["GET"];
    if ($("corsHead") && $("corsHead").checked) methods.push("HEAD");
    if ($("corsOptions") && $("corsOptions").checked) methods.push("OPTIONS");
    const preflight = [];
    if ($("corsPreflightPost") && $("corsPreflightPost").checked) preflight.push("POST");
    return { methods: methods, preflight: preflight, preflight_headers: [] };
  }

  function setPocStatus(text, isError) {
    const el = $("corsPocStatus");
    if (!el) return;
    if (!text) {
      el.hidden = true;
      el.textContent = "";
      return;
    }
    el.hidden = false;
    el.textContent = text;
    el.classList.toggle("field-error", !!isError);
  }

  function setPocButtons(enabled) {
    ["corsPocDownload", "corsPocCopy"].forEach(function (id) {
      const btn = $(id);
      if (btn) btn.disabled = !enabled;
    });
  }

  function buildPoc() {
    const url = validateUrlField($("url"));
    if (!url) {
      lastPoc = null;
      setPocButtons(false);
      setPocStatus("Enter an authorized target URL first.", true);
      return;
    }
    const gen = CyberBuddyCorsPoc.generatePocHtml({ url: url });
    const source = $("corsPocSource");
    if (!gen.ok) {
      lastPoc = null;
      setPocButtons(false);
      setPocStatus(gen.error, true);
      if (source) {
        source.classList.add("hidden");
        source.textContent = "(build a PoC to preview it here)";
      }
      return;
    }
    lastPoc = gen;
    setPocButtons(true);
    setPocStatus("Local TEST ARTIFACT ready. Host it on an origin you control — it does not run a request from this page.");
    if (source) {
      source.classList.remove("hidden");
      source.textContent = gen.html;
    }
  }

  async function probe(url) {
    $("results").classList.remove("hidden");
    setVerdict("PROBING", "Checking " + url + "…");
    $("mTarget").textContent = url;
    $("mStamp").textContent = fmtStampUtc();
    setLoading($("go"), true);

    const t0 = (window.performance && typeof performance.now === "function")
      ? performance.now() : null;

    // A direct CORS probe does not use a relay, but the hosted NXDOMAIN
    // preflight uses public DNS. Reuse the same explicit privacy gate.
    const consent = await ensureRelayConsent(url);
    if (consent === "deny") {
      setVerdict("UNKNOWN", "Hosted DNS/header lookups were declined. Run python3 server.py for a local scan.");
      setLoading($("go"), false);
      return;
    }

    const opts = getSelectedCorsOpts();
    const engine = await apiCors(url, opts);
    if (engine && t0 != null) {
      engine._duration_ms = Math.max(1, Math.round(performance.now() - t0));
    }
    setSourceChip(engine || { _source: "none" });

    const fillMeta = (data) => {
      $("mEngine").textContent = sourceLabel(data || { _source: "none" });
      // Show actual methods tested, not a static GET
      const tested = (data && data.tested_methods && data.tested_methods.length) ? data.tested_methods.join(", ") : ((data && data.methods && data.methods.length) ? data.methods.join(", ") : "GET");
      const requested = data && data.methods ? data.methods.join(", ") + (data.preflight_methods && data.preflight_methods.length ? " + preflight " + data.preflight_methods.join(", ") : "") : "GET · read-only";
      $("mMethod").textContent = tested || requested;
      // For completeness, also show selected vs tested in title
      if (data && data.unassessed_methods && data.unassessed_methods.length) {
        $("mMethod").title = "Selected: " + (data.methods || []).join(", ") + (data.preflight_methods && data.preflight_methods.length ? " + preflight " + data.preflight_methods.join(", ") : "") + " · Tested: " + tested + " · Unassessed: " + data.unassessed_methods.join(", ");
      } else {
        $("mMethod").title = "CORS methods probed for this scan";
      }
      $("mChecks").textContent = String((data && data.checks ? data.checks : []).length);
      $("mDuration").textContent = data && data._duration_ms != null ? data._duration_ms + " ms" : "—";
    };

    if (engine && engine._unreachable) {
      $("mOrigin").textContent = "engine";
      $("mStatus").textContent = "—";
      setVerdict("UNREACHABLE", "Target not reachable — " + unreachableDetail(engine));
      renderChecks(engine.checks, engine);
      renderCoverage(engine);
      fillMeta(engine);
      setLoading($("go"), false);
      finish(engine);
      return;
    }
    if (!isEngineDown(engine) && engine && (engine.checks || engine.error)) {
      const origins = (engine.origins_tested || []).join(" · ") || "engine";
      $("mOrigin").textContent = origins;
      $("mStatus").textContent = engine.status_code != null ? String(engine.status_code) : "—";
      if (engine.error && !engine.checks) {
        setVerdict("UNKNOWN", engine.error);
        renderChecks([], engine);
        renderCoverage(engine);
        fillMeta(engine);
        setLoading($("go"), false);
        finish(engine);
        return;
      }
      setVerdict((engine.risk || "unknown").toUpperCase(), engine.summary || "");
      renderChecks(engine.checks, engine);
      renderCoverage(engine);
      fillMeta(engine);
      setLoading($("go"), false);
      finish(engine);
      return;
    }

    fillMeta(engine);
    renderCoverage(engine);
    setLoading($("go"), false);
    finish(engine);
  }

  window.initCors = function initCors() {
    initUrlInput($("url"));
    // Method selection is for authorized testing: the endpoint must exist and may not support every method.
    // Do not invent a PASS for methods not actually tested.
    const head = $("corsHead");
    if (head) head.addEventListener("change", () => { if (head.checked) head.title = "HEAD will be probed with Origin headers"; });
    $("go").addEventListener("click", () => {
      const url = validateUrlField($("url"));
      if (!url) return;
      pushUrlParam(url);
      addRecentScan(url);
      probe(url);
    });

    $("url").addEventListener("keydown", (e) => {
      if (e.key === "Enter") $("go").click();
    });

    const buildBtn = $("corsPocBuild");
    if (buildBtn) buildBtn.addEventListener("click", buildPoc);
    const downloadBtn = $("corsPocDownload");
    if (downloadBtn) {
      downloadBtn.addEventListener("click", () => {
        if (!lastPoc || !lastPoc.html) return;
        downloadBlob(new Blob([lastPoc.html], { type: "text/html" }), lastPoc.filename);
        flashBtn(downloadBtn, true, "HTML saved ✓");
      });
    }
    const copyBtn = $("corsPocCopy");
    if (copyBtn) {
      copyBtn.addEventListener("click", async () => {
        if (!lastPoc || !lastPoc.html) return;
        const ok = await copyText(lastPoc.html);
        flashBtn(copyBtn, ok, "HTML copied ✓");
      });
    }

    initExportMenu("CORS Validator", () => cbLastData);
    initEvidenceToggle();

    const initial = new URLSearchParams(location.search).get("url");
    if (initial) {
      $("url").value = initial;
      const url = validateUrlField($("url"), false);
      if (url) probe(url);
    }
  };
})();
