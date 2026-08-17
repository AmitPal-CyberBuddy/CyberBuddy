/* CyberBuddy — CORS Validator page controller.
   Externalised from an inline <script> so the site can ship a CSP without
   'unsafe-inline'. Depends on js/app.js. */
"use strict";

(function () {
  let cbLastData = null;

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
    else if (r === "high") { label = "CORS policy: VULNERABLE — reflection + credentials"; cls = "high"; }
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
      ? "<p class=\"form-hint\">Preflight uses OPTIONS + Origin + Access-Control-Request-Method; target must be authorized and may not support every method.</p>"
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
    const preflightHeaders = [];
    if ($("corsPreflightPost") && $("corsPreflightPost").checked) preflight.push("POST");
    const hdrInput = $("corsPreflightHeaders");
    if (hdrInput && hdrInput.value.trim()) {
      hdrInput.value.split(",").forEach((h) => { const t = h.trim(); if (t) preflightHeaders.push(t); });
    }
    return { methods: methods, preflight: preflight, preflight_headers: preflightHeaders };
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
    const opts = $("corsOptions");
    const pre = $("corsPreflightPost");
    const hdr = $("corsPreflightHeaders");
    if (head) head.addEventListener("change", () => { if (head.checked) head.title = "HEAD will be probed with Origin headers"; });
    if (opts) opts.addEventListener("change", () => {});
    if (pre) pre.addEventListener("change", () => {
      if (hdr) hdr.disabled = !pre.checked;
      if (pre.checked && hdr) hdr.placeholder = "Content-Type, X-Custom-Header";
    });
    if (hdr) hdr.disabled = !(pre && pre.checked);
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
