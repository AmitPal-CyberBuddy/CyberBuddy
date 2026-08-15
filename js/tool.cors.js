/* CyberBuddy — CORS Validator page controller.
   Externalised from an inline <script> so the site can ship a CSP without
   'unsafe-inline'. Depends on js/app.js. */
"use strict";

(function () {
  let cbLastData = null;

  function $(id) { return document.getElementById(id); }

  function setVerdict(risk, text) {
    $("verdict").textContent = risk;
    $("verdict").className = "risk " + (risk === "PROBING" ? "unknown" : risk.toLowerCase());
    bump($("verdict"));
    $("summary").textContent = text;
    $("verdictBanner").className = "verdict-banner " +
      (risk === "PROBING" ? "unknown" : risk.toLowerCase());
    const r = (risk || "").toLowerCase();
    let label, cls;
    if (r === "probing") { label = "CORS policy: checking…"; cls = "unknown"; }
    else if (r === "low") { label = "CORS policy: RESTRICTIVE — no arbitrary-origin reflection"; cls = "low"; }
    else if (r === "medium") { label = "CORS policy: PERMISSIVE — review the findings"; cls = "medium"; }
    else if (r === "high") { label = "CORS policy: PERMISSIVE — reflection + credentials"; cls = "high"; }
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

  function finish(data) {
    cbLastData = data;
    const flag = $("reportTitleFlag");
    if (flag) flag.innerHTML = unverifiedFlag(data);
    renderProvenance(data, "CORS Validator");
    enterEvidenceMode();
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

    const engine = await apiCors(url);
    if (engine && t0 != null) {
      engine._duration_ms = Math.max(1, Math.round(performance.now() - t0));
    }
    setSourceChip(engine || { _source: "none" });

    const fillMeta = (data) => {
      $("mEngine").textContent = sourceLabel(data || { _source: "none" });
      $("mMethod").textContent = "GET · read-only";
      $("mChecks").textContent = String((data && data.checks ? data.checks : []).length);
      $("mDuration").textContent = data && data._duration_ms != null ? data._duration_ms + " ms" : "—";
    };

    if (engine && engine._unreachable) {
      $("mOrigin").textContent = "engine";
      $("mStatus").textContent = "—";
      setVerdict("UNREACHABLE", "Target not reachable — " + unreachableDetail(engine));
      renderChecks(engine.checks, engine);
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
        fillMeta(engine);
        setLoading($("go"), false);
        finish(engine);
        return;
      }
      setVerdict((engine.risk || "unknown").toUpperCase(), engine.summary || "");
      renderChecks(engine.checks, engine);
      fillMeta(engine);
      setLoading($("go"), false);
      finish(engine);
      return;
    }

    fillMeta(engine);
    setLoading($("go"), false);
    finish(engine);
  }

  window.initCors = function initCors() {
    initUrlInput($("url"));
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
