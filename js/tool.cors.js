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

  function renderChecks(checks) {
    $("checks").querySelector("tbody").innerHTML = (checks || []).map((c) => {
      const ev = c.evidence ? "<code class='f-evidence'>" + esc(c.evidence) + "</code>" : "";
      return "<tr><td class='k'>" + esc(c.name) + "</td><td>" +
        "<span class='f-status " + esc(c.status) + "'>" + esc(c.status) + "</span>" +
        "<div class='f-detail'>" + esc(c.detail) + "</div>" + ev + "</td></tr>";
    }).join("");
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

    const engine = await apiCors(url);
    setSourceChip(engine || { _source: "none" });

    if (engine && engine._unreachable) {
      $("mOrigin").textContent = "engine";
      $("mStatus").textContent = "—";
      setVerdict("UNREACHABLE", "Target not reachable — " + unreachableDetail(engine));
      renderChecks(engine.checks);
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
        renderChecks([]);
        setLoading($("go"), false);
        finish(engine);
        return;
      }
      setVerdict((engine.risk || "unknown").toUpperCase(), engine.summary || "");
      renderChecks(engine.checks);
      setLoading($("go"), false);
      finish(engine);
      return;
    }

    setLoading($("go"), false);
    finish(engine);
  }

  window.initCors = function initCors() {
    $("go").addEventListener("click", () => {
      const url = normalizeUrl($("url").value);
      if (!url || !validUrl(url)) { $("url").focus(); return; }
      $("url").value = url;
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
      $("url").value = normalizeUrl(initial);
      probe(normalizeUrl(initial));
    }
  };
})();
