/* CyberBuddy — Security Headers page controller.
   Externalised from an inline <script> so the site can ship a CSP without
   'unsafe-inline'. Depends on js/app.js. */
"use strict";

(function () {
  let cbLastData = null;

  function $(id) { return document.getElementById(id); }

  function render(data) {
    cbLastData = data;
    $("results").classList.remove("hidden");
    setSourceChip(data);

    const unreachable = !!data._unreachable;
    const score = data.score != null ? data.score : null;
    const grade = data.grade ? data.grade.toUpperCase() : "—";
    const risk = unreachable ? "UNREACHABLE" : (data.risk || "unknown").toUpperCase();

    if (unreachable) {
      $("gauge").innerHTML = '<div class="score-gauge gauge-f" role="img" aria-label="No score — target unreachable">' +
        '<svg viewBox="0 0 120 120" aria-hidden="true"><circle class="gauge-track" cx="60" cy="60" r="52" pathLength="100"/>' +
        '<text class="gauge-num" x="60" y="58" style="font-size:15px">no</text><text class="gauge-num" x="60" y="76" style="font-size:15px">data</text></svg>' +
        '<span class="gauge-band">not graded</span></div>';
    } else {
      renderGauge($("gauge"), score != null ? score : 0, grade);
    }

    $("grade").textContent = grade;
    $("grade").className = "grade " + (unreachable ? "unknown" : (gradeFor(score) || grade.toLowerCase()));
    bump($("grade"));

    $("verdict").textContent = risk;
    $("verdict").className = "risk " + (unreachable ? "unreachable" : (data.risk || "unknown"));
    bump($("verdict"));
    $("verdictBanner").className = "verdict-banner " + (unreachable ? "unreachable" : (data.risk || "unknown"));

    $("mTarget").textContent = data.url || "—";
    $("mFinal").textContent = data.final_url || "—";
    $("mStatus").textContent = data.status_code != null ? String(data.status_code) : "—";
    $("mStamp").textContent = fmtStampUtc();
    $("mEngine").textContent = sourceLabel(data);
    $("mMethod").textContent = "GET · read-only";
    $("mChecks").textContent = String((data.checks || []).length);
    $("mDuration").textContent = data._duration_ms != null ? data._duration_ms + " ms" : "—";
    $("summary").textContent = data.summary || "";

    const flag = $("reportTitleFlag");
    if (flag) flag.innerHTML = unverifiedFlag(data);

    $("posture").innerHTML = postureHtml(data.checks);

    $("headers").textContent = JSON.stringify(data.headers || {}, null, 2);
    const tbody = $("checks").querySelector("tbody");
    tbody.innerHTML = (data.checks || []).map((c, i) =>
      findingRowHtml(c, { copy: true, index: i })
    ).join("");
    bindFindingCopy(tbody, data.checks || [], "Security Headers", data.url);

    renderProvenance(data, "Security Headers");
    enterEvidenceMode();
  }

  async function scan(url) {
    setLoading($("go"), true);

    const t0 = (window.performance && typeof performance.now === "function")
      ? performance.now() : null;

    const consent = await ensureRelayConsent(url);
    if (consent === "deny") {
      setLoading($("go"), false);
      $("staticNotice").innerHTML =
        "<h3>Header read declined</h3>" +
        "<p>Third-party relays were declined, so response headers cannot be read " +
        "from this hosted page. Run <code>python3 server.py</code> locally for a " +
        "direct scan with no third-party header relay, then retry.</p>";
      $("staticNotice").classList.remove("hidden");
      $("results").classList.add("hidden");
      return;
    }

    const data = await apiHeaders(url);
    if (data && t0 != null) {
      data._duration_ms = Math.max(1, Math.round(performance.now() - t0));
    }
    setLoading($("go"), false);

    if (data && data._unreachable) {
      $("staticNotice").classList.remove("hidden");
      $("staticNotice").innerHTML =
        "<h3>Target not reachable</h3>" +
        "<p>CyberBuddy's engine got no response from this target — the host may be " +
        "down, timing out, or refusing connections. Detail: " +
        "<code>" + esc(unreachableDetail(data)) + "</code></p>";
      render(data);
      return;
    }
    if (isEngineDown(data) || (data && data._source === "none")) {
      if (data && data.checks) {
        $("staticNotice").classList.add("hidden");
        render(data);
      } else {
        $("staticNotice").innerHTML =
          "<h3>Could not read headers</h3>" +
          "<p>No header data was returned for this target. It may be unreachable, " +
          "or the lookup may have been blocked or rate-limited. Run " +
          "<code>python3 server.py</code> locally for a same-origin scan, then retry.</p>";
        $("staticNotice").classList.remove("hidden");
        $("results").classList.add("hidden");
      }
      return;
    }
    $("staticNotice").classList.add("hidden");
    render(data);
  }

  window.initHeaders = function initHeaders() {
    initUrlInput($("url"));
    $("go").addEventListener("click", () => {
      const url = validateUrlField($("url"));
      if (!url) return;
      pushUrlParam(url);
      addRecentScan(url);
      scan(url);
    });

    $("url").addEventListener("keydown", (e) => {
      if (e.key === "Enter") $("go").click();
    });

    initExportMenu("Security Headers", () => cbLastData);
    initEvidenceToggle();

    const initial = new URLSearchParams(location.search).get("url");
    if (initial) {
      $("url").value = initial;
      const url = validateUrlField($("url"), false);
      if (url) scan(url);
    }
  };
})();
