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
    $("results").removeAttribute("aria-busy");
    $("results").classList.remove("is-refreshing");
    setSourceChip(data);

    /* "Unreachable" is a transport claim: no response at all. An HTTP 404/429
       is a *response* — the engine reached the host and saw a status code, it
       just cannot assess headers from it (it returns grade "—", risk
       "unknown"). Calling that "Target not reachable" sent readers to check
       DNS for a site that had just answered. */
    const noResponse = !!data._unreachable;
    const httpError = !noResponse && data.status_code != null && data.status_code >= 400;
    const unreachable = noResponse || httpError;
    const score = data.score != null ? data.score : null;
    const grade = data.grade ? data.grade.toUpperCase() : "—";
    const risk = noResponse ? "UNREACHABLE" : (data.risk || "unknown").toUpperCase();
    // A result is graded only when the engine both measured a score and issued
    // a real letter. Anything else — transport failure, an HTTP error or
    // rate-limited response the engine marks with grade "—", a lookup the
    // relay declined, a payload with no grade — has no posture to report.
    const measured = !unreachable && score != null && !!data.grade && data.grade !== "—";

    if (!measured) {
      // The aria-label must not claim "target unreachable" for a lookup that
      // simply never produced a result; say only what is true.
      $("gauge").innerHTML = '<div class="score-gauge gauge-f" role="img" aria-label="' +
        (noResponse ? "No score — target unreachable" : "No score — this response could not be assessed") + '">' +
        '<svg viewBox="0 0 120 120" aria-hidden="true"><circle class="gauge-track" cx="60" cy="60" r="52" pathLength="100"/>' +
        '<text class="gauge-num" x="60" y="58" style="font-size:15px">no</text><text class="gauge-num" x="60" y="76" style="font-size:15px">data</text></svg>' +
        '<span class="gauge-band">not graded</span></div>';
    } else {
      renderGauge($("gauge"), score, grade);
    }

    /* The box itself said "F" while the gauge said "not graded": the API used
       to return grade:"F" for a request that never completed, so the export
       carried a graded zero too. No measurement, no letter. */
    $("grade").textContent = measured ? grade : "—";
    $("grade").className = "grade " + (measured ? (gradeFor(score) || grade.toLowerCase()) : "unknown");
    bump($("grade"));

    $("verdict").textContent = risk;
    $("verdict").className = "risk " + (noResponse ? "unreachable" : (data.risk || "unknown"));
    bump($("verdict"));
    $("verdictBanner").className = "verdict-banner " + (noResponse ? "unreachable" : (data.risk || "unknown"));

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
    // LIVE / CACHED (this run) and "relay data" (this source) are different
    // claims; the page used to render only the second, so a published CI demo
    // report and a fresh local scan looked identical.
    if (flag) flag.innerHTML = scanTag(data) + unverifiedFlag(data);

    // A bare letter reads as a stray character to a screen reader. Name what
    // the box is, the same way the gauge names itself.
    $("grade").setAttribute("role", "img");
    $("grade").setAttribute(
      "aria-label",
      !measured
        ? "No grade — this response could not be assessed"
        : "Grade " + grade + (score != null ? ", " + score + " out of 100" : "")
    );

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
    // Re-scanning used to leave the previous report on screen with no cue that
    // it was being replaced; mark it busy and name what is happening.
    const results = $("results");
    if (results && !results.classList.contains("hidden")) {
      results.setAttribute("aria-busy", "true");
      results.classList.add("is-refreshing");
    }
    $("staticNotice").classList.add("hidden");

    const t0 = (window.performance && typeof performance.now === "function")
      ? performance.now() : null;

    // A local server.py answers /api/headers itself, so asking for relay
    // consent there demanded approval for a disclosure that never happens.
    const relayNeeded = typeof relayGateNeeded === "function"
      ? await relayGateNeeded(url)
      : true; // shared helper missing → keep the disclosure, never skip it
    const consent = relayNeeded ? await ensureRelayConsent(url) : "skip";
    if (consent === "deny") {
      setLoading($("go"), false);
      $("results").removeAttribute("aria-busy");
      $("results").classList.remove("is-refreshing");
      // Drop the previous target's report before hiding it. Keeping it in
      // cbLastData left the Export menu able to emit a Markdown/JSON/PNG
      // report for a target that is no longer on screen.
      cbLastData = null;
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
      $("results").removeAttribute("aria-busy");
      $("results").classList.remove("is-refreshing");
      if (data && data.checks) {
        $("staticNotice").classList.add("hidden");
        render(data);
      } else {
        cbLastData = null;
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
