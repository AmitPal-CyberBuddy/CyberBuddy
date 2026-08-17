/* CyberBuddy — DNS & Domain Security Analyzer page controller.
   Externalised from an inline <script> so the site can ship a CSP without
   'unsafe-inline'. Depends on js/app.js. */
"use strict";

(function () {
  let cbLastData = null;

  function $(id) { return document.getElementById(id); }

  function renderRecords(data) {
    const tbody = $("records").querySelector("tbody");
    const records = data.records || {};
    const keys = Object.keys(records).sort();
    if (!keys.length) {
      tbody.innerHTML = '<tr class="finding-row"><td class="k">—</td><td>No records returned.</td></tr>';
      return;
    }
    tbody.innerHTML = keys.map((key) =>
      '<tr class="finding-row"><td class="k">' + esc(key) + "</td><td><code>" +
      esc((records[key] || []).slice(0, 8).join("  ·  ") || "—") +
      "</code></td></tr>"
    ).join("");
  }

  function render(data) {
    cbLastData = data;
    $("results").classList.remove("hidden");
    setSourceChip(data);

    const isError = data.status === "error" && !data.checks.filter(function (c) { return c.status === "ok" || c.status === "weak" || c.status === "missing"; }).length;
    const score = data.score != null ? data.score : null;
    const grade = data.grade ? data.grade.toUpperCase() : "—";
    const risk = isError ? "UNKNOWN" : (data.risk || "unknown").toUpperCase();

    if (isError) {
      $("gauge").innerHTML = '<div class="score-gauge gauge-f" role="img" aria-label="No score — domain could not be resolved">' +
        '<svg viewBox="0 0 120 120" aria-hidden="true"><circle class="gauge-track" cx="60" cy="60" r="52" pathLength="100"/>' +
        '<text class="gauge-num" x="60" y="58" style="font-size:15px">no</text><text class="gauge-num" x="60" y="76" style="font-size:15px">data</text></svg>' +
        '<span class="gauge-band">not graded</span></div>';
    } else {
      renderGauge($("gauge"), score != null ? score : 0, grade);
    }

    $("grade").textContent = grade;
    $("grade").className = "grade " + (isError ? "unknown" : (gradeFor(score) || grade.toLowerCase()));
    bump($("grade"));

    $("verdict").textContent = risk;
    $("verdict").className = "risk " + (isError ? "unknown" : (data.risk || "unknown"));
    bump($("verdict"));
    $("verdictBanner").className = "verdict-banner " + (isError ? "unknown" : (data.risk || "unknown"));

    $("mDomain").textContent = data.domain || "—";
    $("mResolver").textContent = data.resolver || sourceLabel(data);
    $("mStamp").textContent = fmtStampUtc();
    $("mEngine").textContent = sourceLabel(data);
    $("mMethod").textContent = "DNS query · resolver only";
    $("mChecks").textContent = String((data.checks || []).length);
    $("mDuration").textContent = data._duration_ms != null ? data._duration_ms + " ms" : "—";
    $("mScore").textContent = data.score != null ? data.score + " / 100" : "—";
    $("summary").textContent = data.summary || "";

    const flag = $("reportTitleFlag");
    if (flag) flag.innerHTML = unverifiedFlag(data);

    $("posture").innerHTML = postureHtml(data.checks);
    renderRecords(data);

    const tbody = $("checks").querySelector("tbody");
    tbody.innerHTML = (data.checks || []).map((c, i) =>
      findingRowHtml(c, { copy: true, index: i })
    ).join("");
    bindFindingCopy(tbody, data.checks || [], "DNS & Domain Security Analyzer", data.domain);

    renderProvenance(data, "DNS & Domain Security Analyzer");
    enterEvidenceMode();
  }

  async function probe(domain) {
    setLoading($("go"), true);

    const t0 = (window.performance && typeof performance.now === "function")
      ? performance.now() : null;

    const consent = await ensureDnsConsent(domain);
    if (consent === "deny") {
      setLoading($("go"), false);
      $("staticNotice").innerHTML =
        "<h3>DNS analysis declined</h3>" +
        "<p>Public DNS lookups were declined, so this hosted page cannot read " +
        "the domain's records. Run <code>python3 server.py</code> locally for a " +
        "resolver-local scan that never leaves your machine, then retry.</p>";
      $("staticNotice").classList.remove("hidden");
      $("results").classList.add("hidden");
      return;
    }

    const data = await apiDns(domain);
    if (data && t0 != null) {
      data._duration_ms = Math.max(1, Math.round(performance.now() - t0));
    }
    setLoading($("go"), false);

    if (!data || (data.error && !data.checks) || (data.status === "error" && !data.checks)) {
      $("staticNotice").innerHTML =
        "<h3>Could not analyze this domain</h3>" +
        "<p>No DNS data was returned. The resolver may be unreachable, blocked " +
        "or rate-limited. Run <code>python3 server.py</code> locally, then retry. " +
        (data && data.error ? "Detail: <code>" + esc(data.error) + "</code>" : "") + "</p>";
      $("staticNotice").classList.remove("hidden");
      $("results").classList.add("hidden");
      return;
    }

    $("staticNotice").classList.add("hidden");
    render(data);
  }

  window.initDns = function initDns() {
    initDomainInput($("domain"));
    $("go").addEventListener("click", () => {
      const domain = validateDomainField($("domain"));
      if (!domain) return;
      pushDomainParam(domain);
      addRecentScan(domain);
      probe(domain);
    });

    $("domain").addEventListener("keydown", (e) => {
      if (e.key === "Enter") $("go").click();
    });

    initExportMenu("DNS & Domain Security Analyzer", () => cbLastData);
    initEvidenceToggle();

    const initial = new URLSearchParams(location.search).get("domain");
    if (initial) {
      $("domain").value = initial;
      const domain = validateDomainField($("domain"), false);
      if (domain) probe(domain);
    }
  };
})();
