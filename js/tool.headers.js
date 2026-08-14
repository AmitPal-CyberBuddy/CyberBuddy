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

    const score = data.score != null ? data.score : 0;
    const grade = (data.grade || "F").toUpperCase();
    const risk = (data.risk || "unknown").toUpperCase();

    $("grade").textContent = grade;
    $("grade").className = "grade " + (gradeFor(score) || grade.toLowerCase());
    bump($("grade"));

    $("risk").textContent = risk;
    $("risk").className = "risk " + (data.risk || "unknown");
    bump($("risk"));

    countUp($("score"), score, "/100");
    $("scoreFill").style.width = score + "%";
    $("verdict").className = "verdict-banner " + (data.risk || "unknown");

    $("mTarget").textContent = data.url || "—";
    $("mFinal").textContent = data.final_url || "—";
    $("mStatus").textContent = data.status_code != null ? String(data.status_code) : "—";
    $("mStamp").textContent = fmtStampUtc();
    $("summary").textContent = data.summary || "";

    const flag = $("reportTitleFlag");
    if (flag) flag.innerHTML = unverifiedFlag(data);

    $("headers").textContent = JSON.stringify(data.headers || {}, null, 2);
    $("checks").querySelector("tbody").innerHTML = (data.checks || []).map((c) => {
      const ev = c.evidence ? "<code class='f-evidence'>" + esc(c.evidence) + "</code>" : "";
      return "<tr><td class='k'>" + esc(c.name) + "</td><td>" +
        "<span class='f-status " + esc(c.status) + "'>" + esc(c.status) + "</span>" +
        "<div class='f-detail'>" + esc(c.detail) + "</div>" + ev + "</td></tr>";
    }).join("");

    renderProvenance(data, "Security Headers");
    enterEvidenceMode();
  }

  async function scan(url) {
    setLoading($("go"), true);

    const consent = await ensureRelayConsent();
    if (consent === "deny") {
      setLoading($("go"), false);
      $("staticNotice").innerHTML =
        "<h3>Header read declined</h3>" +
        "<p>Third-party relays were declined, so response headers cannot be read " +
        "from this hosted page. Run <code>python3 server.py</code> locally for a " +
        "same-origin scan that never leaves your machine, then retry.</p>";
      $("staticNotice").classList.remove("hidden");
      $("results").classList.add("hidden");
      return;
    }

    const data = await apiHeaders(url);
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
    $("go").addEventListener("click", () => {
      const url = normalizeUrl($("url").value);
      if (!url || !validUrl(url)) { $("url").focus(); return; }
      $("url").value = url;
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
      $("url").value = normalizeUrl(initial);
      scan(normalizeUrl(initial));
    }
  };
})();
