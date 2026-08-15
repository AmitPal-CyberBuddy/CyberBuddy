/* CyberBuddy — CSP Policy Auditor page controller. Depends on js/app.js. */
"use strict";

(function () {
  let cbLastData = null;

  function $(id) { return document.getElementById(id); }

  function setVerdict(data) {
    const unreachable = !!data._unreachable;
    const risk = unreachable ? "unreachable" : (data.risk || "unknown").toLowerCase();
    const grade = data.grade || "";
    const score = data.score != null ? data.score : null;

    if (unreachable) {
      $("verdict").textContent = "UNREACHABLE";
    } else if (grade && score != null) {
      // Present the 0-100 posture score and A-F grade as the headline, not a
      // HIGH/MEDIUM/LOW severity that overstates a configuration weakness.
      $("verdict").textContent = grade + " · " + score + "/100";
    } else {
      $("verdict").textContent = "UNKNOWN";
    }
    $("verdict").className = "risk " + risk;
    $("verdictBanner").className = "verdict-banner " + risk;
    bump($("verdict"));

    let label = unreachable ? "CSP posture: NOT GRADED — target unreachable" : "CSP posture: UNABLE TO DETERMINE";
    if (grade === "A") label = "CSP posture: STRONG — no dangerous source pattern";
    else if (grade === "B") label = "CSP posture: GOOD — a few optional hardening gaps";
    else if (grade === "C") label = "CSP posture: FAIR — review the directive gaps";
    else if (grade === "D") label = "CSP posture: WEAK — multiple controls need hardening";
    else if (grade === "F") label = "CSP posture: CRITICAL — enforcement or script controls are weak";
    $("protection").textContent = label;
    $("protection").className = "protection-line " + risk;
    $("summary").textContent = data.summary || "";
  }

  function render(data) {
    cbLastData = data;
    $("results").classList.remove("hidden");
    setSourceChip(data);
    setVerdict(data);

    const pasted = !!data._pasted;
    $("mTarget").textContent = pasted ? "(pasted header)" : (data.url || "—");
    $("mFinal").textContent = pasted ? "—" : (data.final_url || "—");
    $("mStatus").textContent = data.status_code != null ? String(data.status_code) : "—";
    $("mStamp").textContent = fmtStampUtc();
    $("mEngine").textContent = sourceLabel(data);
    $("mMethod").textContent = pasted ? "Pasted header · local" : "GET · read-only";
    $("mChecks").textContent = String((data.checks || []).length);
    $("mDuration").textContent = data._duration_ms != null ? data._duration_ms + " ms" : "—";

    const flag = $("reportTitleFlag");
    if (flag) flag.innerHTML = unverifiedFlag(data);
    $("posture").innerHTML = postureHtml(data.checks);
    $("policy").textContent = data.policy || "(not present)";
    $("reportOnly").textContent = data.report_only_policy || "(not present)";
    $("suggestedPolicy").textContent = "Content-Security-Policy: " +
      (data.suggested_policy || CSP_SUGGESTED_POLICY);

    const tbody = $("checks").querySelector("tbody");
    tbody.innerHTML = (data.checks || []).map((check, index) =>
      findingRowHtml(check, { copy: true, index: index })
    ).join("");
    bindFindingCopy(tbody, data.checks || [], "CSP Policy Auditor", data.url);

    renderProvenance(data, "CSP Policy Auditor");
    enterEvidenceMode();
  }

  async function audit(url) {
    setLoading($("go"), true);
    const started = (window.performance && typeof performance.now === "function")
      ? performance.now() : null;

    const consent = await ensureRelayConsent(url);
    if (consent === "deny") {
      setLoading($("go"), false);
      $("staticNotice").innerHTML =
        "<h3>Header read declined</h3>" +
        "<p>Third-party relays were declined, so this hosted page cannot read " +
        "the target's CSP response header. Run <code>python3 server.py</code> " +
        "locally for a same-origin scan that never leaves your machine.</p>";
      $("staticNotice").classList.remove("hidden");
      $("results").classList.add("hidden");
      return;
    }

    const data = await apiCsp(url);
    if (data && started != null) {
      data._duration_ms = Math.max(1, Math.round(performance.now() - started));
    }
    setLoading($("go"), false);

    if (data && data._unreachable) {
      $("staticNotice").innerHTML =
        "<h3>Target not reachable</h3>" +
        "<p>CyberBuddy's engine got no response from this target. Detail: " +
        "<code>" + esc(unreachableDetail(data)) + "</code></p>";
      $("staticNotice").classList.remove("hidden");
      render(data);
      return;
    }
    if (isEngineDown(data) || (data && data._source === "none")) {
      $("staticNotice").innerHTML =
        "<h3>Could not read CSP headers</h3>" +
        "<p>No CSP header data was returned. The target may be unreachable, " +
        "or the lookup may have been blocked or rate-limited. Run " +
        "<code>python3 server.py</code> locally for a same-origin scan.</p>";
      $("staticNotice").classList.remove("hidden");
      $("results").classList.add("hidden");
      return;
    }
    $("staticNotice").classList.add("hidden");
    render(data);
  }

  window.initCsp = function initCsp() {
    initUrlInput($("url"));
    $("go").addEventListener("click", () => {
      const url = validateUrlField($("url"));
      if (!url) return;
      pushUrlParam(url);
      addRecentScan(url);
      audit(url);
    });

    $("url").addEventListener("keydown", (event) => {
      if (event.key === "Enter") $("go").click();
    });

    // Paste-a-header mode: grade a raw CSP header value with no network.
    const headerInput = $("cspHeaderInput");
    const headerError = $("cspHeaderError");
    const headerGo = $("cspHeaderGo");
    const showHeaderError = (message) => {
      headerError.classList.remove("hidden");
      headerError.textContent = message;
      headerInput.setAttribute("aria-invalid", "true");
    };
    const clearHeaderError = () => {
      headerError.classList.add("hidden");
      headerError.textContent = "";
      headerInput.removeAttribute("aria-invalid");
    };
    headerInput.addEventListener("input", clearHeaderError);
    headerGo.addEventListener("click", () => {
      const raw = headerInput.value;
      if (!raw.trim()) {
        showHeaderError("Paste a Content-Security-Policy header value first.");
        headerInput.focus();
        return;
      }
      const data = gradeCspFromHeader(raw);
      if (!data || !data.policy && !data.report_only_policy) {
        showHeaderError("That did not look like a CSP header value. Check the text and try again.");
        return;
      }
      clearHeaderError();
      $("staticNotice").classList.add("hidden");
      render(data);
    });

    initExportMenu("CSP Policy Auditor", () => cbLastData);
    initEvidenceToggle();

    const initial = new URLSearchParams(location.search).get("url");
    if (initial) {
      $("url").value = initial;
      const url = validateUrlField($("url"), false);
      if (url) audit(url);
    }
  };
})();
