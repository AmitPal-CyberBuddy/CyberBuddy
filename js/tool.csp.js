/* CyberBuddy — CSP Policy Auditor page controller. Depends on js/app.js. */
"use strict";

(function () {
  let cbLastData = null;

  function $(id) { return document.getElementById(id); }

  function setVerdict(data) {
    /* Only a missing response is "unreachable". An HTTP 4xx/5xx *is* a
       response: the auditor reached the host and cannot assess a policy from
       an error page, so it reports unknown with no grade — it must not send
       the reader looking for a network fault that did not happen. */
    const unreachable = !!data._unreachable;
    const risk = unreachable ? "unreachable" : (data.risk || "unknown").toLowerCase();
    const grade = data.grade || "";
    const score = data.score != null ? data.score : null;

    if (unreachable) {
      $("verdict").textContent = "UNREACHABLE";
    } else if (grade && grade !== "—" && score != null) {
      // Present the 0-100 posture score and A-F grade as the headline, not a
      // HIGH/MEDIUM/LOW severity that overstates a configuration weakness.
      $("verdict").textContent = grade + " · " + score + "/100";
    } else {
      $("verdict").textContent = "UNKNOWN";
    }
    $("verdict").className = "risk " + risk;
    $("verdictBanner").className = "verdict-banner " + risk;
    // "F · 45/100" read aloud is a stray letter and a fraction. Name the badge
    // the way the Headers tool names its grade box.
    $("verdict").setAttribute("role", "img");
    $("verdict").setAttribute(
      "aria-label",
      unreachable
        ? "CSP posture: not graded, the target could not be reached"
        : (grade && grade !== "—" && score != null
          ? "CSP posture grade " + grade + ", " + score + " out of 100"
          : "CSP posture: could not be determined")
    );
    bump($("verdict"));

    let label = unreachable ? "CSP posture: NOT GRADED — target unreachable"
      : (data.status_code != null && data.status_code >= 400
        ? "CSP posture: NOT GRADED — HTTP " + data.status_code + " response cannot be assessed"
        : "CSP posture: UNABLE TO DETERMINE");
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
    $("results").removeAttribute("aria-busy");
    $("results").classList.remove("is-refreshing");
    setSourceChip(data);
    setVerdict(data);

    const pasted = !!data._pasted;
    $("mTarget").textContent = pasted ? "(pasted header)" : (data.url || "—");
    $("mFinal").textContent = pasted ? "—" : (data.final_url || "—");
    $("mStatus").textContent = data.status_code != null ? String(data.status_code) : "—";
    // A pasted header has no HTTP response and no request, so the status code
    // and method fields are meaningless. Hiding them stops the emptied report
    // from carrying a "HTTP status —" fact that reads like a failed fetch.
    if ($("statusItem")) $("statusItem").classList.toggle("hidden", pasted);
    if ($("methodItem")) $("methodItem").classList.toggle("hidden", pasted);
    $("mStamp").textContent = fmtStampUtc();
    $("mEngine").textContent = sourceLabel(data);
    $("mMethod").textContent = pasted ? "Pasted header · local" : "GET · read-only";
    $("mChecks").textContent = String((data.checks || []).length);
    $("mDuration").textContent = data._duration_ms != null ? data._duration_ms + " ms" : "—";

    const flag = $("reportTitleFlag");
    // Same three claims as the other tools: LIVE/CACHED for *this run*,
    // "relay data" for *this source*. The page previously showed only the
    // second, so a published CI demo report and a fresh local scan looked
    // identical, and a cached report carried no age cue at all.
    if (flag) flag.innerHTML = scanTag(data) + unverifiedFlag(data);
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
    // Re-auditing used to leave the previous report on screen with no cue that
    // it was being replaced; mark it busy and name what is happening.
    const results = $("results");
    if (results && !results.classList.contains("hidden")) {
      results.setAttribute("aria-busy", "true");
      results.classList.add("is-refreshing");
    }
    $("staticNotice").classList.add("hidden");
    const started = (window.performance && typeof performance.now === "function")
      ? performance.now() : null;

    // A local server.py answers /api/csp itself, so asking for relay consent
    // there demanded approval for a disclosure that never happens. Fail closed:
    // if the shared helper is missing, keep the disclosure.
    const relayNeeded = typeof relayGateNeeded === "function"
      ? await relayGateNeeded(url)
      : true;
    const consent = relayNeeded ? await ensureRelayConsent(url) : "skip";
    const declined = consent === "deny" ||
      (typeof relayAllowed === "function" && !relayAllowed() &&
        !(window.__cbEngine && window.__cbEngine.mode === "python"));
    if (declined) {
      setLoading($("go"), false);
      $("results").removeAttribute("aria-busy");
      $("results").classList.remove("is-refreshing");
      // Drop the previous target's report before hiding it, so the Export menu
      // cannot emit a report for a target that is no longer on screen.
      cbLastData = null;
      $("staticNotice").innerHTML =
        "<h3>Header read declined</h3>" +
        "<p>Third-party relays were declined, so this hosted page cannot read " +
        "the target's CSP response header. Run <code>python3 server.py</code> " +
        "locally for a direct scan with no third-party header relay.</p>";
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
      $("staticNotice").classList.remove("hidden");
      $("staticNotice").innerHTML =
        "<h3>Target not reachable</h3>" +
        "<p>CyberBuddy's engine got no response from this target. Detail: " +
        "<code>" + esc(unreachableDetail(data)) + "</code></p>";
      $("staticNotice").classList.remove("hidden");
      render(data);
      return;
    }
    if (isEngineDown(data) || (data && data._source === "none")) {
      $("results").removeAttribute("aria-busy");
      $("results").classList.remove("is-refreshing");
      // Keep the report when the engine returned usable checks; only blank the
      // panel when there is genuinely nothing to show.
      if (data && data.checks && data.checks.length) {
        $("staticNotice").classList.add("hidden");
        render(data);
        return;
      }
      cbLastData = null;
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
      // The engine always returns a result object, so the old emptiness test
      // ("no policy and no report-only policy" → bad input) rejected a
      // *legitimate* "no CSP present" verdict — the one answer a pasted-header
      // audit most needs to give. Only text that contains no CSP directive at
      // all is rejected as bad input; an empty policy is graded, as an F.
      if (!data || !data.checks || !data.checks.length || !looksLikeCspPolicy(raw)) {
        showHeaderError(
          "That did not look like a CSP header value. Paste directive text such " +
          "as \"default-src 'self'; script-src 'self'\", with or without the " +
          "Content-Security-Policy name.");
        headerInput.focus();
        return;
      }
      clearHeaderError();
      $("staticNotice").classList.add("hidden");
      // A paste-only report replaces whatever URL report was on screen; drop
      // the busy/refresh state a cancelled audit may have left behind.
      $("results").removeAttribute("aria-busy");
      $("results").classList.remove("is-refreshing");
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
