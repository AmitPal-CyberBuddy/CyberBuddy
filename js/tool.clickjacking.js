/* CyberBuddy — Clickjacking Validator page controller.
   Externalised from an inline <script> so the site can ship a CSP without
   'unsafe-inline'. Depends on js/app.js. */
"use strict";

(function () {
  let cbLastData = null;
  let frameLoaded = false;
  let confirmTimer = null;
  let frameObservation = {
    event: "pending",
    rendered: null,
    peek: "Frame has not finished loading."
  };

  function $(id) { return document.getElementById(id); }

  function attachFrameEvidence(data) {
    if (!data) return data;
    data.frame_observation = Object.assign({}, frameObservation);
    const stage = $("stage");
    const slider = $("pocOpacity");
    data.poc_overlay = {
      visible: !!(stage && stage.classList.contains("poc")),
      opacity_percent: slider ? Number(slider.value) : 72
    };
    return data;
  }

  function syncFrameEvidence() {
    if (cbLastData) attachFrameEvidence(cbLastData);
  }

  function protectionLabel(risk, opts) {
    const r = (risk || "").toLowerCase();
    const visual = !!(opts && opts.confirmation === "manual");
    const byVisual = visual ? " (by visual confirmation)" : "";
    if (r === "low") return { text: "Clickjacking protection: ENABLED" + byVisual, cls: "low" };
    if (r === "medium") return { text: "Clickjacking protection: PARTIAL" + byVisual, cls: "medium" };
    if (r === "high") return { text: "Clickjacking protection: NOT ENABLED" + byVisual, cls: "high" };
    return { text: "Clickjacking protection: MANUAL CHECK", cls: "unknown" };
  }

  function setVerdict(risk, text, opts) {
    // When protection is ENABLED (risk=low), integrate the verdict to avoid
    // showing "Clickjacking protection: ENABLED" with a separate "LOW" badge.
    // The protection text already conveys the status clearly.
    const r = (risk || "").toLowerCase();
    const p = protectionLabel(risk, opts);

    // Show verdict badge only when not showing "ENABLED" for low risk,
    // or when the verdict is "FRAME ONLY" / unknown (needs visual check)
    const showVerdictBadge = r !== "low" && r !== "frame only";

    if (showVerdictBadge) {
      $("verdict").textContent = risk;
      $("verdict").className = "risk " + (risk === "FRAME ONLY" ? "unknown" : r);
      $("verdict").style.display = "";
      bump($("verdict"));
    } else {
      $("verdict").style.display = "none";
    }

    $("summary").textContent = text;
    $("verdictBanner").className = "verdict-banner " +
      (risk === "FRAME ONLY" ? "unknown" : r);
    $("protection").textContent = p.text;
    $("protection").className = "protection-line " + p.cls;
  }

  function clearVisualConfirm() {
    if (confirmTimer) {
      clearTimeout(confirmTimer);
      confirmTimer = null;
    }
    const wrap = $("visualConfirm");
    if (!wrap) return;
    wrap.classList.add("hidden");
    wrap.innerHTML = "";
  }

  function fillMeta(url, data) {
    $("mTarget").textContent = url;
    $("mFinal").textContent = data && data.final_url ? data.final_url : url;
    $("mStatus").textContent = data && data.status_code != null ? String(data.status_code) : "—";
    $("mStamp").textContent = fmtStampUtc();
    $("mEngine").textContent = sourceLabel(data || { _source: "browser" });
    $("mMethod").textContent = "GET · read-only";
    $("mDuration").textContent = data && data._duration_ms != null ? data._duration_ms + " ms" : "—";
    // Also update the inline URL in the live-frame title.
    $("liveFrameUrl").textContent = url;
    // Provenance is never hidden: the source chip used to be suppressed when
    // protection was ENABLED (risk=low), which removed the one label that says
    // *where the header values came from* on exactly the reassuring result an
    // auditor is most likely to quote. Keep it on every result.
  }

  function renderRows(list, url) {
    const tbody = $("findings").querySelector("tbody");
    tbody.innerHTML = (list || []).map((f, i) =>
      findingRowHtml(f, { copy: true, index: i })
    ).join("");
    bindFindingCopy(tbody, list || [], "Clickjacking Validator", url);
  }

  function finish(data, toolTitle) {
    cbLastData = attachFrameEvidence(data);
    renderProvenance(data, toolTitle || "Clickjacking Validator");
    const head = $("reportTitleFlag");
    // LIVE / CACHED describes *this* run; "relay data" describes the source.
    // Both belong on the report: a published CI demo report and a fresh
    // server.py scan used to render identically here, which is exactly the
    // ambiguity the LIVE/CACHED promise exists to remove.
    if (head) head.innerHTML = scanTag(data) + unverifiedFlag(data);
    enterEvidenceMode();
  }

  async function scan(url) {
    $("results").classList.remove("hidden");
    // Overlay is opt-in: the frame loads plainly by default.
    $("stage").classList.remove("poc");
    $("pocControls").classList.add("hidden");
    $("togglePoc").textContent = "Show PoC overlay";
    $("togglePoc").disabled = true;
    $("stage").removeAttribute("data-frame-width");
    $("stage").style.removeProperty("--frame-w");
    $("stage").style.removeProperty("--frame-h");
    $("frame").style.removeProperty("width");
    $("frame").style.removeProperty("height");
    clearVisualConfirm();
    frameLoaded = false;
    frameObservation = {
      event: "pending",
      rendered: null,
      peek: "Frame has not finished loading."
    };
    const ctx = $("frameContext");
    if (ctx) { ctx.classList.add("hidden"); ctx.innerHTML = ""; }
    $("frame").src = url;
    $("frameStatus").textContent = "Loading frame…";
    $("stage").classList.add("scanning");
    setLoading($("go"), true);
    fillMeta(url, null);

    // Ask before anything can reach a third-party relay — but only when a
    // relay is actually reachable. A local server.py answers /api/scan itself,
    // so prompting there asked the analyst to approve a disclosure that never
    // happens (and a "Decline" skipped the engine, producing a header-less
    // FRAME ONLY report against a perfectly good local scan).
    const t0 = (window.performance && typeof performance.now === "function")
      ? performance.now() : null;

    const relayNeeded = typeof relayGateNeeded === "function"
      ? await relayGateNeeded(url)
      : true; // shared helper missing → keep the disclosure, never skip it
    const consent = relayNeeded ? await ensureRelayConsent(url) : "skip";
    if (consent === "deny") {
      setLoading($("go"), false);
      setSourceChip({ _source: "browser" });
      setVerdict("FRAME ONLY",
        "Relay lookups declined — the frame above is your evidence.");
      describeFrameContext(url, { url: url, final_url: url });
      renderRows([row0()], url);
      $("headers").textContent = "{}";
      askVisualConfirmation(url, { url: url, headers: {}, _source: "browser" });
      finish({ url: url, risk: "unknown", findings: [], headers: {}, _source: "browser" });
      return;
    }

    const data = await apiScan(url);
    if (data && t0 != null) {
      data._duration_ms = Math.max(1, Math.round(performance.now() - t0));
    }
    setLoading($("go"), false);
    setSourceChip(data || { _source: "browser" });

    if (isEngineDown(data) || (data && data.error && !data.findings)) {
      setVerdict("FRAME ONLY",
        "If you can see the real site in the frame, it is clickjackable in this browser.");
      describeFrameContext(url, { url: url, final_url: url });
      renderRows([{
        name: "Frame test",
        status: "info",
        detail: "Visual proof only. Header values are not available from this host.",
        evidence: ""
      }], url);
      $("headers").textContent = "{}";
      askVisualConfirmation(url, { url: url, headers: {}, _source: "browser" });
      finish({ url: url, risk: "unknown", findings: [], headers: {}, _source: "browser" });
      return;
    }

    if (data && data._unreachable) {
      fillMeta(url, data);
      setVerdict("UNREACHABLE", "Target not reachable — " + unreachableDetail(data));
      describeFrameContext(url, data);
      $("frameStatus").textContent =
        "Target not reachable — " + unreachableDetail(data) +
        ". The frame above may show the browser's own error page; that is not framing evidence.";
      renderRows(data.findings, url);
      $("headers").textContent = JSON.stringify(data.headers || {}, null, 2);
      finish(data);
      return;
    }

    fillMeta(url, data);
    setVerdict((data.risk || "unknown").toUpperCase(), data.summary ||
      "If you can see the real site in the frame, it is clickjackable.",
      { confirmation: data.confirmation });
    renderRows(data.findings, url);
    $("headers").textContent = JSON.stringify(data.headers || {}, null, 2);
    describeFrameContext(url, data);
    if ((data.risk || "unknown") === "unknown") {
      askVisualConfirmation(url, data);
    }
    finish(data);
  }

  /* The frame and the grade can describe two different documents, and the
     origin that framed the page is what decides whether a rendered frame is
     evidence of exposure or of a working allowlist. Neither was stated, so an
     analyst reading the screenshot could not tell why the frame appeared. */
  function describeFrameContext(url, data) {
    const el = $("frameContext");
    if (!el) return;
    const target = redactUrlCredentials(url || "");
    let framedOrigin = "";
    try { framedOrigin = new URL(target).origin; } catch (_) { framedOrigin = ""; }
    const graded = redactUrlCredentials((data && data.final_url) || target);
    const notes = [];

    if (framedOrigin) {
      notes.push(
        "This report was framed by <code>" + esc(window.location.origin) + "</code> — " +
        "a page the target did not necessarily name. A frame that renders proves " +
        "framing is allowed <em>for that origin</em>; compare it with the framing " +
        "control above."
      );
    }
    if (graded && target && graded !== target) {
      notes.push(
        "<strong>Redirect drift:</strong> the header grade describes <code>" + esc(graded) +
        "</code>, but the live frame below loaded <code>" + esc(target) +
        "</code>. If those are different documents, the frame is not evidence for " +
        "the graded response — re-run against the final URL."
      );
    }
    if (!notes.length) {
      el.classList.add("hidden");
      el.innerHTML = "";
      return;
    }
    el.classList.remove("hidden");
    el.innerHTML = notes.map((n, i) =>
      '<p class="frame-context-line' + (i ? " is-warn" : "") + '">' + n + "</p>"
    ).join("");
  }

  function row0() {
    return {
      name: "Frame test",
      status: "info",
      detail: "Visual proof only — third-party header lookups were declined.",
      evidence: ""
    };
  }

  /* Header data unavailable → ask the analyst what the frame shows. */
  function askVisualConfirmation(url, base) {
    // Give the frame a moment to settle before guessing.
    if (confirmTimer) clearTimeout(confirmTimer);
    confirmTimer = setTimeout(() => {
      confirmTimer = null;
      const suggestion = frameLikelyBlocked($("frame"), frameLoaded) ? "blocked" : "framed";
      renderConfirmPrompt("visualConfirm", suggestion, (verdict) => {
        frameObservation.rendered = verdict === "framed";
        const data = attestedClickjacking(Object.assign({ url: url }, base), verdict);
        fillMeta(url, data);
        setVerdict(data.risk.toUpperCase(), data.summary, { confirmation: data.confirmation });
        renderRows(data.findings, url);
        describeFrameContext(url, data);
        finish(data);
      });
    }, 1200);
  }

  window.initClickjacking = function initClickjacking() {
    initUrlInput($("url"));
    // The overlay is meaningless before a frame exists; leaving the button
    // enabled let it "open" a blank stage with no way to tell why.
    $("togglePoc").disabled = true;
    $("frame").addEventListener("load", () => {
      frameLoaded = true;
      $("stage").classList.remove("scanning");
      // Evidence "peek", kept from the original standalone validator:
      // reading the framed document proves the load fired and records how
      // the browser classified the frame. Cross-origin documents are
      // unreadable by design, so the catch is the expected result.
      let peek = "cross-origin (document not readable — expected)";
      try {
        const doc = $("frame").contentDocument;
        if (doc && doc.location) peek = "document readable — " + doc.location.href;
      } catch (_) { /* SecurityError: cross-origin — expected */ }
      frameObservation = {
        event: "load",
        rendered: frameObservation.rendered,
        peek: peek
      };
      syncFrameEvidence();
      $("togglePoc").disabled = false;
      $("frameStatus").textContent =
        "Frame loaded — peek: " + peek +
        ". If the real site UI is visible, treat it as clickjackable.";
    });

    // Network-level failures fire `error` on iframes (Chromium fires it for
    // policy blocks such as mixed content; refused connections may instead
    // render the browser's error page and fire `load` — the engine verdict
    // covers that case). Surface both honestly instead of leaving the
    // "Loading frame…" status stuck.
    $("frame").addEventListener("error", () => {
      $("stage").classList.remove("scanning");
      frameObservation = {
        event: "error",
        rendered: false,
        peek: "Frame error event — no framed document was readable."
      };
      syncFrameEvidence();
      $("frameStatus").textContent =
        "Frame load failed — the browser blocked or could not reach the target " +
        "(mixed-content policy, CSP, or connection failure). No framing verdict " +
        "can be drawn from this attempt; retry or verify the target.";
    });

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

    $("togglePoc").addEventListener("click", () => {
      $("stage").classList.toggle("poc");
      const on = $("stage").classList.contains("poc");
      $("pocControls").classList.toggle("hidden", !on);
      $("togglePoc").textContent = on ? "Hide PoC overlay" : "Show PoC overlay";
      syncFrameEvidence();
    });

    // Frame viewport switcher. A desktop page squeezed into a 390px phone
    // frame only proves the top-left corner; forcing a page width and letting
    // the stage scroll horizontally is what makes the visual test meaningful on
    // a small screen. "Fill" is the default and matches the old behaviour.
    const stage = $("stage");
    const frameEl = $("frame");
    function applyFrameWidth(value) {
      const wide = value && value !== "100%" ? Number(value) : 0;
      stage.setAttribute("data-frame-width", value || "100%");
      if (wide) {
        // Give the stage a stable aspect ratio for that device width, then let
        // the horizontal scrollbar reach the rest of the page.
        stage.style.setProperty("--frame-w", wide + "px");
        stage.style.setProperty("--frame-h", Math.round(wide * 0.62) + "px");
      } else {
        stage.style.removeProperty("--frame-w");
        stage.style.removeProperty("--frame-h");
      }
      frameEl.style.width = wide ? wide + "px" : "";
      frameEl.style.height = wide ? "100%" : "";
      if (wide) stage.scrollLeft = 0;
      $("frameStatus").textContent = wide
        ? "Frame rendered at " + wide + "px wide — scroll horizontally to inspect the full page."
        : "Frame fills the stage — switch to a device width to see the full page layout.";
    }

    const frameSizeButtons = Array.prototype.slice.call(
      document.querySelectorAll(".stage-toolbar [data-frame-width]")
    );
    function selectFrameWidth(value) {
      stage.setAttribute("data-frame-width", value);
      frameSizeButtons.forEach((b) => {
        const on = b.getAttribute("data-frame-width") === value;
        b.setAttribute("aria-pressed", on ? "true" : "false");
      });
      applyFrameWidth(value);
    }
    frameSizeButtons.forEach((btn) => {
      btn.addEventListener("click", () => selectFrameWidth(btn.getAttribute("data-frame-width")));
    });
    selectFrameWidth("100%");

    $("pocOpacity").addEventListener("input", () => {
      const value = Math.max(5, Math.min(100, Number($("pocOpacity").value) || 72));
      $("pocOverlay").style.setProperty("--attacker-opacity", String(value / 100));
      $("pocOpacityValue").textContent = value + "%";
      syncFrameEvidence();
    });

    initExportMenu("Clickjacking Validator", () => cbLastData);
    initEvidenceToggle();

    const initial = new URLSearchParams(location.search).get("url");
    if (initial) {
      $("url").value = initial;
      const url = validateUrlField($("url"), false);
      if (url) scan(url);
    }
  };
})();
