/* CyberBuddy — Clickjacking Validator page controller.
   Externalised from an inline <script> so the site can ship a CSP without
   'unsafe-inline'. Depends on js/app.js. */
"use strict";

(function () {
  let cbLastData = null;
  let frameLoaded = false;

  function $(id) { return document.getElementById(id); }

  function protectionLabel(risk) {
    const r = (risk || "").toLowerCase();
    if (r === "low") return { text: "Clickjacking protection: ENABLED", cls: "low" };
    if (r === "medium") return { text: "Clickjacking protection: PARTIAL", cls: "medium" };
    if (r === "high") return { text: "Clickjacking protection: NOT ENABLED", cls: "high" };
    return { text: "Clickjacking protection: MANUAL CHECK", cls: "unknown" };
  }

  function setVerdict(risk, text) {
    $("risk").textContent = risk;
    $("risk").className = "risk " + (risk === "FRAME ONLY" ? "unknown" : risk.toLowerCase());
    bump($("risk"));
    $("summary").textContent = text;
    $("verdict").className = "verdict-banner " +
      (risk === "FRAME ONLY" ? "unknown" : risk.toLowerCase());
    const p = protectionLabel(risk);
    $("protection").textContent = p.text;
    $("protection").className = "protection-line " + p.cls;
  }

  function fillMeta(url, data) {
    $("mTarget").textContent = url;
    $("mFinal").textContent = data && data.final_url ? data.final_url : url;
    $("mStatus").textContent = data && data.status_code != null ? String(data.status_code) : "—";
    $("mStamp").textContent = fmtStampUtc();
  }

  function row(name, status, detail, evidence) {
    const ev = evidence ? "<code class='f-evidence'>" + esc(evidence) + "</code>" : "";
    return "<tr><td class='k'>" + esc(name) + "</td><td>" +
      "<span class='f-status " + esc(status) + "'>" + esc(status) + "</span>" +
      "<div class='f-detail'>" + esc(detail) + "</div>" + ev + "</td></tr>";
  }

  function renderRows(list) {
    $("findings").querySelector("tbody").innerHTML =
      (list || []).map((f) => row(f.name, f.status, f.detail, f.evidence)).join("");
  }

  function finish(data, toolTitle) {
    cbLastData = data;
    renderProvenance(data, toolTitle || "Clickjacking Validator");
    const head = $("reportTitleFlag");
    if (head) head.innerHTML = unverifiedFlag(data);
    enterEvidenceMode();
  }

  async function scan(url) {
    $("results").classList.remove("hidden");
    // Overlay is opt-in: the frame loads plainly by default.
    $("stage").classList.remove("poc");
    $("togglePoc").textContent = "Show PoC overlay";
    frameLoaded = false;
    $("frame").src = url;
    $("frameStatus").textContent = "Loading frame…";
    $("stage").classList.add("scanning");
    setLoading($("go"), true);
    fillMeta(url, null);

    // Ask before anything can reach a third-party relay.
    const consent = await ensureRelayConsent();
    if (consent === "deny") {
      setLoading($("go"), false);
      setSourceChip({ _source: "browser" });
      setVerdict("FRAME ONLY",
        "Relay lookups declined — the frame above is your evidence.");
      renderRows([row0()]);
      $("headers").textContent = "{}";
      askVisualConfirmation(url, { url: url, headers: {}, _source: "browser" });
      finish({ url: url, risk: "unknown", findings: [], headers: {}, _source: "browser" });
      return;
    }

    const data = await apiScan(url);
    setLoading($("go"), false);
    setSourceChip(data || { _source: "browser" });

    if (isEngineDown(data) || (data && data.error && !data.findings)) {
      setVerdict("FRAME ONLY",
        "If you can see the real site in the frame, it is clickjackable in this browser.");
      renderRows([{
        name: "Frame test",
        status: "info",
        detail: "Visual proof only. Header values are not available from this host.",
        evidence: ""
      }]);
      $("headers").textContent = "{}";
      askVisualConfirmation(url, { url: url, headers: {}, _source: "browser" });
      finish({ url: url, risk: "unknown", findings: [], headers: {}, _source: "browser" });
      return;
    }

    if (data && data._unreachable) {
      fillMeta(url, data);
      setVerdict("UNREACHABLE", "Target not reachable — " + unreachableDetail(data));
      renderRows(data.findings);
      $("headers").textContent = JSON.stringify(data.headers || {}, null, 2);
      finish(data);
      return;
    }

    fillMeta(url, data);
    setVerdict((data.risk || "unknown").toUpperCase(), data.summary ||
      "If you can see the real site in the frame, it is clickjackable.");
    renderRows(data.findings);
    $("headers").textContent = JSON.stringify(data.headers || {}, null, 2);
    finish(data);
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
    setTimeout(() => {
      const suggestion = frameLikelyBlocked($("frame"), frameLoaded) ? "blocked" : "framed";
      renderConfirmPrompt("visualConfirm", suggestion, (verdict) => {
        const data = attestedClickjacking(Object.assign({ url: url }, base), verdict);
        fillMeta(url, data);
        setVerdict(data.risk.toUpperCase(), data.summary);
        renderRows(data.findings);
        finish(data);
      });
    }, 1200);
  }

  window.initClickjacking = function initClickjacking() {
    $("frame").addEventListener("load", () => {
      frameLoaded = true;
      $("stage").classList.remove("scanning");
      $("frameStatus").textContent =
        "Frame loaded. If the real site UI is visible, treat it as clickjackable.";
    });

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

    $("togglePoc").addEventListener("click", () => {
      $("stage").classList.toggle("poc");
      const on = $("stage").classList.contains("poc");
      $("togglePoc").textContent = on ? "Hide PoC overlay" : "Show PoC overlay";
    });

    initExportMenu("Clickjacking Validator", () => cbLastData);
    initEvidenceToggle();

    const initial = new URLSearchParams(location.search).get("url");
    if (initial) {
      $("url").value = normalizeUrl(initial);
      scan(normalizeUrl(initial));
    }
  };
})();
