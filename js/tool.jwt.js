/* ==========================================================================
   CyberBuddy — JWT Security Workbench controller (JWT-01 + JWT-02 + JWT-03)

   Functional: Analyze & Verify (decode, inspect, verify via Web Crypto),
   Edit & Generate (edit header/payload, semantic diff, HMAC/private-key
   signing, local RSA test-key generation, TEST TOKEN output with safe
   copy/download), Test Variants (authorized-test variant templates) and
   Secret Test (bounded HS256/384/512 secret testing in a Web Worker with
   progress, cancel and limits). The pure engine lives in js/jwt.engine.js
   (DOM-free, also exercised under Node in test_engines.py); the secret
   search runs in js/jwt.worker.js. All crypto — including private key
   import/export, test-key generation and the secret search loop — lives in
   the engine/worker; this controller only binds DOM.

   Privacy guarantees baked in here:
     - no fetch/XMLHttpRequest/sendBeacon; connect-src is 'self' only;
     - no localStorage/sessionStorage/history/URL writing;
     - tokens, keys and wordlists live in memory only and are never
       persisted; the uploaded wordlist is read inside the worker;
     - "Copy token" / "Download token" export the token alone — key export
       is a separate, explicit, confirmed action (never accidental).
   ========================================================================== */
"use strict";

(function (root) {
  var J = root.CyberBuddyJwt;
  if (!J) {
    // Engine failed to load; degrade gracefully (tabs still work).
    root.initJwt = function () {};
    return;
  }

  function $(id) { return document.getElementById(id); }

  function showError(msg) {
    var el = $("jwtTokenError");
    if (!el) return;
    if (msg) {
      el.textContent = msg;
      el.classList.remove("hidden");
    } else {
      el.textContent = "";
      el.classList.add("hidden");
    }
  }

  function prettyJson(value) {
    try { return JSON.stringify(value, null, 2); }
    catch (e) { return String(value); }
  }

  function fmtTime(n) {
    if (typeof n !== "number") return "—";
    try { return new Date(n * 1000).toISOString().replace(/\.\d+Z$/, "Z"); }
    catch (e) { return String(n); }
  }

  function age(seconds) {
    var abs = Math.abs(seconds);
    if (abs < 60) return seconds + "s";
    if (abs < 3600) return Math.floor(seconds / 60) + "m";
    if (abs < 86400) return Math.floor(seconds / 3600) + "h";
    return Math.floor(seconds / 86400) + "d";
  }

  function renderObservations(obs) {
    var ul = $("jwtObservations");
    if (!ul) return;
    ul.innerHTML = "";
    obs.forEach(function (o) {
      var li = document.createElement("li");
      li.className = "jwt-obs jwt-obs-" + o.level;
      li.textContent = o.message;
      ul.appendChild(li);
    });
    if (!obs.length) {
      var li = document.createElement("li");
      li.textContent = "No contextual observations.";
      ul.appendChild(li);
    }
  }

  function renderClaims(payload, parsed) {
    var now = Math.floor(Date.now() / 1000);
    var iat = typeof payload.iat === "number" ? payload.iat : null;
    var exp = typeof payload.exp === "number" ? payload.exp : null;
    var nbf = typeof payload.nbf === "number" ? payload.nbf : null;

    var timeline = $("jwtTimeline");
    if (timeline) {
      var parts = [];
      parts.push("Header alg: <code>" + escapeHtml(parsed.header.alg) + "</code>");
      if (iat != null) parts.push("issued " + fmtTime(iat));
      if (nbf != null) parts.push("not before " + fmtTime(nbf));
      if (exp != null) parts.push("expires " + fmtTime(exp) + " (" + (exp < now ? "expired " + age(now - exp) + " ago" : "in " + age(exp - now)) + ")");
      timeline.innerHTML = parts.join(" &middot; ");
    }

    var wrap = $("jwtClaims");
    if (!wrap) return;
    wrap.innerHTML = "";
    [
      ["iss", "Issuer"], ["sub", "Subject"], ["aud", "Audience"],
      ["iat", "Issued at", true], ["nbf", "Not before", true],
      ["exp", "Expires", true], ["jti", "JWT ID"]
    ].forEach(function (row) {
      var key = row[0], label = row[1], isTime = row[2];
      if (!Object.prototype.hasOwnProperty.call(payload, key)) return;
      var val = payload[key];
      var div = document.createElement("div");
      div.className = "jwt-claim";
      var text = isTime ? fmtTime(val) + (typeof val === "number" ? " (" + val + ")" : "")
        : (typeof val === "object" ? prettyJson(val) : String(val));
      div.innerHTML = "<span class=jwt-claim-k>" + label + " <code>" + key + "</code></span>" +
        "<span class=jwt-claim-v>" + escapeHtml(text) + "</span>";
      wrap.appendChild(div);
    });
    var other = Object.keys(payload).filter(function (k) {
      return ["iss", "sub", "aud", "iat", "nbf", "exp", "jti"].indexOf(k) === -1;
    });
    if (other.length) {
      other.forEach(function (k) {
        var val = payload[k];
        var div = document.createElement("div");
        div.className = "jwt-claim";
        var text = typeof val === "object" ? prettyJson(val) : String(val);
        div.innerHTML = "<span class=jwt-claim-k>" + escapeHtml(k) + "</span>" +
          "<span class=jwt-claim-v>" + escapeHtml(text) + "</span>";
        wrap.appendChild(div);
      });
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function setDecodedState(label, cls) {
    var el = $("jwtDecodedState");
    if (!el) return;
    el.textContent = label;
    el.className = "jwt-state " + (cls || "jwt-state-decoded");
  }

  function showDecoded() {
    $("jwtDecodeEmpty").classList.add("hidden");
    $("jwtDecoded").classList.remove("hidden");
  }

  function clearVerifyResult() {
    var box = $("jwtVerifyResult");
    if (!box) return;
    box.className = "jwt-verify-result hidden";
    box.innerHTML = "";
  }

  var lastParsed = null;

  function parse() {
    var raw = $("jwtToken").value.trim();
    // Accept "Authorization: Bearer <token>" or "Bearer <token>".
    raw = raw.replace(/^[\s,;]*(?:authorization\s*:)?\s*bearer\s+/i, "");
    clearVerifyResult();
    if (!raw) {
      showError(null);
      $("jwtDecodeEmpty").classList.remove("hidden");
      $("jwtDecoded").classList.add("hidden");
      lastParsed = null;
      lastVerification = null;
      setExportEnabled(false);
      refreshEditDiff();
      updateSecretBase();
      updateVariantBase();
      renderVapt(null);
      return;
    }
    var res = J.tryParseToken(raw);
    if (!res.ok) {
      showError(res.error);
      $("jwtDecodeEmpty").classList.remove("hidden");
      $("jwtDecoded").classList.add("hidden");
      lastParsed = null;
      lastVerification = null;
      setExportEnabled(false);
      refreshEditDiff();
      updateSecretBase();
      updateVariantBase();
      renderVapt(null);
      return;
    }
    showError(null);
    showDecoded();
    var parsed = res.token;
    lastParsed = parsed;
    // A different token means the previous verify() no longer describes it.
    lastVerification = null;
    setExportEnabled(true);
    $("jwtHeader").textContent = prettyJson(parsed.header);
    $("jwtPayload").textContent = prettyJson(parsed.payload);
    renderClaims(parsed.payload, parsed);
    renderObservations(J.observations(parsed));
    setDecodedState("Decoded", "jwt-state-decoded");
    refreshEditDiff();
    updateSecretBase();
    updateVariantBase();
    renderVapt(parsed);

    // Do not silently use the token's header as an expected-algorithm policy.
    // The analyst may choose an issuer-configured expected value in the
    // verification panel; Auto remains deliberately explicit.

    // Auto-run claim validation so the analyst sees time/iss/aud state
    // without having to supply a key.
    var cv = J.validateClaims(parsed.payload, {
      iss: $("jwtExpIss").value.trim() || undefined,
      aud: $("jwtExpAud").value.trim() || undefined,
      sub: $("jwtExpSub").value.trim() || undefined,
      clockTolerance: parseInt($("jwtSkew").value, 10) || 0
    });
    if (!cv.valid) {
      setDecodedState("Decoded · claims issues", "jwt-state-warn");
    }
  }

  function activeKeyType() {
    var active = document.querySelector("#jwt-panel-analyze .jwt-key-tab.is-active");
    return active ? active.getAttribute("data-keytype") : "secret";
  }

  function readKey() {
    var type = activeKeyType();
    if (type === "secret") return { type: type, key: $("jwtSecret").value };
    if (type === "pem") return { type: type, key: $("jwtPem").value.trim() };
    if (type === "jwk") {
      var txt = $("jwtJwk").value.trim();
      if (!txt) return { type: type, key: null };
      try { return { type: type, key: JSON.parse(txt) }; }
      catch (e) { return { error: "JWK is not valid JSON: " + e.message }; }
    }
    if (type === "jwks") {
      var t = $("jwtJwks").value.trim();
      if (!t) return { type: type, key: null };
      try { return { type: type, key: JSON.parse(t) }; }
      catch (e) { return { error: "JWKS is not valid JSON: " + e.message }; }
    }
    return { error: "Unknown key type" };
  }

  function setVerifyResult(valid, lines) {
    var box = $("jwtVerifyResult");
    if (!box) return;
    box.classList.remove("hidden", "jwt-verify-ok", "jwt-verify-bad");
    box.classList.add(valid ? "jwt-verify-ok" : "jwt-verify-bad");
    box.innerHTML = "<strong>" + (valid ? "Verified" : "Not verified") + "</strong>" +
      "<ul>" + lines.map(function (l) { return "<li>" + escapeHtml(l) + "</li>"; }).join("") + "</ul>";
  }

  async function verify() {
    if (!lastParsed) {
      setVerifyResult(false, ["Paste a valid token first."]);
      return;
    }
    var read = readKey();
    if (read.error) { setVerifyResult(false, [read.error]); return; }
    if (read.key == null || read.key === "") {
      setVerifyResult(false, ["Supply a key to verify the signature."]);
      return;
    }
    var opts = {
      iss: $("jwtExpIss").value.trim() || undefined,
      aud: $("jwtExpAud").value.trim() || undefined,
      sub: $("jwtExpSub").value.trim() || undefined,
      clockTolerance: parseInt($("jwtSkew").value, 10) || 0
    };
    var expectedAlg = $("jwtExpectedAlg").value;
    if (expectedAlg) opts.alg = expectedAlg;

    var btn = $("jwtVerify");
    if (btn) { btn.disabled = true; btn.textContent = "Verifying…"; }
    var lines = [];
    var ok = true;
    try {
      var res = await J.verifyToken(lastParsed.raw, read.key, opts);
      if (!res.valid) {
        ok = false;
        lines.push(res.error || "Signature verification failed.");
      } else {
        lines.push("Signature matches using " + res.alg + ".");
      }
    } catch (e) {
      ok = false;
      lines.push(e && e.message ? e.message : String(e));
    }
    var cv = J.validateClaims(lastParsed.payload, opts);
    if (cv.valid) {
      lines.push("Claims (iss/aud/sub/exp/nbf) validate.");
    } else {
      ok = false;
      cv.errors.forEach(function (err) { lines.push(err.message + " (" + err.code + ")."); });
    }
    if (ok) setDecodedState("Verified", "jwt-state-ok");
    else setDecodedState("Decoded · verification issues", "jwt-state-warn");
    setVerifyResult(ok, lines);
    lastVerification = { valid: ok, lines: lines };
    if (btn) { btn.disabled = false; btn.textContent = "Verify signature & claims"; }
  }

  // --- Markdown analysis export ---------------------------------------
  /* Parity with the scanners and the CSRF generator, which all leave with a
     shareable artifact. The document is assembled by the engine
     (J.buildMarkdown) so the redaction rules are covered by the Node-side
     tests rather than only existing in DOM code. */

  var lastVerification = null;

  function setExportEnabled(on) {
    ["jwtCopyMd", "jwtDownloadMd"].forEach(function (id) {
      var el = $(id);
      if (el) el.disabled = !on;
    });
    if (!on) {
      var st = $("jwtExportStatus");
      if (st) st.textContent = "";
    }
  }

  function currentMarkdown() {
    return J.buildMarkdown(lastParsed, { verification: lastVerification });
  }

  function initExportPanel() {
    var copyBtn = $("jwtCopyMd");
    var dlBtn = $("jwtDownloadMd");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        if (!lastParsed) return;
        setClipboardIn("jwtExportStatus", currentMarkdown(),
          "Markdown analysis copied to clipboard.",
          "Copy failed — download the file instead.");
      });
    }
    if (dlBtn) {
      dlBtn.addEventListener("click", function () {
        if (!lastParsed) return;
        downloadText("cyberbuddy-jwt-analysis.md", currentMarkdown() + "\n", "text/markdown");
        var st = $("jwtExportStatus");
        if (st) st.textContent = "Markdown analysis downloaded.";
      });
    }
  }

  // --- Roving-tabindex tab navigation (panels) ------------------------
  function initTabs(onActivate) {
    var tablist = document.querySelector(".jwt-tablist");
    if (!tablist) return;
    var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));
    var panels = tabs.map(function (t) { return document.getElementById(t.getAttribute("aria-controls")); });

    function activate(tab, focus) {
      tabs.forEach(function (t) {
        var sel = t === tab;
        t.classList.toggle("is-active", sel);
        t.setAttribute("aria-selected", sel ? "true" : "false");
        t.setAttribute("tabindex", sel ? "0" : "-1");
      });
      panels.forEach(function (p) {
        var show = p.id === tab.getAttribute("aria-controls");
        p.classList.toggle("is-active", show);
        if (show) p.removeAttribute("hidden");
        else p.setAttribute("hidden", "");
      });
      if (focus) tab.focus();
      if (onActivate && tab.getAttribute("aria-controls")) onActivate(tab.getAttribute("aria-controls"));
    }

    tabs.forEach(function (tab, i) {
      tab.addEventListener("click", function () { activate(tab); tab.focus(); });
      tab.addEventListener("keydown", function (e) {
        var next = null;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") next = tabs[(i + 1) % tabs.length];
        else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = tabs[(i - 1 + tabs.length) % tabs.length];
        else if (e.key === "Home") next = tabs[0];
        else if (e.key === "End") next = tabs[tabs.length - 1];
        if (next) { e.preventDefault(); activate(next, true); }
      });
    });
  }

  // --- Key-type sub-tabs (Verify panel + Edit panel; one per tablist) --
  function initKeyTabs() {
    var lists = Array.prototype.slice.call(document.querySelectorAll(".jwt-key-tabs"));
    lists.forEach(function (list) {
      var tabs = Array.prototype.slice.call(list.querySelectorAll(".jwt-key-tab"));
      var panelsWrap = list.nextElementSibling;
      var panels = panelsWrap && panelsWrap.classList.contains("jwt-key-panels")
        ? Array.prototype.slice.call(panelsWrap.children) : [];
      tabs.forEach(function (tab) {
        tab.addEventListener("click", function () {
          tabs.forEach(function (t) {
            var on = t === tab;
            t.classList.toggle("is-active", on);
            t.setAttribute("aria-selected", on ? "true" : "false");
          });
          panels.forEach(function (p) {
            var on = p.id === tab.getAttribute("aria-controls");
            p.classList.toggle("hidden", !on);
            if (on) p.removeAttribute("hidden"); else p.setAttribute("hidden", "");
          });
        });
      });
    });
  }

  // --- Mask the raw token on screen (display only; the underlying value
  // is still parsed in memory) ---------------------------------------
  function initMask() {
    var cb = $("jwtMask");
    var ta = $("jwtToken");
    if (!cb || !ta) return;
    var real = "";
    cb.addEventListener("change", function () {
      if (cb.checked) {
        real = ta.value;
        ta.value = real.replace(/./g, "•");
        ta.setAttribute("readonly", "readonly");
      } else {
        ta.value = real;
        ta.removeAttribute("readonly");
        ta.focus();
      }
    });
    // If the analyst edits while masked, unmask.
    ta.addEventListener("focus", function () { if (cb.checked) { cb.checked = false; cb.dispatchEvent(new Event("change")); } });
  }

  // ======================================================================
  // JWT-02 — Edit & Generate
  // ======================================================================

  var editGenKey = null;      // {alg, privateKey, publicKey, publicJwk}
  var editDirty = false;      // the analyst (or a helper) changed the editors
  var editLoadedRaw = null;   // raw token last loaded into the editors

  /* Parse an editor's JSON without showing errors (diff refresh is noisy
     while typing). Returns the object or null. */
  function silentParse(text) {
    if (!text || !text.trim()) return null;
    try {
      var v = JSON.parse(text);
      return (v && typeof v === "object" && !Array.isArray(v)) ? v : null;
    } catch (e) { return null; }
  }

  /* Parse an editor's JSON for the sign flow, reporting errors to the
     matching error line. Returns the object or null. */
  function parseEditor(id, errId) {
    var el = $(id);
    var err = $(errId);
    var text = el.value.trim();
    if (!text) {
      if (err) { err.textContent = "Paste JSON here."; err.classList.remove("hidden"); }
      return null;
    }
    var v;
    try { v = JSON.parse(text); }
    catch (e) {
      if (err) { err.textContent = "Not valid JSON: " + e.message; err.classList.remove("hidden"); }
      return null;
    }
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      if (err) { err.textContent = "Must be a JSON object."; err.classList.remove("hidden"); }
      return null;
    }
    if (err) { err.textContent = ""; err.classList.add("hidden"); }
    return v;
  }

  function fillEditTemplate() {
    var now = Math.floor(Date.now() / 1000);
    $("jwtEditHeader").value = prettyJson({ alg: "HS256", typ: "JWT" });
    $("jwtEditPayload").value = prettyJson({ sub: "test-user", iat: now, exp: now + 3600, jti: J.randomJti() });
    editDirty = false;
    editLoadedRaw = "template";
  }

  function fmtVal(v) {
    if (v == null) return "—";
    if (typeof v === "object") { try { return JSON.stringify(v); } catch (e) { return String(v); } }
    return String(v);
  }

  function refreshEditDiff() {
    var list = $("jwtEditDiffList");
    if (!list) return;
    var summary = $("jwtEditDiffSummary");
    var base = lastParsed
      ? { header: lastParsed.header, payload: lastParsed.payload }
      : { header: {}, payload: {} };
    var h = silentParse($("jwtEditHeader").value);
    var p = silentParse($("jwtEditPayload").value);
    list.innerHTML = "";
    if (h === null || p === null) {
      if (summary) summary.textContent = "Waiting for valid JSON in both editors — the semantic diff renders before you sign.";
      return;
    }
    var counts = { added: 0, removed: 0, changed: 0 };
    [["Header", J.diffClaims(base.header, h)], ["Payload", J.diffClaims(base.payload, p)]].forEach(function (pair) {
      var rows = pair[1];
      rows.forEach(function (r) { if (counts[r.kind] != null) counts[r.kind]++; });
      var hd = document.createElement("p");
      hd.className = "jwt-diff-head";
      hd.textContent = pair[0] + (lastParsed ? " (original token → editor)" : " (new token — no original analyzed)");
      list.appendChild(hd);
      if (!rows.length) {
        var empty = document.createElement("p");
        empty.className = "jwt-diff-empty";
        empty.textContent = "(empty)";
        list.appendChild(empty);
        return;
      }
      rows.forEach(function (r) {
        var div = document.createElement("div");
        div.className = "jwt-diff-row jwt-diff-" + r.kind;
        var middle;
        if (r.kind === "added") middle = "<em>added:</em> " + escapeHtml(fmtVal(r.to));
        else if (r.kind === "removed") middle = "<em>was:</em> " + escapeHtml(fmtVal(r.from));
        else if (r.kind === "changed") middle = "<em>was:</em> " + escapeHtml(fmtVal(r.from)) + " &rarr; <em>now:</em> " + escapeHtml(fmtVal(r.to));
        else middle = escapeHtml(fmtVal(r.from));
        div.innerHTML = "<span class=jwt-diff-kind>" +
          { added: "+ add", removed: "− del", changed: "~ mod", unchanged: "· same" }[r.kind] + "</span>" +
          "<span class=jwt-diff-claim><code>" + escapeHtml(r.claim) + "</code></span>" +
          "<span class=jwt-diff-vals>" + middle + "</span>";
        list.appendChild(div);
      });
    });
    if (summary) {
      if (counts.added + counts.removed + counts.changed === 0) {
        summary.textContent = "No semantic changes vs the original token.";
      } else {
        summary.textContent = counts.added + " added · " + counts.removed +
          " removed · " + counts.changed + " changed — review before signing.";
      }
    }
  }

  function loadEditFromToken() {
    if (!lastParsed) {
      var status = $("jwtEditDiffSummary");
      if (status) status.textContent = "Paste and decode a token in the shared input first, then load it into the editors.";
      return;
    }
    $("jwtEditHeader").value = prettyJson(lastParsed.header);
    $("jwtEditPayload").value = prettyJson(lastParsed.payload);
    editDirty = false;
    editLoadedRaw = lastParsed.raw;
    syncAlgSelectFromHeader();
    refreshEditDiff();
  }

  function onEditPanelShown() {
    var h = $("jwtEditHeader");
    var p = $("jwtEditPayload");
    if (!h || !p) return;
    // Auto-load the analyzed token into untouched editors; never clobber
    // edits the analyst has already made.
    if (!editDirty) {
      if (lastParsed && editLoadedRaw !== lastParsed.raw) loadEditFromToken();
      else if (!editLoadedRaw) fillEditTemplate();
    }
    refreshEditDiff();
  }

  function syncAlgSelectFromHeader() {
    var h = silentParse($("jwtEditHeader").value);
    var sel = $("jwtSignAlg");
    if (!h || !h.alg || !sel) return;
    if (sel.value === h.alg) return;
    var match = Array.prototype.some.call(sel.options, function (o) { return o.value === h.alg; });
    if (match) sel.value = h.alg;
  }

  function syncHeaderAlgFromSelect() {
    var h = silentParse($("jwtEditHeader").value);
    var sel = $("jwtSignAlg");
    if (!h || !sel) return;
    h.alg = sel.value;
    $("jwtEditHeader").value = prettyJson(h);
    editDirty = true;
    refreshEditDiff();
  }

  // --- Standard-claim helpers ----------------------------------------

  function helperDefs() {
    return [
      ["iss", "jwtHelpIss"], ["sub", "jwtHelpSub"], ["aud", "jwtHelpAud"],
      ["exp", "jwtHelpExp", true], ["nbf", "jwtHelpNbf", true],
      ["iat", "jwtHelpIat", true], ["jti", "jwtHelpJti"]
    ];
  }

  function applyHelpers() {
    var p = parseEditor("jwtEditPayload", "jwtEditPayloadError");
    if (!p) return;
    var changed = false;
    helperDefs().forEach(function (d) {
      var claim = d[0], inputId = d[1], isTime = d[2];
      var cb = $(inputId + "Use");
      if (!cb || !cb.checked) return;
      var v = $(inputId).value.trim();
      if (v === "") {
        if (Object.prototype.hasOwnProperty.call(p, claim)) { delete p[claim]; changed = true; }
        return;
      }
      var out = v;
      if (isTime) {
        var n = Number(v);
        if (!isFinite(n)) { out = null; }
        else out = Math.floor(n);
      }
      if (out !== null && JSON.stringify(p[claim]) !== JSON.stringify(out)) { p[claim] = out; changed = true; }
    });
    if (changed) {
      $("jwtEditPayload").value = prettyJson(p);
      editDirty = true;
      refreshEditDiff();
    }
  }

  function quickHelper(claim, value) {
    var def = helperDefs().filter(function (d) { return d[0] === claim; })[0];
    if (!def) return;
    $(def[1]).value = String(value);
    var cb = $(def[1] + "Use");
    if (cb) cb.checked = true;
    applyHelpers();
  }

  // --- Signing --------------------------------------------------------

  function activeEditKeyType() {
    var active = document.querySelector(".jwt-edit-key-tabs .jwt-key-tab.is-active");
    return active ? active.getAttribute("data-keytype") : "secret";
  }

  function readEditKey() {
    var type = activeEditKeyType();
    var alg = $("jwtSignAlg").value;
    if (type === "secret") return { key: $("jwtEditSecret").value };
    if (type === "pem") {
      var v = $("jwtEditPem").value.trim();
      return v ? { key: v } : { error: "Paste a PKCS#8 private key (-----BEGIN PRIVATE KEY-----)." };
    }
    if (type === "jwk") {
      var t = $("jwtEditJwk").value.trim();
      if (!t) return { error: "Paste a private JWK (it must include \"d\")." };
      try { return { key: JSON.parse(t) }; }
      catch (e) { return { error: "Private JWK is not valid JSON: " + e.message }; }
    }
    if (type === "generated") {
      if (!editGenKey) return { error: "No generated key yet — generate a throwaway RSA test key first." };
      if (!/^(RS|PS)/.test(alg)) return { error: "The generated key is an RSA key — select an RS*/PS* algorithm to sign with it." };
      if (editGenKey.alg !== alg) return { error: "The generated key was created for " + editGenKey.alg + " — select that algorithm (RSA key families are not interchangeable in Web Crypto)." };
      return { key: editGenKey.privateKey };
    }
    return { error: "Unknown key type" };
  }

  function setSignResult(ok, lines) {
    var result = $("jwtEditResult");
    if (!result) return;
    result.classList.remove("hidden");
    var banner = $("jwtTestBanner");
    if (banner) banner.classList.toggle("hidden", !ok);
    var ul = $("jwtEditResultLines");
    if (ul) {
      ul.className = "jwt-edit-lines " + (ok ? "ok" : "bad");
      ul.innerHTML = lines.map(function (l) { return "<li>" + escapeHtml(l) + "</li>"; }).join("");
    }
  }

  async function signEdit() {
    var header = parseEditor("jwtEditHeader", "jwtEditHeaderError");
    var payload = parseEditor("jwtEditPayload", "jwtEditPayloadError");
    if (!header || !payload) {
      $("jwtEditResult").classList.add("hidden");
      return;
    }
    var alg = $("jwtSignAlg").value;
    if (header.alg && header.alg !== alg) {
      setSignResult(false, ["The header editor declares alg " + header.alg +
        " but the signing algorithm is " + alg + " — they must agree."]);
      return;
    }
    var read = readEditKey();
    if (read.error) { setSignResult(false, [read.error]); return; }
    if (read.key == null || read.key === "") {
      setSignResult(false, ["Supply a key to sign."]);
      return;
    }

    var btn = $("jwtSign");
    if (btn) { btn.disabled = true; btn.textContent = "Signing…"; }
    var res = await J.signToken(header, payload, read.key, { alg: alg });
    if (btn) { btn.disabled = false; btn.textContent = "Sign & build test token"; }

    if (!res || res.error) {
      setSignResult(false, [res && res.error ? res.error : "Signing failed."]);
      $("jwtEditToken").value = "";
      return;
    }
    $("jwtEditToken").value = res.token;
    $("jwtCopyStatus").textContent = "";
    setSignResult(true, [
      "Signed locally with " + res.alg + ".",
      "This is a TEST TOKEN — a target may still reject it (key, claims or algorithm policy)."
    ]);
  }

  // --- Safe copy / download (token only — never key material) ---------

  /* One clipboard path for the whole workbench. Delegates to the shared
     copyText() in js/app.js, which already handles the insecure-context
     fallback (execCommand) that a bare navigator.clipboard check misses —
     the panels used to carry three near-identical copies of this logic and
     only differed in which status element they wrote to. */
  function setClipboardIn(statusId, text, okMsg, failMsg) {
    var status = $(statusId);
    var done = function (ok) {
      if (status) status.textContent = ok ? okMsg : failMsg;
      return ok;
    };
    if (typeof root.copyText === "function") return root.copyText(text).then(done, function () { return done(false); });
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () { return done(true); },
        function () { return done(false); });
    }
    return Promise.resolve(done(false));
  }

  function setClipboard(text, okMsg, failMsg) {
    return setClipboardIn("jwtCopyStatus", text, okMsg, failMsg);
  }

  function downloadText(name, text, type) {
    var blob = new Blob([text], { type: type || "text/plain" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function copyToken() {
    var ta = $("jwtEditToken");
    if (!ta || !ta.value) return;
    setClipboard(ta.value, "Token copied to clipboard.", "Copy failed — select the token text manually.");
  }

  function downloadToken() {
    var ta = $("jwtEditToken");
    if (!ta || !ta.value) return;
    downloadText("cyberbuddy-test-token.jwt", ta.value + "\n", "text/plain");
  }

  // --- Generated throwaway RSA test key -------------------------------

  async function generateEditKey() {
    var btn = $("jwtGenKey");
    var status = $("jwtGenKeyStatus");
    var alg = $("jwtSignAlg").value;
    if (btn) { btn.disabled = true; btn.textContent = "Generating…"; }
    var res = await J.generateRsaTestPair(alg);
    if (btn) { btn.disabled = false; btn.textContent = "Generate RSA test key pair"; }
    if (!res || res.error) {
      if (status) status.textContent = (res && res.error) || "Generation failed.";
      return;
    }
    editGenKey = res;
    if (status) status.textContent = "2048-bit RSA test key pair ready for " + res.alg + " — held in memory only.";
    $("jwtGenKeyPub").value = prettyJson(res.publicJwk);
    $("jwtGenKeyPubWrap").classList.remove("hidden");
    $("jwtGenKeyActions").classList.remove("hidden");
  }

  function copyPublicKey() {
    var ta = $("jwtGenKeyPub");
    if (!ta || !ta.value) return;
    setClipboard(ta.value, "Public JWK copied to clipboard.", "Copy failed — select the JWK text manually.");
  }

  async function copyPrivateKey() {
    if (!editGenKey) return;
    if (!root.confirm("Copy the PRIVATE JWK of the throwaway test key? Anyone with it can sign as this key. Only do this for your own authorized testing.")) return;
    try {
      var jwk = await J.exportPrivateJwk(editGenKey.privateKey);
      setClipboard(JSON.stringify(jwk, null, 2), "Private JWK copied to clipboard — treat it like a password.", "Copy failed.");
    } catch (e) {
      $("jwtGenKeyStatus").textContent = "Private key export failed: " + (e && e.message ? e.message : String(e));
    }
  }

  async function downloadPrivateKey() {
    if (!editGenKey) return;
    if (!root.confirm("Download the PRIVATE JWK of the throwaway test key? Anyone with this file can sign as this key. Only do this for your own authorized testing.")) return;
    try {
      var jwk = await J.exportPrivateJwk(editGenKey.privateKey);
      downloadText("throwaway-private-key.jwk.json", JSON.stringify(jwk, null, 2) + "\n", "application/json");
    } catch (e) {
      $("jwtGenKeyStatus").textContent = "Private key export failed: " + (e && e.message ? e.message : String(e));
    }
  }

  // ======================================================================
  // JWT-03 — Test Variants
  // ======================================================================

  var varGen = null; // {alg, privateKey, publicJwk}

  function updateVariantBase() {
    var el = $("jwtVarBase");
    if (!el) return;
    if (!lastParsed) {
      el.textContent = "Paste and decode a token above — variants build on the analyzed token.";
    } else {
      el.textContent = "Base token: " + lastParsed.header.alg +
        (lastParsed.header.kid != null ? " · kid " + String(lastParsed.header.kid) : "") +
        " — variants are templates, never findings.";
    }
  }

  function activeVarKeyType() {
    var active = document.querySelector(".jwt-var-key-tabs .jwt-key-tab.is-active");
    return active ? active.getAttribute("data-keytype") : "secret";
  }

  function readVariantSigningKey() {
    var base = lastParsed;
    if (!base) return { error: "Paste a token to use as the base first." };
    var alg = base.header.alg;
    var type = activeVarKeyType();
    if (type === "secret") {
      if (!/^HS/.test(alg)) {
        return { error: "The base token is " + alg + " — an HMAC secret only signs HS* tokens. Use a private key or the generated pair." };
      }
      var s = $("jwtVarSecret").value;
      if (!s) return { error: "Supply the HMAC secret." };
      return { alg: alg, key: s };
    }
    if (type === "private") {
      var t = $("jwtVarPrivate").value.trim();
      if (!t) return { error: "Paste a private key (PEM PKCS#8 or JWK JSON)." };
      var key = t;
      var jwk = null;
      try {
        var j = JSON.parse(t);
        if (j && typeof j === "object" && !Array.isArray(j)) { key = j; jwk = j; }
      } catch (e) { /* not JSON -> PEM */ }
      return { alg: alg, key: key, jwk: jwk };
    }
    if (type === "generated") {
      if (!varGen) return { error: "Generate a local RSA test pair first." };
      if (varGen.alg !== alg) {
        return { error: "The generated pair is " + varGen.alg + " but the base token is " + alg + " — the pair is bound to one algorithm family." };
      }
      return { alg: alg, key: varGen.privateKey, publicJwk: varGen.publicJwk };
    }
    return { error: "Unknown key type" };
  }

  async function generateVariantKey() {
    var btn = $("jwtVarGenKey");
    var status = $("jwtVarGenStatus");
    if (!lastParsed) {
      if (status) status.textContent = "Paste a base token first.";
      return;
    }
    var alg = lastParsed.header.alg;
    if (btn) { btn.disabled = true; btn.textContent = "Generating…"; }
    var res = await J.generateRsaTestPair(alg);
    if (btn) { btn.disabled = false; btn.textContent = "Generate RSA test pair"; }
    if (!res || res.error) {
      if (status) status.textContent = (res && res.error) + " — paste a private key (or an HMAC secret for HS* tokens) instead.";
      return;
    }
    varGen = res;
    if (status) status.textContent = "2048-bit RSA test pair ready for " + res.alg + " — held in memory only.";
    $("jwtVarGenPub").value = prettyJson(res.publicJwk);
  }

  function setVariantResult(ok, note, lines) {
    var result = $("jwtVarResult");
    if (!result) return;
    result.classList.remove("hidden");
    var banner = result.querySelector(".jwt-test-banner");
    if (banner) banner.classList.toggle("hidden", !ok);
    var noteEl = $("jwtVarNote");
    if (noteEl) noteEl.textContent = ok ? note : "";
    var ul = $("jwtVarResultLines");
    if (ul) {
      ul.className = "jwt-edit-lines " + (ok ? "ok" : "bad");
      ul.innerHTML = lines.map(function (l) { return "<li>" + escapeHtml(l) + "</li>"; }).join("");
    }
  }

  async function runVariant(type) {
    if (!lastParsed) {
      setVariantResult(false, "", ["Paste and decode a base token first."]);
      $("jwtVarToken").value = "";
      return;
    }
    var opts = {};
    if (type === "tamper" || type === "claim-resign") {
      opts.claim = $("jwtVarClaim").value.trim();
      opts.value = $("jwtVarValue").value;
    } else if (type === "alg-confusion") {
      opts.publicKeyPem = $("jwtVarPubPem").value.trim();
    } else if (type === "jku" || type === "x5u") {
      opts.url = $("jwtVarUrl").value.trim();
      type = $("jwtVarJkuX5u").value === "x5u" ? "x5u" : "jku";
    } else if (type === "kid") {
      opts.kid = $("jwtVarKid").value.trim();
    }
    var needsKey = ["claim-resign", "jku", "x5u", "kid", "embedded-jwk"].indexOf(type) !== -1;
    if (needsKey) {
      var keyInfo = readVariantSigningKey();
      if (keyInfo.error) { setVariantResult(false, "", [keyInfo.error]); $("jwtVarToken").value = ""; return; }
      opts.alg = keyInfo.alg;
      opts.key = keyInfo.key;
      if (type === "embedded-jwk") {
        if (keyInfo.publicJwk) {
          opts.publicJwk = keyInfo.publicJwk;
        } else if (keyInfo.jwk) {
          try { opts.publicJwk = J.publicJwkFromPrivate(keyInfo.jwk); }
          catch (e) { setVariantResult(false, "", [e.message]); $("jwtVarToken").value = ""; return; }
        } else {
          setVariantResult(false, "", ["The embedded-JWK template needs the public JWK of the signing key — use the generated pair or paste a private JWK (not PEM)."]);
          $("jwtVarToken").value = "";
          return;
        }
      }
    }
    var res = await J.buildVariant(lastParsed, type, opts);
    if (!res || res.error) {
      setVariantResult(false, "", [res && res.error ? res.error : "Variant build failed."]);
      $("jwtVarToken").value = "";
      return;
    }
    $("jwtVarToken").value = res.token;
    $("jwtVarCopyStatus").textContent = "";
    setVariantResult(true, res.note || "", [
      "Template built: " + type + ".",
      "A template is not a finding — only the target's behavior decides."
    ]);
  }

  function presetKidStyle() {
    var style = $("jwtVarKidStyle").value;
    $("jwtVarKid").value = style === "sql" ? "1' OR 1=1--" : "../../../dev/null";
  }

  function copyVariantToken() {
    var ta = $("jwtVarToken");
    if (!ta || !ta.value) return;
    setVariantClipboard(ta.value, "Token copied to clipboard.", "Copy failed — select the token text manually.");
  }

  function setVariantClipboard(text, okMsg, failMsg) {
    return setClipboardIn("jwtVarCopyStatus", text, okMsg, failMsg);
  }

  function downloadVariantToken() {
    var ta = $("jwtVarToken");
    if (!ta || !ta.value) return;
    downloadText("cyberbuddy-test-template.jwt", ta.value + "\n", "text/plain");
  }

  // ======================================================================
  // JWT-03 — Secret Test (bounded HS256/384/512 search in a Web Worker)
  // ======================================================================

  var secretWorker = null;

  function workerUrl() {
    // Derive the worker URL from the engine script tag so the ?v=
    // cache-buster stamped at deploy time is inherited automatically.
    var s = document.querySelector('script[src*="jwt.engine.js"]');
    if (s && s.getAttribute("src")) {
      return s.getAttribute("src").replace(/jwt\.engine\.js/, "jwt.worker.js");
    }
    return "../../js/jwt.worker.js";
  }

  function updateSecretBase() {
    var el = $("jwtSecretBase");
    if (!el) return;
    if (!lastParsed) {
      el.textContent = "Paste an HS256/384/512 token above — secret testing works on the analyzed token.";
    } else if (!/^HS(256|384|512)$/.test(lastParsed.header.alg)) {
      el.textContent = "Secret testing covers HS256/384/512 only; this token is " + lastParsed.header.alg + ".";
    } else {
      el.textContent = "Base token: " + lastParsed.header.alg + " — candidates are tested against its signature, locally.";
    }
  }

  function setSecretResult(ok, lines) {
    var box = $("jwtSecretResult");
    if (!box) return;
    box.classList.remove("hidden", "jwt-verify-ok", "jwt-verify-bad");
    box.classList.add(ok ? "jwt-verify-ok" : "jwt-verify-bad");
    box.innerHTML = "<strong>" + (ok ? "Secret found" : "Secret test") + "</strong>" +
      "<ul>" + lines.map(function (l) { return "<li>" + escapeHtml(l) + "</li>"; }).join("") + "</ul>";
  }

  function secretRunning(running) {
    var start = $("jwtSecretStart");
    var cancel = $("jwtSecretCancel");
    var progress = $("jwtSecretProgress");
    if (start) start.disabled = running;
    if (cancel) cancel.classList.toggle("hidden", !running);
    if (progress) progress.classList.toggle("hidden", !running);
  }

  function finishSecret(m) {
    secretWorker = null;
    secretRunning(false);
    var bar = $("jwtSecretBar");
    var count = $("jwtSecretCount");
    if (m.cancelled) {
      if (count) count.textContent = "Stopped after " + m.tested + " of " + m.total + " candidates.";
      setSecretResult(false, ["Secret test cancelled.", "No secret matched before you stopped it."]);
      $("jwtSecretFoundWrap").classList.add("hidden");
      return;
    }
    if (m.error) {
      if (count) count.textContent = "";
      setSecretResult(false, [m.error]);
      $("jwtSecretFoundWrap").classList.add("hidden");
      return;
    }
    if (m.found) {
      if (bar) bar.value = 100;
      if (count) count.textContent = m.tested + " of " + m.total + " candidates tested — match found.";
      $("jwtSecretFound").value = m.secret;
      $("jwtSecretFoundWrap").classList.remove("hidden");
      setSecretResult(true, [
        "The token's " + (lastParsed ? lastParsed.header.alg : "HS") + " signature matches HMAC key candidate \"" + m.secret + "\".",
        "This is a discovered secret for your own authorized testing — not a verdict about the target."
      ]);
    } else {
      if (bar) bar.value = 100;
      if (count) count.textContent = m.tested + " of " + m.total + " candidates tested — no match.";
      setSecretResult(false, [
        "No candidate matched in " + m.tested + " tested (limit " + m.total + ").",
        "A miss only means the secret is not in this candidate set."
      ]);
      $("jwtSecretFoundWrap").classList.add("hidden");
    }
  }

  function startSecretTest() {
    if (secretWorker) {
      secretWorker.terminate();
      secretWorker = null;
    }
    var base = lastParsed;
    if (!base) { setSecretResult(false, ["Paste a token first."]); return; }
    if (!/^HS(256|384|512)$/.test(base.header.alg)) {
      setSecretResult(false, ["Secret testing covers HS256/384/512 only — this token is " + base.header.alg + "."]);
      return;
    }
    var builtin = $("jwtSecretBuiltin").checked;
    var fileInput = $("jwtWordlist");
    var file = fileInput && fileInput.files && fileInput.files.length ? fileInput.files[0] : null;
    if (!builtin && !file) {
      setSecretResult(false, ["No candidates — enable the built-in list or upload a wordlist."]);
      return;
    }
    var maxCand = parseInt($("jwtMaxCand").value, 10);
    if (!isFinite(maxCand)) maxCand = 10000;
    maxCand = Math.min(100000, Math.max(1, maxCand));
    var maxSec = parseInt($("jwtMaxSec").value, 10);
    if (!isFinite(maxSec)) maxSec = 60;
    maxSec = Math.min(120, Math.max(1, maxSec));

    var worker;
    try {
      worker = new Worker(workerUrl());
    } catch (e) {
      setSecretResult(false, ["This browser could not start the secret-test worker: " + (e && e.message ? e.message : String(e))]);
      return;
    }
    secretWorker = worker;

    worker.onmessage = function (e) {
      var m = e.data || {};
      if (m.type === "progress") {
        var bar = $("jwtSecretBar");
        var count = $("jwtSecretCount");
        if (bar && m.total) bar.value = Math.round((m.tested / m.total) * 100);
        if (count) count.textContent = "Testing " + m.tested + " of " + m.total + " candidates…";
      } else if (m.type === "note") {
        var countEl = $("jwtSecretCount");
        if (countEl) countEl.textContent = m.text;
      } else if (m.type === "done") {
        finishSecret(m);
      }
    };
    worker.onerror = function (ev) {
      finishSecret({ error: "The secret-test worker failed: " + (ev && ev.message ? ev.message : "unknown error") });
    };

    $("jwtSecretResult").classList.add("hidden");
    $("jwtSecretFoundWrap").classList.add("hidden");
    var bar = $("jwtSecretBar");
    if (bar) bar.value = 0;
    secretRunning(true);
    worker.postMessage({
      type: "run",
      alg: base.header.alg,
      signingInput: base.signingInput,
      signature: base.signature,
      builtin: builtin,
      file: file,
      maxCandidates: maxCand,
      deadline: Date.now() + maxSec * 1000
    });
  }

  function cancelSecretTest() {
    if (secretWorker) {
      secretWorker.postMessage({ type: "cancel" });
    }
  }

  function copySecret() {
    var input = $("jwtSecretFound");
    if (!input || !input.value) return;
    setClipboardIn("jwtSecretCopyStatus", input.value,
      "Secret copied to clipboard.",
      "Copy failed — select the secret text manually.");
  }

  function initSecretPanel() {
    var start = $("jwtSecretStart");
    if (!start) return;
    start.addEventListener("click", startSecretTest);
    var cancel = $("jwtSecretCancel");
    if (cancel) cancel.addEventListener("click", cancelSecretTest);
    var wordlist = $("jwtWordlist");
    if (wordlist) {
      wordlist.addEventListener("change", function () {
        var status = $("jwtWordlistStatus");
        var f = wordlist.files && wordlist.files.length ? wordlist.files[0] : null;
        if (status) {
          status.textContent = f
            ? f.name + " chosen — it is read inside the worker when the test starts, never persisted."
            : "No file chosen — the worker reads it only when the test starts.";
        }
      });
    }
    var copy = $("jwtSecretCopy");
    if (copy) copy.addEventListener("click", copySecret);
    updateSecretBase();
  }

  function initVariantPanel() {
    var noneBtn = $("jwtVarNone");
    if (!noneBtn) return;
    noneBtn.addEventListener("click", function () { runVariant("alg-none"); });
    $("jwtVarTamper").addEventListener("click", function () { runVariant("tamper"); });
    $("jwtVarResign").addEventListener("click", function () { runVariant("claim-resign"); });
    $("jwtVarConfusion").addEventListener("click", function () { runVariant("alg-confusion"); });
    $("jwtVarEmbed").addEventListener("click", function () { runVariant("embedded-jwk"); });
    $("jwtVarJku").addEventListener("click", function () { runVariant("jku"); });
    $("jwtVarKidBuild").addEventListener("click", function () { runVariant("kid"); });
    $("jwtVarGenKey").addEventListener("click", generateVariantKey);
    $("jwtVarCopy").addEventListener("click", copyVariantToken);
    $("jwtVarDl").addEventListener("click", downloadVariantToken);
    var style = $("jwtVarKidStyle");
    if (style) {
      style.addEventListener("change", presetKidStyle);
      presetKidStyle();
    }
    updateVariantBase();
  }

  // ======================================================================
  // VAPT — Testing Suggestions & Test Payloads (Analyze & Verify panel)
  //
  // Context-aware authorized-testing cards derived from the parsed token
  // by J.vaptRecommendations (pure rules in the engine — DOM-free and
  // Node-tested). One click builds the ready-to-test TEST PAYLOAD locally;
  // nothing is ever sent anywhere. Refine buttons jump to the matching
  // workbench tab with the same values prefilled.
  // ======================================================================

  var vaptCurrent = null;      // suggestion whose payload is on screen
  var vaptRsaBusy = null;      // in-flight generateRsaTestPair promise

  function switchJwtTab(tabId) {
    var tab = $(tabId);
    if (tab) tab.click(); // the tablist handler activates + moves focus
  }

  function vaptStatus(msg) {
    var el = $("jwtVaptStatus");
    if (el) el.textContent = msg || "";
  }

  /* The embedded-JWK and jku/x5u payloads are self-signed with a throwaway
     local RSA pair. Generate it once per page load and mirror it into the
     Test Variants panel so the refine flow shows the exact key that signed
     the payload. */
  function ensureVaptRsaPair() {
    if (varGen) return Promise.resolve(varGen);
    if (vaptRsaBusy) return vaptRsaBusy;
    vaptRsaBusy = J.generateRsaTestPair("RS256").then(function (res) {
      vaptRsaBusy = null;
      if (!res || res.error) return { error: (res && res.error) || "RSA test-pair generation failed." };
      varGen = res;
      var pub = $("jwtVarGenPub");
      if (pub) pub.value = prettyJson(res.publicJwk);
      var st = $("jwtVarGenStatus");
      if (st) st.textContent = "2048-bit RSA test pair ready for " + res.alg + " — generated by the VAPT suggestion, held in memory only.";
      return res;
    }, function (err) {
      vaptRsaBusy = null;
      return { error: err && err.message ? err.message : String(err) };
    });
    return vaptRsaBusy;
  }

  /* Prefill the workbench tab the suggestion refines into, using the same
     values the one-click build used. */
  function vaptPrefill(sug, opts) {
    opts = opts || {};
    if (sug.tab === "variants") {
      if (opts.publicKeyPem != null) { var pem = $("jwtVarPubPem"); if (pem) pem.value = opts.publicKeyPem; }
      if (opts.url != null) { var u = $("jwtVarUrl"); if (u) u.value = opts.url; }
      if (opts.headerParam) { var sel = $("jwtVarJkuX5u"); if (sel) sel.value = opts.headerParam; }
      if (opts.kid != null) {
        var kid = $("jwtVarKid"); if (kid) kid.value = opts.kid;
        var style = $("jwtVarKidStyle");
        if (style) style.value = opts.kidStyle || "path";
      }
      if (opts.claim != null) {
        var c = $("jwtVarClaim"); if (c) c.value = opts.claim;
      }
    } else if (sug.tab === "edit") {
      // Never clobber edits the analyst already made (onEditPanelShown rule).
      if (lastParsed && !editDirty && editLoadedRaw !== lastParsed.raw) {
        $("jwtEditHeader").value = prettyJson(lastParsed.header);
        $("jwtEditPayload").value = prettyJson(lastParsed.payload);
        editDirty = false;
        editLoadedRaw = lastParsed.raw;
        syncAlgSelectFromHeader();
        refreshEditDiff();
      }
    }
  }

  async function runVaptBuild(sug, inline) {
    if (!lastParsed) {
      vaptStatus("Paste and decode a token first.");
      return;
    }
    var opts = {};
    if (sug.payload === "alg-confusion") {
      opts.publicKeyPem = inline && inline.pem ? inline.pem.value.trim() : "";
      if (!opts.publicKeyPem) {
        vaptStatus("Paste the server's RSA public key (PEM/SPKI) into the card field — the confusion test signs with it as the HMAC secret.");
        if (inline && inline.pem) inline.pem.focus();
        return;
      }
    } else if (sug.payload === "kid") {
      var style = inline && inline.kidStyle ? inline.kidStyle.value : "path";
      opts.kid = style === "sql" ? "1' OR 1=1--" : "../../../dev/null";
      opts.kidStyle = style;
    } else if (sug.payload === "jku" || sug.payload === "x5u") {
      opts.url = inline && inline.url ? inline.url.value.trim() : "";
      if (!opts.url) opts.url = "https://attacker.example/jwks.json";
      if (inline && inline.url && !inline.url.value.trim()) inline.url.value = opts.url;
      opts.headerParam = inline && inline.headerParam && inline.headerParam.value === "x5u" ? "x5u" : "jku";
      var pairJku = await ensureVaptRsaPair();
      if (pairJku.error) { vaptStatus(pairJku.error); return; }
      opts.alg = pairJku.alg;
      opts.key = pairJku.privateKey;
    } else if (sug.payload === "embedded-jwk") {
      var pairEmb = await ensureVaptRsaPair();
      if (pairEmb.error) { vaptStatus(pairEmb.error); return; }
      opts.alg = pairEmb.alg;
      opts.key = pairEmb.privateKey;
      opts.publicJwk = pairEmb.publicJwk;
    }
    vaptStatus("Building “" + sug.title + "” payload locally…");
    var kind = (sug.payload === "jku" || sug.payload === "x5u") ? opts.headerParam : sug.payload;
    var res = await J.buildVaptPayload(lastParsed, kind, opts);
    if (!res || res.error) {
      vaptStatus(res && res.error ? res.error : "Payload build failed.");
      return;
    }
    vaptStatus("");
    vaptPrefill(sug, opts);
    vaptCurrent = { sug: sug, opts: opts };
    showVaptPayload(sug, res);
  }

  function showVaptPayload(sug, res) {
    var box = $("jwtVaptOut");
    if (!box) return;
    box.classList.remove("hidden");
    var label = $("jwtVaptOutLabel");
    if (label) label.textContent = "Test payload for “" + sug.title + "” (compact JWS)";
    var noteEl = $("jwtVaptOutNote");
    if (noteEl) noteEl.textContent = res.note || "";
    var ta = $("jwtVaptToken");
    if (ta) ta.value = res.token || "";
    var copyStatus = $("jwtVaptCopyStatus");
    if (copyStatus) copyStatus.textContent = "";
    var refine = $("jwtVaptRefine");
    if (refine) refine.textContent = sug.refineLabel || "Open the matching tab";
    var howTo = $("jwtVaptHowTo");
    if (howTo) {
      howTo.innerHTML = "";
      (sug.howTo || []).forEach(function (line) {
        var li = document.createElement("li");
        li.textContent = line;
        howTo.appendChild(li);
      });
    }
    try { box.scrollIntoView({ block: "nearest", behavior: "smooth" }); }
    catch (e) { /* older engines */ }
  }

  /* Switch to the matching workbench tab with the suggestion's values
     prefilled — Edit & Generate, Test Variants or Secret Test. */
  function vaptRefine(sug, opts) {
    if (!lastParsed) {
      vaptStatus("Paste and decode a token first.");
      return;
    }
    vaptPrefill(sug, opts || (vaptCurrent && vaptCurrent.sug.id === sug.id ? vaptCurrent.opts : {}));
    if (sug.tab === "edit") {
      switchJwtTab("jwt-tab-edit");
      onEditPanelShown();
      var p = $("jwtEditPayload");
      if (p) p.focus();
      var claims = sug.claims && sug.claims.length ? " Flip: " + sug.claims.join(", ") + "." : "";
      vaptStatus("Token loaded into the editors." + claims);
    } else if (sug.tab === "secret") {
      switchJwtTab("jwt-tab-secret");
      startSecretTest();
    } else {
      switchJwtTab("jwt-tab-variants");
      if ((sug.payload === "embedded-jwk" || sug.payload === "jku" || sug.payload === "x5u") && varGen) {
        var genTab = document.querySelector('.jwt-var-key-tabs .jwt-key-tab[data-keytype="generated"]');
        if (genTab) genTab.click();
      }
    }
  }

  function renderVapt(parsed) {
    var list = $("jwtVaptList");
    if (!list) return;
    list.innerHTML = "";
    vaptCurrent = null;
    var out = $("jwtVaptOut");
    if (out) out.classList.add("hidden");
    vaptStatus("");
    var card = $("jwtVapt");
    var suggestions = parsed ? J.vaptRecommendations(parsed) : [];
    if (card) card.classList.toggle("hidden", !suggestions.length);
    if (!suggestions.length) return;

    suggestions.forEach(function (sug) {
      var item = document.createElement("section");
      item.className = "jwt-vapt-item jwt-vapt-sev-" + sug.severity;

      var head = document.createElement("div");
      head.className = "jwt-vapt-item-head";
      var tag = document.createElement("span");
      tag.className = "jwt-vapt-tag jwt-vapt-tag-" + sug.severity;
      tag.textContent = sug.severity.toUpperCase();
      var title = document.createElement("h4");
      title.className = "jwt-vapt-title";
      title.textContent = sug.title;
      head.appendChild(tag);
      head.appendChild(title);
      item.appendChild(head);

      var why = document.createElement("p");
      why.className = "jwt-vapt-why";
      why.textContent = sug.why;
      item.appendChild(why);

      var inline = {};
      if (sug.needsPem) {
        var pemField = document.createElement("label");
        pemField.className = "jwt-field jwt-vapt-field";
        var pemSpan = document.createElement("span");
        pemSpan.textContent = "Server RSA public key (PEM/SPKI) — pasted, never fetched";
        var pem = document.createElement("textarea");
        pem.id = "jwtVaptConfPem";
        pem.spellcheck = false;
        pem.placeholder = "-----BEGIN PUBLIC KEY-----…";
        pemField.appendChild(pemSpan);
        pemField.appendChild(pem);
        item.appendChild(pemField);
        inline.pem = pem;
      }
      if (sug.needsUrl) {
        var row = document.createElement("div");
        row.className = "jwt-vapt-inline";
        var sel = document.createElement("select");
        sel.id = "jwtVaptJkuSel";
        sel.setAttribute("aria-label", "Header parameter");
        ["jku", "x5u"].forEach(function (v) {
          var o = document.createElement("option");
          o.value = v; o.textContent = v;
          sel.appendChild(o);
        });
        var url = document.createElement("input");
        url.type = "text";
        url.id = "jwtVaptJkuUrl";
        url.autocomplete = "off";
        url.spellcheck = false;
        url.placeholder = "https://attacker.example/jwks.json";
        url.setAttribute("aria-label", "Analyst-controlled key URL");
        row.appendChild(sel);
        row.appendChild(url);
        item.appendChild(row);
        inline.url = url;
        inline.headerParam = sel;
      }
      if (sug.payload === "kid") {
        var kidRow = document.createElement("div");
        kidRow.className = "jwt-vapt-inline";
        var kidSel = document.createElement("select");
        kidSel.id = "jwtVaptKidStyle";
        kidSel.setAttribute("aria-label", "kid test vector");
        [["path", "Path traversal — ../../../dev/null"],
         ["sql", "SQL injection — 1' OR 1=1--"]].forEach(function (pair) {
          var o = document.createElement("option");
          o.value = pair[0]; o.textContent = pair[1];
          kidSel.appendChild(o);
        });
        kidRow.appendChild(kidSel);
        item.appendChild(kidRow);
        inline.kidStyle = kidSel;
      }

      var actions = document.createElement("div");
      actions.className = "jwt-btn-row jwt-vapt-actions";
      var build = document.createElement("button");
      build.type = "button";
      build.className = "btn btn-primary jwt-vapt-build";
      build.textContent = sug.actionLabel;
      build.addEventListener("click", function () {
        if (sug.action === "build") {
          runVaptBuild(sug, inline);
        } else {
          vaptRefine(sug, {});
        }
      });
      actions.appendChild(build);
      item.appendChild(actions);
      list.appendChild(item);
    });
  }

  function initVaptPanel() {
    if (!$("jwtVaptList")) return;
    var copy = $("jwtVaptCopy");
    if (copy) copy.addEventListener("click", function () {
      var ta = $("jwtVaptToken");
      if (!ta || !ta.value) return;
      setClipboardIn("jwtVaptCopyStatus", ta.value,
        "Token copied to clipboard.", "Copy failed — select the token text manually.");
    });
    var copyBurp = $("jwtVaptCopyBurp");
    if (copyBurp) copyBurp.addEventListener("click", function () {
      var ta = $("jwtVaptToken");
      if (!ta || !ta.value) return;
      setClipboardIn("jwtVaptCopyStatus", "Authorization: Bearer " + ta.value,
        "Burp Authorization header copied — paste it into the Repeater request.",
        "Copy failed — select the token text manually.");
    });
    var refine = $("jwtVaptRefine");
    if (refine) refine.addEventListener("click", function () {
      if (vaptCurrent) vaptRefine(vaptCurrent.sug, vaptCurrent.opts);
    });
  }

  // --- Boot -----------------------------------------------------------

  function initEditPanel() {
    var h = $("jwtEditHeader");
    if (!h) return;
    fillEditTemplate();

    $("jwtEditLoad").addEventListener("click", loadEditFromToken);
    $("jwtEditReset").addEventListener("click", function () {
      fillEditTemplate();
      refreshEditDiff();
    });
    h.addEventListener("input", function () { editDirty = true; syncAlgSelectFromHeader(); refreshEditDiff(); });
    $("jwtEditPayload").addEventListener("input", function () { editDirty = true; refreshEditDiff(); });
    $("jwtSignAlg").addEventListener("change", syncHeaderAlgFromSelect);

    $("jwtHelpApply").addEventListener("click", applyHelpers);
    $("jwtQuickIatNow").addEventListener("click", function () { quickHelper("iat", Math.floor(Date.now() / 1000)); });
    $("jwtQuickExp1h").addEventListener("click", function () { quickHelper("exp", Math.floor(Date.now() / 1000) + 3600); });
    $("jwtQuickExp24h").addEventListener("click", function () { quickHelper("exp", Math.floor(Date.now() / 1000) + 86400); });
    $("jwtQuickJti").addEventListener("click", function () { quickHelper("jti", J.randomJti()); });

    $("jwtSign").addEventListener("click", signEdit);
    $("jwtCopyToken").addEventListener("click", copyToken);
    $("jwtDlToken").addEventListener("click", downloadToken);

    $("jwtGenKey").addEventListener("click", generateEditKey);
    $("jwtCopyPub").addEventListener("click", copyPublicKey);
    $("jwtCopyPriv").addEventListener("click", copyPrivateKey);
    $("jwtDlPriv").addEventListener("click", downloadPrivateKey);

    refreshEditDiff();
  }

  function initJwt() {
    var ta = $("jwtToken");
    if (!ta) return;
    initTabs(function (panelId) {
      if (panelId === "jwt-panel-edit") onEditPanelShown();
    });
    initKeyTabs();
    initMask();
    ta.addEventListener("input", parse);
    ["jwtExpIss", "jwtExpAud", "jwtExpSub", "jwtSkew"].forEach(function (id) {
      var el = $(id);
      if (el) el.addEventListener("input", parse);
    });
    var verifyBtn = $("jwtVerify");
    if (verifyBtn) verifyBtn.addEventListener("click", verify);
    initEditPanel();
    initVariantPanel();
    initSecretPanel();
    initExportPanel();
    initVaptPanel();
  }

  root.initJwt = initJwt;
})(typeof window !== "undefined" ? window : (typeof globalThis !== "undefined" ? globalThis : this));
