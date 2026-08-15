/* ==========================================================================
   CyberBuddy — JWT Security Workbench controller (JWT-01 + JWT-02)

   Functional: Analyze & Verify (decode, inspect, verify via Web Crypto) and
   Edit & Generate (edit header/payload, semantic diff, HMAC/private-key
   signing, local RSA test-key generation, TEST TOKEN output with safe
   copy/download). Previews (non-interactive): Test Variants and Secret Test
   (JWT-03). The pure engine lives in js/jwt.engine.js (DOM-free, also
   exercised under Node in test_engines.py). All crypto — including private
   key import/export and test-key generation — lives in the engine; this
   controller only binds DOM.

   Privacy guarantees baked in here:
     - no fetch/XMLHttpRequest/sendBeacon; connect-src is 'self' only;
     - no localStorage/sessionStorage/history/URL writing;
     - tokens and keys live in memory only and are never persisted;
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
      refreshEditDiff();
      return;
    }
    var res = J.tryParseToken(raw);
    if (!res.ok) {
      showError(res.error);
      $("jwtDecodeEmpty").classList.remove("hidden");
      $("jwtDecoded").classList.add("hidden");
      lastParsed = null;
      refreshEditDiff();
      return;
    }
    showError(null);
    showDecoded();
    var parsed = res.token;
    lastParsed = parsed;
    $("jwtHeader").textContent = prettyJson(parsed.header);
    $("jwtPayload").textContent = prettyJson(parsed.payload);
    renderClaims(parsed.payload, parsed);
    renderObservations(J.observations(parsed));
    setDecodedState("Decoded", "jwt-state-decoded");
    refreshEditDiff();

    // Reflect the token alg in the optional pin label.
    var pinLabel = $("jwtPinAlgLabel");
    if (pinLabel) pinLabel.textContent = parsed.header.alg;

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
    if ($("jwtPinAlg").checked) opts.alg = lastParsed.header.alg;

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
    if (btn) { btn.disabled = false; btn.textContent = "Verify signature & claims"; }
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

  function setClipboard(text, okMsg, failMsg) {
    var status = $("jwtCopyStatus");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () {
        if (status) status.textContent = okMsg;
      }, function () {
        if (status) status.textContent = failMsg;
      });
    }
    if (status) status.textContent = failMsg;
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
    // Preview-panel controls are intentionally not wired: JWT-03.
  }

  root.initJwt = initJwt;
})(typeof window !== "undefined" ? window : (typeof globalThis !== "undefined" ? globalThis : this));
