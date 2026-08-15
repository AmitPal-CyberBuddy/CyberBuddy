/* ==========================================================================
   CyberBuddy — JWT Security Workbench controller (JWT-01)

   Functional: Analyze & Verify (decode, inspect, verify via Web Crypto).
   Previews (non-interactive): Edit & Generate (JWT-02), Test Variants and
   Secret Test (JWT-03). The pure decode/verify engine lives in
   js/jwt.engine.js (DOM-free, also exercised under Node in test_engines.py).

   Privacy guarantees baked in here:
     - no fetch/XMLHttpRequest/sendBeacon; connect-src is 'self' only;
     - no localStorage/sessionStorage/history/URL writing;
     - the token is parsed in memory and never persisted;
     - only the key the analyst supplies is used to verify.
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
      return;
    }
    var res = J.tryParseToken(raw);
    if (!res.ok) {
      showError(res.error);
      $("jwtDecodeEmpty").classList.remove("hidden");
      $("jwtDecoded").classList.add("hidden");
      lastParsed = null;
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
    var active = document.querySelector(".jwt-key-tab.is-active");
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
  function initTabs() {
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

  // --- Key-type sub-tabs ---------------------------------------------
  function initKeyTabs() {
    var tabs = Array.prototype.slice.call(document.querySelectorAll(".jwt-key-tab"));
    var panels = Array.prototype.slice.call(document.querySelectorAll(".jwt-key-panel"));
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        tabs.forEach(function (t) {
          var on = t === tab;
          t.classList.toggle("is-active", on);
          t.setAttribute("aria-selected", on ? "true" : "false");
        });
        var which = tab.getAttribute("data-keytype");
        panels.forEach(function (p) {
          var on = p.id === "jwt-key-" + which;
          p.classList.toggle("hidden", !on);
          if (on) p.removeAttribute("hidden"); else p.setAttribute("hidden", "");
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

  function initJwt() {
    var ta = $("jwtToken");
    if (!ta) return;
    initTabs();
    initKeyTabs();
    initMask();
    ta.addEventListener("input", parse);
    ["jwtExpIss", "jwtExpAud", "jwtExpSub", "jwtSkew"].forEach(function (id) {
      var el = $(id);
      if (el) el.addEventListener("input", parse);
    });
    var verifyBtn = $("jwtVerify");
    if (verifyBtn) verifyBtn.addEventListener("click", verify);
    // Preview-panel controls are intentionally not wired: JWT-02/03.
  }

  root.initJwt = initJwt;
})(typeof window !== "undefined" ? window : (typeof globalThis !== "undefined" ? globalThis : this));
