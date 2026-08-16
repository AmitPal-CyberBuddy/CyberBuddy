/* ==========================================================================
   CyberBuddy — CSRF PoC Generator (local-only page controller + pure engine)

   The user pastes a raw Burp HTTP request. Everything happens in the browser:
     - the request is parsed locally,
     - a standalone HTML PoC is generated locally,
     - nothing is sent, stored, cached, relayed, or written into the URL,
     - the PoC is never executed inside CyberBuddy (it is shown as inert text
       and only ever downloaded/copied).

   The pure functions below are deliberately free of `document`/`window` so
   they can be exercised under Node (see test_engines.py's CsrfParserTests).

   Honesty rules baked in here:
     - a PoC is a reproduction of request MECHANICS, never a vulnerability
       verdict, and never a numeric score;
     - Cookie / Authorization / Host / Content-Length / Origin / Referer
       values are never echoed into generated HTML;
     - request values are only ever emitted through an HTML-escaping helper
       or a JSON.stringify-based JS string literal — never by concatenating
       raw text into executable JavaScript.
   ========================================================================== */
"use strict";

(function (root) {
  var FORBIDDEN_ECHO = {
    cookie: 1, authorization: 1, "proxy-authorization": 1,
    host: 1, "content-length": 1, origin: 1, referer: 1,
    "transfer-encoding": 1, connection: 1, "keep-alive": 1,
    "x-forwarded-for": 1, "x-forwarded-host": 1, "x-forwarded-proto": 1,
    "x-real-ip": 1
  };

  var SAFELISTED_CONTENT_TYPES = {
    "application/x-www-form-urlencoded": 1,
    "multipart/form-data": 1,
    "text/plain": 1
  };

  function escHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* A JS string literal that round-trips the exact bytes of `value` and can
     never terminate its <script> element: JSON.stringify escapes quotes,
     backslashes and newlines, and we additionally escape every `<` so a
     pasted `</script>` cannot close the block. */
  function jsLiteral(value) {
    return JSON.stringify(String(value == null ? "" : value))
      .replace(/</g, "\\u003c")
      .replace(/\u2028/g, "\\u2028")
      .replace(/\u2029/g, "\\u2029");
  }

  function truncate(value, max) {
    value = String(value == null ? "" : value);
    return value.length > max ? value.slice(0, max - 1) + "\u2026" : value;
  }

  function normalizeLines(text) {
    return String(text == null ? "" : text).replace(/\r\n?/g, "\n");
  }

  function hval(headers, name) {
    var v = headers[name];
    if (v == null) return "";
    return Array.isArray(v) ? v.join(", ") : String(v);
  }

  function decodePart(value, plusAsSpace) {
    var raw = String(value == null ? "" : value);
    var work = plusAsSpace ? raw.replace(/\+/g, " ") : raw;
    try {
      return decodeURIComponent(work);
    } catch (_) {
      return raw;
    }
  }

  function parsePairs(text, plusAsSpace) {
    var out = [];
    String(text || "").split("&").forEach(function (pair) {
      var eq = pair.indexOf("=");
      var name, value;
      if (eq === -1) { name = pair; value = ""; }
      else { name = pair.slice(0, eq); value = pair.slice(eq + 1); }
      out.push({
        name: decodePart(name, plusAsSpace),
        value: decodePart(value, plusAsSpace),
        raw: pair,
        index: out.length
      });
    });
    return out;
  }

  function looksLikeToken(name) {
    var n = String(name == null ? "" : name).toLowerCase();
    if (!n) return false;
    if (/csrf|xsrf|nonce|authenticity|requestverification|antiforgery|anti-forgery/.test(n)) return true;
    if (n === "token" || n.indexOf("_token") === 0) return true;
    var t = n.indexOf("token");
    return t !== -1 && t === n.length - 5;
  }

  function splitTarget(target) {
    var schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(target);
    if (!schemeMatch) return null;
    var scheme = schemeMatch[1].toLowerCase();
    var rest = target.slice(schemeMatch[0].length);
    var slash = rest.search(/[/?#]/);
    var authority = slash === -1 ? rest : rest.slice(0, slash);
    var pathQuery = slash === -1 ? "/" : rest.slice(slash);
    var at = authority.lastIndexOf("@");
    if (at !== -1) authority = authority.slice(at + 1);
    var host = authority, port = "";
    if (authority.charAt(0) === "[") {
      var close = authority.indexOf("]");
      if (close !== -1) {
        host = authority.slice(1, close);
        var after = authority.slice(close + 1);
        if (after.charAt(0) === ":") port = after.slice(1);
      }
    } else {
      var colon = authority.lastIndexOf(":");
      if (colon !== -1 && authority.indexOf(":") === colon) {
        host = authority.slice(0, colon);
        port = authority.slice(colon + 1);
      }
    }
    var q = pathQuery.indexOf("?");
    var path = q === -1 ? pathQuery : pathQuery.slice(0, q);
    var query = q === -1 ? "" : pathQuery.slice(q + 1);
    if (!path) path = "/";
    return { scheme: scheme, host: host, port: port, path: path, query: query, absolute: true };
  }

  function splitHostHeader(value) {
    var v = String(value == null ? "" : value).trim();
    var host = v, port = "";
    if (v.charAt(0) === "[") {
      var close = v.indexOf("]");
      if (close !== -1) {
        host = v.slice(1, close);
        var after = v.slice(close + 1);
        if (after.charAt(0) === ":") port = after.slice(1);
      }
    } else {
      var colon = v.lastIndexOf(":");
      if (colon !== -1 && v.indexOf(":") === colon) {
        host = v.slice(0, colon);
        port = v.slice(colon + 1);
      }
    }
    return { host: host, port: port };
  }

  function looksLocal(host) {
    return /^(localhost|127\.(\d{1,3}\.){3}\d{1,3}|::1|0\.0\.0\.0)$/i.test(String(host || ""));
  }

  function parseMultipart(body, boundary) {
    var out = { params: [], error: "" };
    if (!boundary) {
      out.error = "multipart/form-data requires a boundary parameter.";
      return out;
    }
    var parts = String(body || "").split("--" + boundary);
    for (var p = 1; p < parts.length - 1; p++) {
      var chunk = parts[p].replace(/^\r?\n/, "").replace(/\r?\n$/, "");
      var headerEnd = chunk.search(/\r?\n\r?\n/);
      var head = headerEnd === -1 ? chunk : chunk.slice(0, headerEnd);
      var val = headerEnd === -1 ? "" : chunk.slice(headerEnd).replace(/^\r?\n\r?\n/, "").replace(/\r?\n$/, "");
      var name = "", filename = "";
      var cd = /content-disposition\s*:\s*form-data\s*;?([\s\S]*)/i.exec(head);
      if (cd) {
        var params = cd[1] || "";
        var nm = /(?:^|;)\s*name\s*=\s*"([^"]*)"/i.exec(params) || /(?:^|;)\s*name\s*=\s*([^;]+)/i.exec(params);
        var fn = /(?:^|;)\s*filename\s*=\s*"([^"]*)"/i.exec(params) || /(?:^|;)\s*filename\s*=\s*([^;]+)/i.exec(params);
        name = nm ? nm[1].trim() : "";
        filename = fn ? fn[1].trim() : "";
      }
      out.params.push({
        name: name, value: val, file: !!filename, filename: filename, raw: "",
        index: out.params.length
      });
    }
    return out;
  }

  /* ------------------------------------------------------------------------
     parseRequest(text) -> structured request (see the return object).
     A result is `ok:false` with `errors` for malformed input.
     ---------------------------------------------------------------------- */
  function parseRequest(raw) {
    var text = normalizeLines(raw);
    var lines = text.split("\n");
    var errors = [];
    var warnings = [];
    var fatal = false;
    var i = 0;
    while (i < lines.length && lines[i].trim() === "") i++;
    var requestLine = (lines[i] || "").trim();
    i++;

    if (!requestLine) {
      return { ok: false, errors: [{ code: "empty", message: "Paste a raw HTTP request to begin (e.g. copy it from Burp Repeater)." }] };
    }

    var rl = /^([A-Za-z]+)[ \t]+(\S+)(?:[ \t]+(HTTP\/\d+(?:\.\d+)?))?[ \t]*$/.exec(requestLine);
    if (!rl) {
      return { ok: false, errors: [{ code: "request-line", message: "The first line must be a request line such as `POST /profile HTTP/1.1`." }] };
    }
    var method = rl[1].toUpperCase();
    var target = rl[2];

    var headers = {};
    var headerOrder = [];
    function appendHeader(name, value) {
      var k = name.toLowerCase();
      if (headers[k] == null) headers[k] = value;
      else if (Array.isArray(headers[k])) headers[k].push(value);
      else headers[k] = [headers[k], value];
    }

    while (i < lines.length) {
      var line = lines[i];
      if (line.trim() === "") { i++; break; }
      var m = /^([^:]+):[ \t]*(.*)$/.exec(line);
      if (!m) {
        if (headerOrder.length && /^[ \t]/.test(line)) {
          appendHeader(headerOrder[headerOrder.length - 1], " " + line.trim());
        } else {
          errors.push({ code: "header", message: "Malformed header line: " + truncate(line, 70) });
        }
        i++;
        continue;
      }
      var name = m[1].trim();
      if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) {
        errors.push({ code: "header", message: "Malformed header name: " + truncate(name, 60) });
        i++;
        continue;
      }
      appendHeader(name, m[2]);
      if (headerOrder.indexOf(name.toLowerCase()) === -1) headerOrder.push(name.toLowerCase());
      i++;
    }

    var body = lines.slice(i).join("\n");

    // --- Resolve the request URL (absolute-form or origin-form + Host). ---
    var absolute = splitTarget(target);
    var scheme, host, port, path, query;
    if (absolute) {
      scheme = absolute.scheme;
      host = absolute.host;
      port = absolute.port;
      path = absolute.path;
      query = absolute.query;
      if (!host) { errors.push({ code: "host", message: "The absolute request URL is missing a host." }); fatal = true; }
    } else {
      var hostHeader = hval(headers, "host");
      var sh = splitHostHeader(hostHeader);
      host = sh.host;
      port = sh.port;
      if (!host) {
        errors.push({ code: "host", message: "No Host header and the request target is not an absolute URL. Add a Host header." });
        fatal = true;
        scheme = "https"; path = target; query = "";
      } else {
        var pathQuery = target;
        if (pathQuery.charAt(0) !== "/" && pathQuery.charAt(0) !== "*") pathQuery = "/" + pathQuery;
        if (pathQuery === "*") pathQuery = "/";
        var q = pathQuery.indexOf("?");
        path = q === -1 ? pathQuery : pathQuery.slice(0, q);
        query = q === -1 ? "" : pathQuery.slice(q + 1);
        scheme = looksLocal(host) ? "http" : "https";
      }
    }
    if (scheme !== "http" && scheme !== "https") {
      errors.push({ code: "scheme", message: "Only http:// and https:// requests can be turned into a browser PoC." });
      fatal = true;
      scheme = "https";
    }

    // --- Content-Type ---
    var ctRaw = hval(headers, "content-type");
    var ctParts = ctRaw.split(";");
    var mediaType = (ctParts[0] || "").trim().toLowerCase();
    var ctParams = {};
    ctParts.slice(1).forEach(function (piece) {
      var e = piece.indexOf("=");
      if (e === -1) return;
      var k = piece.slice(0, e).trim().toLowerCase();
      var v = piece.slice(e + 1).trim().replace(/^"|"$/g, "");
      ctParams[k] = v;
    });

    // --- Parameters ---
    var queryParams = parsePairs(query, true);
    var bodyParams = [];
    var textPlainPairs = [];
    var isJson = mediaType === "application/json" || (mediaType !== "" && mediaType.slice(-5) === "+json");
    var jsonRaw = body;

    if (mediaType === "application/x-www-form-urlencoded") {
      bodyParams = parsePairs(body, true);
    } else if (mediaType === "multipart/form-data") {
      var mp = parseMultipart(body, ctParams.boundary);
      if (mp.error) { errors.push({ code: "multipart", message: mp.error }); fatal = true; }
      bodyParams = mp.params;
    } else if (mediaType === "text/plain") {
      var allPairs = true;
      String(body || "").split(/\r?\n/).forEach(function (line, idx, arr) {
        if (idx === arr.length - 1 && line === "") return;
        var eq = line.indexOf("=");
        if (eq <= 0) { allPairs = false; return; }
        textPlainPairs.push({ name: line.slice(0, eq), value: line.slice(eq + 1), raw: line, index: textPlainPairs.length });
      });
      if (!textPlainPairs.length) allPairs = false;
      if (!allPairs) textPlainPairs = [];
    }

    // --- Custom X-* headers (only these may be replayed by fetch). ---
    var customHeaders = [];
    headerOrder.forEach(function (name) {
      if (name.indexOf("x-") !== 0) return;
      if (FORBIDDEN_ECHO[name] || name === "content-type") return;
      customHeaders.push({
        name: name,
        value: hval(headers, name),
        token: looksLikeToken(name.replace(/^x-/, "")),
        uid: "h:" + name,
        index: customHeaders.length
      });
    });

    // --- Token detection across query, body and custom headers. ---
    var tokens = [];
    queryParams.forEach(function (p) {
      if (looksLikeToken(p.name)) {
        p.token = true; p.uid = "q:" + p.index;
        tokens.push({ name: p.name, source: "query", uid: p.uid, index: p.index });
      } else {
        p.token = false; p.uid = "q:" + p.index;
      }
    });
    bodyParams.forEach(function (p) {
      if (!p.file && looksLikeToken(p.name)) {
        p.token = true; p.uid = "b:" + p.index;
        tokens.push({ name: p.name, source: "body", uid: p.uid, index: p.index });
      } else {
        p.token = false; p.uid = "b:" + p.index;
      }
    });
    customHeaders.forEach(function (h) {
      if (h.token) tokens.push({ name: h.name, source: "header", uid: h.uid, index: h.index });
    });

    var hasFileFields = bodyParams.some(function (p) { return p.file; });

    var url = scheme + "://" + host + (port ? ":" + port : "") + path + (query ? "?" + query : "");

    return {
      ok: !fatal,
      errors: errors,
      warnings: warnings,
      method: method,
      target: target,
      url: url,
      scheme: scheme,
      host: host,
      port: port,
      path: path,
      query: query,
      headers: headers,
      contentType: ctRaw,
      mediaType: mediaType,
      body: body,
      queryParams: queryParams,
      bodyParams: bodyParams,
      textPlainPairs: textPlainPairs,
      customHeaders: customHeaders,
      tokens: tokens,
      hasFileFields: hasFileFields,
      isJson: isJson,
      jsonRaw: jsonRaw
    };
  }

  function safeFilename(parsed, variantId) {
    var host = String((parsed && parsed.host) || "target").toLowerCase()
      .replace(/[^a-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "");
    if (!host) host = "target";
    return "csrf-" + String(parsed.method || "req").toLowerCase() + "-" + host +
      (variantId ? "-" + variantId : "") + ".html";
  }

  /* ------------------------------------------------------------------------
     Standalone PoC document. `inner` is the form/script; request values are
     already escaped by the callers. The auto-submit script is fixed text —
     no request value is ever concatenated into it.
     ---------------------------------------------------------------------- */
  function pocDocument(parsed, inner, opts) {
    var auto = !!(opts && opts.autoSubmit);
    var target = (parsed.method || "GET") + " " + (parsed.url || "");
    var head =
      "<!DOCTYPE html>\n" +
      "<html lang=\"en\">\n" +
      "<head>\n" +
      "  <meta charset=\"utf-8\" />\n" +
      "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n" +
      "  <title>CSRF proof of concept \u2014 CyberBuddy</title>\n" +
      "  <style>\n" +
      "    body { font-family: system-ui, sans-serif; margin: 28px; background: #0a0d13; color: #e9eef5; }\n" +
      "    h1 { font-size: 1.15rem; }\n" +
      "    code, .target { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 0.85rem; }\n" +
      "    .target { display: block; margin: 10px 0 18px; padding: 10px 12px; background: #0e121a;\n" +
      "      border: 1px solid #232a36; border-radius: 8px; word-break: break-all; color: #c5ced8; }\n" +
      "    button { font: inherit; padding: 9px 16px; border: 0; border-radius: 8px; background: #3ee0c2;\n" +
      "      color: #04110e; font-weight: 700; cursor: pointer; }\n" +
      "    .note, .foot { color: #96a2b4; font-size: 0.82rem; }\n" +
      "    .foot { margin-top: 22px; border-top: 1px solid #232a36; padding-top: 12px; }\n" +
      "    #status { color: #96a2b4; font-size: 0.82rem; margin-top: 12px; }\n" +
      "  </style>\n" +
      "</head>\n" +
      "<body>\n" +
      "  <h1>CSRF proof of concept (authorized testing only)</h1>\n" +
      "  <p class=\"note\">Reproduces the request mechanics below. This page does not prove the " +
      "target is vulnerable \u2014 the target must also change state, accept the request from a " +
      "cross-site origin, and rely on the victim's ambient credentials.</p>\n" +
      "  <span class=\"target\">" + escHtml(target) + "</span>\n";
    var foot =
      "  <p class=\"foot\">Generated by CyberBuddy \u2014 authorized testing only. Open this file " +
      "from a separate attacker-controlled origin against an authorized test account.</p>\n" +
      "</body>\n" +
      "</html>\n";
    if (auto) {
      return head + inner +
        "  <!-- AUTO-SUBMIT ENABLED: this page sends the request as soon as it opens. -->\n" +
        foot;
    }
    return head + inner + foot;
  }

  function formVariant(parsed, opts, id, label, method, action, enctype, fields, note, kind) {
    var auto = !!(opts && opts.autoSubmit);
    var enc = enctype ? ' enctype="' + escHtml(enctype) + '"' : "";
    var inputs = fields.map(function (f) {
      if (f.type === "file") {
        return '  <label>File \u2014 <code>' + escHtml(f.name) + "</code><br>" +
          '<input type="file" name="' + escHtml(f.name) + '" /></label>';
      }
      return '  <input type="hidden" name="' + escHtml(f.name) + '" value="' + escHtml(f.value) + '" />';
    }).join("\n");
    var manual = auto ? "" :
      '  <p><button type="submit">Send request</button></p>\n';
    var inner =
      '<form id="csrf-form" method="' + method + '" action="' + escHtml(action) + '"' + enc + ">\n" +
      inputs + "\n" + manual +
      "</form>\n" +
      (auto
        ? "<script>document.getElementById(\"csrf-form\").submit();</script>\n"
        : '<p id="status">Click \u201cSend request\u201d to submit the form.</p>\n');
    return {
      id: id,
      label: label,
      kind: kind,
      note: note,
      html: pocDocument(parsed, inner, opts),
      filename: safeFilename(parsed, id)
    };
  }

  function fetchVariant(parsed, opts, id, label, method, headersObj, body, note, kind) {
    var auto = !!(opts && opts.autoSubmit);
    var headerNames = Object.keys(headersObj || {});
    var headerLines = headerNames.map(function (k) {
      return "        " + jsLiteral(k) + ": " + jsLiteral(headersObj[k]);
    }).join(",\n");
    var bodyLine = body == null ? "      body: null" : "      body: " + jsLiteral(body);
    var script =
      "<script>\n" +
      "  window.__send = function () {\n" +
      "    fetch(" + jsLiteral(parsed.url) + ", {\n" +
      "      method: " + jsLiteral(method) + ",\n" +
      "      credentials: \"include\",\n" +
      "      headers: {\n" +
      (headerLines ? headerLines + "\n" : "") +
      "      },\n" +
      bodyLine + "\n" +
      "    }).then(function () {\n" +
      "      document.getElementById(\"status\").textContent = \"Request sent.\";\n" +
      "    }).catch(function () {\n" +
      "      document.getElementById(\"status\").textContent = \"Blocked by the browser (CORS/preflight) \u2014 see the note below.\";\n" +
      "    });\n" +
      "  };\n" +
      "  document.getElementById(\"send\").addEventListener(\"click\", window.__send);\n" +
      "</script>\n";
    var inner =
      '<p><button id="send" type="button">Send request</button></p>\n' +
      script +
      (auto
        ? "<script>document.addEventListener(\"DOMContentLoaded\", function () { window.__send(); });</script>\n"
        : '<p id="status">Click \u201cSend request\u201d to issue the fetch.</p>\n');
    return {
      id: id,
      label: label,
      kind: kind,
      note: note,
      html: pocDocument(parsed, inner, opts),
      filename: safeFilename(parsed, id)
    };
  }

  /* ------------------------------------------------------------------------
     generatePoc(parsed, opts) -> { status, reason, repro, variants, ... }
     opts: { autoSubmit: bool, excluded: Set<uid> }
     Status is derived from browser mechanics only (form vs preflight vs
     nothing), never from a vulnerability judgement.
     ---------------------------------------------------------------------- */
  function generatePoc(parsed, opts) {
    opts = opts || {};
    var auto = !!opts.autoSubmit;
    var excluded = opts.excluded || {};
    var method = parsed.method;
    var variants = [];
    var limitations = [];
    var status = "READY";
    var reason = "";

    var baseUrl = parsed.scheme + "://" + parsed.host + (parsed.port ? ":" + parsed.port : "") + parsed.path;

    var qIncluded = parsed.queryParams.filter(function (p) { return !(p.token && excluded[p.uid]); });
    var bIncluded = parsed.bodyParams.filter(function (p) { return !(p.token && excluded[p.uid]); });
    var bText = bIncluded.filter(function (p) { return !p.file; });
    var bFiles = bIncluded.filter(function (p) { return p.file; });

    var queryString = qIncluded.length ? qIncluded.map(function (p) { return p.raw; }).join("&") : "";
    var urlWithQuery = baseUrl + (queryString ? "?" + queryString : "");

    var activeCustomHeaders = parsed.customHeaders.filter(function (h) { return !excluded[h.uid]; });
    var customHeaderNames = activeCustomHeaders.map(function (h) { return h.name; });
    if (customHeaderNames.length) {
      var manyHeaders = customHeaderNames.length > 1;
      limitations.push("Custom header" + (manyHeaders ? "s " : " ") +
        customHeaderNames.join(", ") +
        (manyHeaders ? " cannot be sent by a plain HTML form; they are" : " cannot be sent by a plain HTML form; it is") +
        " carried only in the fetch variant, and " +
        (manyHeaders ? "their values are" : "its value is") +
        " supplied by the PoC (a server that only checks for " +
        (manyHeaders ? "their" : "its") +
        " presence is not protected).");
    }

    var excludedTokens = parsed.tokens.filter(function (t) { return excluded[t.uid]; });
    var includedTokens = parsed.tokens.filter(function (t) { return !excluded[t.uid]; });
    if (includedTokens.length) {
      var manyIncluded = includedTokens.length > 1;
      limitations.push("Likely CSRF-token field" + (manyIncluded ? "s " : " ") +
        includedTokens.map(function (t) { return t.name; }).join(", ") +
        (manyIncluded ? " are included with their pasted (static) values." : " is included with its pasted (static) value.") +
        " A real per-session token will not match \u2014 treat a failure as expected token validation, not a broken PoC.");
    }
    if (excludedTokens.length) {
      limitations.push("You excluded token field" + (excludedTokens.length > 1 ? "s " : " ") +
        excludedTokens.map(function (t) { return t.name; }).join(", ") +
        ". Excluding a token is only appropriate to verify that the server actually validates it (an authorized check).");
    }
    if (parsed.hasFileFields) {
      limitations.push("File fields cannot be pre-populated: the victim must select the file. That is social engineering on top of CSRF, not a pure CSRF request.");
    }

    function headerTokenObjects() {
      var headers = {};
      if (parsed.contentType) headers["Content-Type"] = parsed.contentType;
      activeCustomHeaders.forEach(function (h) { headers[h.name] = h.value; });
      return headers;
    }

    // --- Not representable by any browser mechanism. ---
    if (["CONNECT", "TRACE", "TRACK"].indexOf(method) !== -1 ||
        ["GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"].indexOf(method) === -1) {
      status = "NOT DIRECTLY REPRESENTABLE";
      reason = method + " cannot be issued by a browser form or fetch() from a cross-site page.";
      limitations.push(reason);
      return finish(parsed, variants, limitations, status, reason, auto);
    }

    if (method === "GET" && parsed.body) {
      status = "NOT DIRECTLY REPRESENTABLE";
      reason = "A GET request cannot carry a request body in any browser mechanism \u2014 the body would be dropped. Only the URL/query can be reproduced.";
      limitations.push(reason);
      variants.push(formVariant(parsed, opts, "get-query",
        "GET form (query only \u2014 body omitted)", "GET", baseUrl, null,
        qIncluded.map(function (p) { return { type: "hidden", name: p.name, value: p.value }; }),
        "The body cannot be sent via GET; this form reproduces only the URL and query string.", "limited"));
      return finish(parsed, variants, limitations, status, reason, auto);
    }

    if (method === "GET") {
      variants.push(formVariant(parsed, opts, "get",
        "GET form", "GET", baseUrl, null,
        qIncluded.map(function (p) { return { type: "hidden", name: p.name, value: p.value }; }),
        "Standard GET form. Query parameters are re-encoded by the browser; verify against the target.", "ready"));
      return finish(parsed, variants, limitations, status, reason, auto);
    }

    if (method === "HEAD") {
      status = "LIMITED";
      reason = "HEAD is rarely state-changing and cannot be sent by a form; it is reproduced via fetch().";
      limitations.push(reason);
      variants.push(fetchVariant(parsed, opts, "head",
        "HEAD via fetch()", "HEAD", {}, null,
        "Sent as a simple request (no preflight), but HEAD is not normally state-changing.", "limited"));
      return finish(parsed, variants, limitations, status, reason, auto);
    }

    if (method === "POST") {
      if (parsed.isJson) {
        status = "LIMITED";
        reason = "application/json cannot be sent by a plain form. The fetch() variant forces a CORS preflight; the text/plain trick only works if the server accepts that type.";
        limitations.push(reason);
        variants.push(fetchVariant(parsed, opts, "json-fetch",
          "JSON via fetch() (application/json)", "POST",
          headerTokenObjects(), parsed.body,
          "Content-Type: application/json is not a CORS-safelisted type, so the browser sends an OPTIONS preflight first. This only works if the target answers the preflight (or has permissive CORS).",
          "limited"));
        var jsonHasEq = parsed.jsonRaw.indexOf("=") !== -1;
        var jsonHasNewline = /[\r\n]/.test(parsed.jsonRaw);
        if (jsonHasEq && !jsonHasNewline && parsed.jsonRaw.length > 0) {
          var eq = parsed.jsonRaw.indexOf("=");
          var nm = parsed.jsonRaw.slice(0, eq);
          var vl = parsed.jsonRaw.slice(eq + 1);
          variants.push(formVariant(parsed, opts, "json-textplain",
            "JSON as text/plain form (alternative)", "POST", urlWithQuery, "text/plain",
            [{ type: "hidden", name: nm, value: vl }],
            "A form with enctype=\"text/plain\" serializes this single field as name=value, which equals the exact JSON body. Only works if the server accepts text/plain (or ignores Content-Type). Browser serialization can vary \u2014 verify the bytes.",
            "limited"));
        } else {
          limitations.push("The JSON body cannot be split into a text/plain name=value pair, so no JSON-as-text/plain alternative is offered.");
        }
        return finish(parsed, variants, limitations, status, reason, auto);
      }

      if (parsed.mediaType === "text/plain") {
        status = "READY";
        reason = "text/plain is CORS-safelisted, so the exact body can be sent as a simple fetch() with no preflight.";
        variants.push(fetchVariant(parsed, opts, "textplain-fetch",
          "text/plain via fetch() (exact body)", "POST",
          headerTokenObjects(), parsed.body,
          "Exact body delivered with Content-Type: text/plain \u2014 a simple request, no preflight. The response is not read back (CORS gates reads, not the request).",
          "ready"));
        if (parsed.textPlainPairs.length) {
          variants.push(formVariant(parsed, opts, "textplain-form",
            "text/plain form (name=value lines)", "POST", urlWithQuery, "text/plain",
            parsed.textPlainPairs.filter(function (p) { return !(excluded["b:" + p.index] || excluded["q:" + p.index]); })
              .map(function (p) { return { type: "hidden", name: p.name, value: p.value }; }),
            "Browsers serialize text/plain forms as name=value lines (CRLF-separated). Use only when the body is exactly that shape; verify the bytes.", "ready"));
        } else {
          limitations.push("The text/plain body is not a sequence of name=value lines, so a form cannot reproduce it; use the fetch variant.");
        }
        return finish(parsed, variants, limitations, status, reason, auto);
      }

      if (parsed.mediaType === "multipart/form-data") {
        if (parsed.hasFileFields) {
          status = "LIMITED";
          reason = "The multipart body contains file fields, whose content cannot be pre-populated \u2014 the victim must select the file.";
          limitations.push(reason);
        } else {
          status = "READY";
        }
        variants.push(formVariant(parsed, opts, "multipart",
          "multipart/form-data form", "POST", urlWithQuery, "multipart/form-data",
          bText.map(function (p) { return { type: "hidden", name: p.name, value: p.value }; })
            .concat(bFiles.map(function (p) { return { type: "file", name: p.name }; })),
          parsed.hasFileFields
            ? "Text fields are hidden inputs; file fields become file pickers the victim must fill in."
            : "Multipart form with all text fields as hidden inputs (a CORS-safelisted, preflight-free request).",
          parsed.hasFileFields ? "limited" : "ready"));
        if (!parsed.hasFileFields && bText.length) {
          variants.push(formVariant(parsed, opts, "urlencoded-alt",
            "URL-encoded form (alternative)", "POST", urlWithQuery, "application/x-www-form-urlencoded",
            bText.map(function (p) { return { type: "hidden", name: p.name, value: p.value }; }),
            "Alternative URL-encoded encoding \u2014 only if the server accepts application/x-www-form-urlencoded.", "limited"));
        }
        return finish(parsed, variants, limitations, status, reason, auto);
      }

      if (parsed.mediaType === "application/x-www-form-urlencoded") {
        status = "READY";
        variants.push(formVariant(parsed, opts, "urlencoded",
          "URL-encoded form", "POST", urlWithQuery, "application/x-www-form-urlencoded",
          bText.map(function (p) { return { type: "hidden", name: p.name, value: p.value }; }),
          "Standard application/x-www-form-urlencoded form \u2014 a simple request, no preflight.", "ready"));
        if (bText.length) {
          variants.push(formVariant(parsed, opts, "multipart-alt",
            "multipart/form-data form (alternative)", "POST", urlWithQuery, "multipart/form-data",
            bText.map(function (p) { return { type: "hidden", name: p.name, value: p.value }; }),
            "Alternative multipart encoding \u2014 only if the server accepts multipart/form-data.", "limited"));
        }
        return finish(parsed, variants, limitations, status, reason, auto);
      }

      // Empty body (POST with query only, or no Content-Type and no body).
      if (!parsed.body) {
        status = "READY";
        variants.push(formVariant(parsed, opts, "post-empty",
          "Empty POST form", "POST", urlWithQuery, null,
          bText.map(function (p) { return { type: "hidden", name: p.name, value: p.value }; }),
          "Reproduces a POST with no request body. Query parameters stay in the action URL.", "ready"));
        return finish(parsed, variants, limitations, status, reason, auto);
      }

      // Unknown / other content type with a body: raw fetch fallback.
      status = "LIMITED";
      reason = "The body's Content-Type cannot be reproduced by a plain form; a fetch() carries the raw body instead.";
      limitations.push(reason);
      var hdrs = {};
      if (parsed.contentType && SAFELISTED_CONTENT_TYPES[parsed.mediaType]) hdrs["Content-Type"] = parsed.contentType;
      activeCustomHeaders.forEach(function (h) { hdrs[h.name] = h.value; });
      variants.push(fetchVariant(parsed, opts, "raw-fetch",
        "Raw body via fetch()", "POST", hdrs, parsed.body,
        "The raw body is sent unchanged. If no Content-Type is set the browser adds text/plain; the server may reject the altered Content-Type.", "limited"));
      return finish(parsed, variants, limitations, status, reason, auto);
    }

    // PUT / PATCH / DELETE / OPTIONS — fetch only, preflight required.
    status = "LIMITED";
    reason = method + " cannot be sent by a plain HTML form. The fetch() variant forces a CORS preflight (the method is not CORS-safelisted).";
    limitations.push(reason);
    var putHeaders = {};
    if (parsed.body && parsed.contentType) putHeaders["Content-Type"] = parsed.contentType;
    activeCustomHeaders.forEach(function (h) { putHeaders[h.name] = h.value; });
    variants.push(fetchVariant(parsed, opts, method.toLowerCase(),
      method + " via fetch()", method, putHeaders,
      parsed.body || null,
      "Non-safelisted method \u2014 the browser sends an OPTIONS preflight before the real request, and it is only sent if the target answers that preflight.",
      "limited"));
    return finish(parsed, variants, limitations, status, reason, auto);
  }

  function finish(parsed, variants, limitations, status, reason, auto) {
    if (!variants.length) {
      status = "NOT DIRECTLY REPRESENTABLE";
      reason = reason || "No browser mechanism can reproduce this request.";
      limitations.push(reason);
    }
    return {
      status: status,
      reason: reason,
      repro: reproLabel(status),
      method: parsed.method,
      url: parsed.url,
      contentType: parsed.contentType,
      mediaType: parsed.mediaType,
      variants: variants,
      limitations: limitations,
      params: {
        query: parsed.queryParams.length,
        body: parsed.bodyParams.length,
        file: parsed.bodyParams.filter(function (p) { return p.file; }).length
      },
      tokens: parsed.tokens,
      hasFileFields: parsed.hasFileFields,
      autoSubmit: !!auto
    };
  }

  function reproLabel(status) {
    if (status === "READY") return "simple request \u00b7 no preflight";
    if (status === "LIMITED") return "CORS preflight or server leniency required";
    return "no browser mechanism reproduces this";
  }

  /* ------------------------------------------------------------------------
     Recommendations, tailored to the parsed request (never a verdict).
     ---------------------------------------------------------------------- */
  function buildRecommendations(parsed) {
    var recs = [];
    recs.push("Require an unpredictable, per-session CSRF token on every state-changing request and validate it server-side before acting.");
    recs.push("Validate the Origin and/or Referer header on state-changing requests, and treat a missing Origin as suspicious for non-GET requests.");
    recs.push("Set cookies with SameSite=Lax (or Strict where possible) so ambient cookies are not attached to most cross-site requests.");
    recs.push("Never let GET perform a state change; use POST/PUT/PATCH/DELETE for mutations.");
    recs.push("Use your framework's built-in CSRF protection (Django, Rails protect_from_forgery, Spring Security, Express csurf, Laravel VerifyCsrfToken, ASP.NET antiforgery) rather than hand-rolling it.");
    recs.push("Require re-authentication or step-up verification for high-value state changes.");
    recs.push("Enforce a strict allowlist of Content-Type and methods; do not accept text/plain in place of application/json or urlencoded.");
    if (parsed.tokens.length) {
      recs.push("This request carries a likely CSRF-token field (" +
        parsed.tokens.map(function (t) { return t.name; }).join(", ") +
        "). Confirm the server actually validates it \u2014 a field present in the request does not mean the server rejects a wrong value.");
    }
    if (parsed.method === "GET") {
      recs.push("This is a GET request. If the endpoint changes state, move it to a non-GET method \u2014 that is the root cause to fix.");
    }
    if (parsed.isJson) {
      recs.push("For JSON endpoints, require a custom header or API token and reject requests whose Content-Type is not application/json. A CORS preflight alone is not CSRF protection.");
    }
    if (parsed.hasFileFields) {
      recs.push("File-upload endpoints should require a valid CSRF token; requiring the victim to pick a file adds friction but is not itself a control.");
    }
    if (parsed.mediaType === "text/plain") {
      recs.push("Reject text/plain bodies for endpoints that expect form- or JSON-encoded data.");
    }
    if (parsed.customHeaders.length) {
      recs.push("Do not rely on client-settable headers (" +
        parsed.customHeaders.map(function (h) { return h.name; }).join(", ") +
        ") as CSRF protection \u2014 a cross-site page can send them via fetch() (with a preflight).");
    }
    return recs;
  }

  /* ------------------------------------------------------------------------
     Markdown assessment (names only \u2014 never the pasted parameter values,
     so no secret is copied into a report by accident).
     ---------------------------------------------------------------------- */
  function buildMarkdown(parsed, gen) {
    var q = parsed.queryParams.map(function (p) { return p.name; });
    var b = parsed.bodyParams.map(function (p) { return p.file ? p.name + " (file: " + p.filename + ")" : p.name; });
    var lines = [];
    lines.push("# CyberBuddy \u2014 CSRF PoC Generator");
    lines.push("");
    lines.push("- **Method:** " + parsed.method);
    lines.push("- **URL:** " + parsed.url);
    lines.push("- **Query parameters:** " + (q.length ? q.length + " (" + q.join(", ") + ")" : "none"));
    lines.push("- **Body parameters:** " + (b.length ? b.length + " (" + b.join(", ") + ")" : "none"));
    lines.push("- **Content-Type:** " + (parsed.contentType || "(none)"));
    lines.push("- **Mechanism status:** " + gen.status);
    lines.push("- **Reproducibility:** " + gen.repro);
    if (gen.tokens.length) {
      lines.push("- **Likely CSRF-token fields:** " + gen.tokens.map(function (t) { return t.name; }).join(", "));
    }
    lines.push("");
    lines.push("## Variants generated");
    gen.variants.forEach(function (v) {
      lines.push("- **" + v.label + "** (" + v.kind.toUpperCase() + "): " + v.note);
    });
    lines.push("");
    lines.push("## Reproducibility limitations");
    gen.limitations.forEach(function (l) { lines.push("- " + l); });
    lines.push("");
    lines.push("## Prerequisites for a successful test");
    lines.push("- The endpoint must actually change state when it receives this request.");
    lines.push("- The victim must be logged in with ambient credentials (cookies) that the request reuses.");
    lines.push("- The target must not fully reject the request via CSRF tokens, SameSite cookies, or Origin/Referer validation.");
    lines.push("- For preflighted variants, the target must answer the CORS preflight.");
    lines.push("- For sensitive flows, the target must not require re-authentication the victim cannot supply.");
    lines.push("");
    lines.push("## How to test");
    lines.push("1. Use a dedicated, authorized test account you are permitted to mutate.");
    lines.push("2. Host the downloaded PoC on a separate origin from the target (a different domain or a localhost server).");
    lines.push("3. Open the PoC in a browser where the test account is logged in.");
    lines.push("4. Confirm whether the state change actually occurred; if it did not, check which control blocked it.");
    lines.push("5. Never test against other users or production accounts.");
    lines.push("");
    lines.push("## Recommendations");
    buildRecommendations(parsed).forEach(function (r) { lines.push("- " + r); });
    lines.push("");
    lines.push("## References");
    lines.push("- OWASP WSTG-SESS-05 \u2014 Testing for Cross Site Request Forgery");
    lines.push("- CWE-352 \u2014 Cross-Site Request Forgery (CSRF)");
    lines.push("");
    lines.push("---");
    lines.push("Generated with CyberBuddy \u2014 authorized testing only. A generated PoC proves request mechanics, not that the target is vulnerable.");
    return lines.join("\n");
  }

  var NS = {
    parseRequest: parseRequest,
    generatePoc: generatePoc,
    buildRecommendations: buildRecommendations,
    buildMarkdown: buildMarkdown,
    escHtml: escHtml,
    jsLiteral: jsLiteral,
    safeFilename: safeFilename,
    looksLikeToken: looksLikeToken
  };

  root.CyberBuddyCsrf = NS;

  /* ------------------------------------------------------------------------
     Page controller (browser only). Exposed as window.initCsrf and wired by
     <body data-init="initCsrf">.
     ---------------------------------------------------------------------- */
  NS.initCsrf = function initCsrf() {
    function $(id) { return document.getElementById(id); }

    var lastParsed = null;
    var lastGen = null;
    var selectedVariant = "";

    function clearError() {
      var err = $("requestError");
      if (err) { err.textContent = ""; err.classList.add("hidden"); }
      var input = $("request");
      if (input) input.removeAttribute("aria-invalid");
    }

    function showError(message) {
      var err = $("requestError");
      if (err) { err.textContent = message; err.classList.remove("hidden"); }
      var input = $("request");
      if (input) input.setAttribute("aria-invalid", "true");
    }

    function syncWarn() {
      var auto = $("autoSubmit");
      var warn = $("autoSubmitWarn");
      if (auto && warn) {
        warn.classList.toggle("hidden", !auto.checked);
      }
    }

    function tokenState() {
      var excluded = {};
      if (!lastParsed) return excluded;
      lastParsed.tokens.forEach(function (t) {
        var el = document.querySelector('[data-token-uid="' + t.uid + '"]');
        if (el && !el.checked) excluded[t.uid] = true;
      });
      return excluded;
    }

    function renderTokens(parsed) {
      var panel = $("tokensPanel");
      var list = $("tokenList");
      if (!panel || !list) return;
      if (!parsed.tokens.length) {
        panel.classList.add("hidden");
        list.innerHTML = "";
        return;
      }
      panel.classList.remove("hidden");
      list.innerHTML = parsed.tokens.map(function (t) {
        return '<label class="csrf-token-item" for="tok-' + t.uid.replace(/[^a-z0-9-]/g, "") + '">' +
          '<input type="checkbox" id="tok-' + t.uid.replace(/[^a-z0-9-]/g, "") + '" data-token-uid="' + escHtml(t.uid) + '" checked />' +
          "<code>" + escHtml(t.name) + "</code>" +
          '<span class="csrf-token-src">' + escHtml(t.source) + "</span></label>";
      }).join("");
      list.querySelectorAll("input[type=checkbox]").forEach(function (el) {
        el.addEventListener("change", function () { regenerate(); });
      });
    }

    function renderVariants(gen) {
      var wrap = $("variants");
      if (!wrap) return;
      wrap.innerHTML = gen.variants.map(function (v, i) {
        var checked = selectedVariant === v.id || (i === 0 && !selectedVariant) ? " checked" : "";
        return '<label class="csrf-variant">' +
          '<input type="radio" name="csrfVariant" value="' + escHtml(v.id) + '"' + checked + " />" +
          '<span class="csrf-variant-main"><strong>' + escHtml(v.label) + "</strong>" +
          '<span class="csrf-variant-kind ' + v.kind + '">' + v.kind.toUpperCase() + "</span></span>" +
          '<span class="csrf-variant-note">' + escHtml(v.note) + "</span>" +
          "</label>";
      }).join("");
      if (gen.variants.length) {
        selectedVariant = gen.variants[0].id;
      }
      wrap.querySelectorAll('input[name="csrfVariant"]').forEach(function (el) {
        if (el.checked) selectedVariant = el.value;
        el.addEventListener("change", function () {
          selectedVariant = el.value;
          renderPreview(gen);
        });
      });
    }

    function currentVariant(gen) {
      var found = null;
      gen.variants.forEach(function (v) { if (v.id === selectedVariant) found = v; });
      return found || gen.variants[0];
    }

    function renderPreview(gen) {
      var pre = $("pocSource");
      var v = currentVariant(gen);
      if (pre && v) pre.textContent = v.html;
    }

    function render(parsed, gen) {
      $("results").classList.remove("hidden");
      /* Reproducibility, NOT risk. This tool reports whether browser mechanics
         can carry the request; it never judges the target. Using the risk
         palette here would read backwards (a working PoC is the strongest
         claim, yet "low risk" is green), so it has its own neutral ramp. */
      var repro = gen.status === "READY" ? "repro-ready"
        : gen.status === "LIMITED" ? "repro-limited" : "repro-none";
      var verdict = $("verdict");
      verdict.textContent = gen.status;
      verdict.className = "risk " + repro;
      /* Match the scanners' verdict-transition animation (re-triggered by
         forcing a reflow, otherwise re-adding the class is a no-op). */
      verdict.classList.remove("bump");
      void verdict.offsetWidth;
      verdict.classList.add("bump");
      var banner = $("verdictBanner");
      if (banner) banner.className = "verdict-banner " + repro;

      var prot = $("protection");
      if (prot) {
        prot.textContent = gen.status === "READY" ? "READY \u2014 reproduced as a simple browser request (no preflight)."
          : gen.status === "LIMITED" ? "LIMITED \u2014 reproduced but depends on a CORS preflight or server leniency."
          : "NOT DIRECTLY REPRESENTABLE \u2014 no browser mechanism can reproduce this request.";
        prot.className = "protection-line " + repro;
      }
      /* READY carries no `reason` (there is no caveat to report), so state the
         positive outcome rather than leaving the line blank on the happy path. */
      var summary = $("summary");
      if (summary) {
        summary.textContent = gen.reason
          || "A plain HTML form reproduces this request cross-origin, so the browser will send it with the user's cookies. Whether the server accepts it is what your authorized test confirms.";
      }

      $("mMethod").textContent = parsed.method;
      $("mUrl").textContent = parsed.url;
      $("mContentType").textContent = parsed.contentType || "(none)";
      $("mRepro").textContent = gen.repro;
      $("mParams").textContent = gen.params.query + " query \u00b7 " + gen.params.body + " body" +
        (gen.params.file ? " \u00b7 " + gen.params.file + " file" : "");
      $("mTokens").textContent = parsed.tokens.length ? String(parsed.tokens.length) : "\u2014";

      var rec = $("recommendations");
      if (rec) {
        rec.innerHTML = buildRecommendations(parsed).map(function (r) { return "<li>" + escHtml(r) + "</li>"; }).join("");
      }

      var prov = $("reportProvenance");
      if (prov) {
        prov.innerHTML =
          '<span class="prov-brand">CyberBuddy \u00b7 CSRF PoC Generator</span>' +
          '<span class="prov-sep">|</span>' +
          "<span>" + escHtml(parsed.url) + "</span>" +
          '<span class="prov-sep">|</span>' +
          "<span>" + escHtml(fmtStampUtc()) + "</span>" +
          '<span class="prov-sep">|</span>' +
          "<span>generated locally \u2014 nothing transmitted</span>";
      }

      renderTokens(parsed);
      renderVariants(gen);
      renderPreview(gen);

      ["download", "copyHtml", "copyMd"].forEach(function (id) {
        var btn = $(id);
        if (btn) btn.disabled = false;
      });
    }

    function regenerate() {
      if (!lastParsed) return;
      var gen = generatePoc(lastParsed, {
        autoSubmit: $("autoSubmit").checked,
        excluded: tokenState()
      });
      lastGen = gen;
      render(lastParsed, gen);
    }

    function generate() {
      clearError();
      var parsed = parseRequest($("request").value);
      if (!parsed.ok) {
        showError(parsed.errors.length ? parsed.errors[0].message : "Could not parse this request.");
        $("results").classList.add("hidden");
        return;
      }
      if (parsed.errors.length) {
        // Non-fatal parse issues still warn the analyst.
        showError(parsed.errors[0].message);
      }
      lastParsed = parsed;
      selectedVariant = "";
      var gen = generatePoc(parsed, { autoSubmit: $("autoSubmit").checked, excluded: {} });
      lastGen = gen;
      render(parsed, gen);
    }

    function download() {
      var v = lastGen && currentVariant(lastGen);
      if (!v) return;
      downloadBlob(new Blob([v.html], { type: "text/html" }), v.filename);
    }

    $("generate").addEventListener("click", generate);
    $("request").addEventListener("input", clearError);
    $("autoSubmit").addEventListener("change", function () {
      syncWarn();
      regenerate();
    });
    $("download").addEventListener("click", download);
    $("copyHtml").addEventListener("click", function () {
      var v = lastGen && currentVariant(lastGen);
      if (!v) return;
      copyText(v.html).then(function (ok) {
        flashBtn($("copyHtml"), ok, "HTML copied \u2713");
      });
    });
    $("copyMd").addEventListener("click", function () {
      if (!lastParsed || !lastGen) return;
      copyText(buildMarkdown(lastParsed, lastGen)).then(function (ok) {
        flashBtn($("copyMd"), ok, "Markdown copied \u2713");
      });
    });
    $("clear").addEventListener("click", function () {
      $("request").value = "";
      clearError();
      $("results").classList.add("hidden");
      lastParsed = null;
      lastGen = null;
      selectedVariant = "";
      ["download", "copyHtml", "copyMd"].forEach(function (id) { $(id).disabled = true; });
    });

    syncWarn();
    ["download", "copyHtml", "copyMd"].forEach(function (id) { $(id).disabled = true; });
  };

  root.initCsrf = NS.initCsrf;
})(typeof window !== "undefined" ? window : (typeof globalThis !== "undefined" ? globalThis : this));
