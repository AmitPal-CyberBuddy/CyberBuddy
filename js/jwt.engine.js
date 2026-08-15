/* ==========================================================================
   CyberBuddy — JWT engine: decode, inspect and verify (JWT-01)

   Pure, DOM-free functions shared by the browser controller and the Node
   unit tests in test_engines.py. Nothing here touches the network, storage
   or history. Cryptography uses the standard Web Crypto API
   (globalThis.crypto.subtle), available in all modern browsers and Node 22+.

   JWT-01 scope (strict):
     - compact JWS decoding (header/payload/signature); JWE is rejected;
     - signature verification for HS256/384/512, RS256/384/512,
       PS256/384/512, ES256/384 via a key the ANALYST supplies;
     - expected-value validation for iss/aud/sub plus exp/nbf with skew;
     - contextual observations (never a numeric score or verdict).
   JWT-01 explicitly does NOT edit, sign, generate, fetch a JWKS URL, do
   secret testing or touch network/storage. See docs/ROADMAP.md.

   Accuracy rules enforced here:
     - we never trust the token's "alg" header to choose the verifier; the
       caller passes the expected alg (or the key's alg/JWK alg is used and
       matched), and a mismatch fails verification;
     - HMAC algs only accept symmetric (string) keys; RS/PS/ES only accept
       public keys (PEM/JWK/JWKS) — this blocks algorithm-confusion;
     - decoding is reported separately from signature/claim verification.
   ========================================================================== */
"use strict";

(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.CyberBuddyJwt = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {

  function b64urlDecode(str) {
    if (typeof str !== "string") throw new TypeError("base64url: expected string");
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    if (typeof atob === "function") {
      var bin = atob(str);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    }
    if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(str, "base64"));
    throw new Error("No base64 decoder available");
  }

  function b64urlEncode(bytes) {
    var str = "";
    for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    var b64;
    if (typeof btoa === "function") b64 = btoa(str);
    else if (typeof Buffer !== "undefined") b64 = Buffer.from(bytes).toString("base64");
    else throw new Error("No base64 encoder available");
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  var SUPPORTED_ALGS = {
    HS256: { name: "HMAC", hash: "SHA-256", kty: "oct" },
    HS384: { name: "HMAC", hash: "SHA-384", kty: "oct" },
    HS512: { name: "HMAC", hash: "SHA-512", kty: "oct" },
    RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", kty: "RSA" },
    RS384: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384", kty: "RSA" },
    RS512: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512", kty: "RSA" },
    PS256: { name: "RSA-PSS", hash: "SHA-256", kty: "RSA", pss: true },
    PS384: { name: "RSA-PSS", hash: "SHA-384", kty: "RSA", pss: true },
    PS512: { name: "RSA-PSS", hash: "SHA-512", kty: "RSA", pss: true },
    ES256: { name: "ECDSA", hash: "SHA-256", kty: "EC", namedCurve: "P-256" },
    ES384: { name: "ECDSA", hash: "SHA-384", kty: "EC", namedCurve: "P-384" }
  };

  function algSpec(alg) {
    return alg && Object.prototype.hasOwnProperty.call(SUPPORTED_ALGS, alg)
      ? SUPPORTED_ALGS[alg] : null;
  }

  /* Parse the compact JWS structure without any key or verification.
     Returns {raw, header, payload, signature, signingInput} or throws. */
  function parseToken(raw) {
    if (typeof raw !== "string") throw new Error("Token must be a string");
    var s = raw.trim();
    if (!s) throw new Error("Empty token");
    if (s.split(".").length === 5) {
      throw new Error("JWE (encrypted) tokens are not supported in JWT-01");
    }
    var parts = s.split(".");
    if (parts.length !== 3) {
      throw new Error("A compact JWS must have three dot-separated parts");
    }
    var headerBytes, payloadBytes;
    try { headerBytes = b64urlDecode(parts[0]); }
    catch (e) { throw new Error("Header is not valid base64url"); }
    try { payloadBytes = b64urlDecode(parts[1]); }
    catch (e) { throw new Error("Payload is not valid base64url"); }
    var header, payload;
    try { header = JSON.parse(new TextDecoder().decode(headerBytes)); }
    catch (e) { throw new Error("Header is not valid JSON"); }
    try { payload = JSON.parse(new TextDecoder().decode(payloadBytes)); }
    catch (e) { throw new Error("Payload is not valid JSON"); }
    if (!header || typeof header !== "object") throw new Error("Header is not a JSON object");
    if (!payload || typeof payload !== "object") throw new Error("Payload is not a JSON object");
    var alg = header.alg;
    if (!alg) throw new Error("Header has no alg");
    if (!algSpec(alg)) throw new Error("Unsupported alg: " + alg);
    if (!parts[2]) throw new Error("Token has no signature");
    var sig;
    try { sig = b64urlDecode(parts[2]); }
    catch (e) { throw new Error("Signature is not valid base64url"); }
    if (!sig.length) throw new Error("Token has an empty signature");
    if (header.alg === "none") throw new Error("alg:none is unsigned and cannot be verified");
    return {
      raw: s,
      header: header,
      payload: payload,
      signature: sig,
      signingInput: parts[0] + "." + parts[1]
    };
  }

  function tryParseToken(raw) {
    try { return { ok: true, token: parseToken(raw) }; }
    catch (e) { return { ok: false, error: e.message }; }
  }

  /* Contextual observations. These are advisory flags, not findings or a
     score. They only describe the decoded token; they never assert
     vulnerability. */
  function observations(parsed) {
    var out = [];
    function obs(level, code, message) { out.push({ level: level, code: code, message: message }); }
    var h = parsed.header, p = parsed.payload;
    if (h.alg === "none") obs("high", "alg-none", "Token declares alg:none — it is unsigned.");
    if (!Object.prototype.hasOwnProperty.call(p, "exp"))
      obs("info", "no-exp", "No exp claim — the token never expires (context-dependent).");
    if (!Object.prototype.hasOwnProperty.call(p, "iat"))
      obs("info", "no-iat", "No iat claim.");
    if (!Object.prototype.hasOwnProperty.call(p, "nbf"))
      obs("info", "no-nbf", "No nbf claim.");
    if (!Object.prototype.hasOwnProperty.call(p, "iss"))
      obs("info", "no-iss", "No iss claim.");
    if (!Object.prototype.hasOwnProperty.call(p, "aud"))
      obs("info", "no-aud", "No aud claim.");
    if (Object.prototype.hasOwnProperty.call(p, "exp") && typeof p.exp === "number"
        && Object.prototype.hasOwnProperty.call(p, "iat") && typeof p.iat === "number") {
      var lifetime = p.exp - p.iat;
      if (lifetime > 24 * 3600)
        obs("info", "long-lifetime", "Lifetime exceeds 24 hours — widens the replay window if the token leaks.");
    }
    if (h.jku) obs("high", "jku", "Header carries a jku URL; verify it only if your trust policy pins it.");
    if (h.x5u) obs("high", "x5u", "Header carries an x5u URL; verify it only if your trust policy pins it.");
    if (h.jwk) obs("high", "jwk", "Header carries an embedded jwk; do not trust a key supplied by the token.");
    if (h.kid != null) obs("info", "kid", "Key id present: " + String(h.kid));
    var spec = algSpec(h.alg);
    if (spec && spec.kty === "oct" && h.alg && /^HS/.test(h.alg))
      obs("info", "hmac", "HMAC token — verification needs the shared secret.");
    return out;
  }

  function normalizeTime(t) {
    if (t == null) return null;
    var n = Number(t);
    if (!isFinite(n)) return null;
    return n;
  }

  /* Validate registered claims. Returns {valid, errors}. This is claim
     validation only — it does not prove the signature. */
  function validateClaims(payload, opts) {
    opts = opts || {};
    var errors = [];
    var now = Math.floor(Date.now() / 1000);
    var clockTolerance = Number(opts.clockTolerance) || 0;
    var exp = normalizeTime(payload.exp);
    if (exp != null && now > exp + clockTolerance) {
      errors.push({ code: "exp", message: "Token has expired" });
    }
    var nbf = normalizeTime(payload.nbf);
    if (nbf != null && now < nbf - clockTolerance) {
      errors.push({ code: "nbf", message: "Token is not yet valid (nbf)" });
    }
    if (opts.iss != null && payload.iss !== opts.iss) {
      errors.push({ code: "iss", message: "Issuer mismatch" });
    }
    if (opts.aud != null) {
      var aud = payload.aud;
      var audList = Array.isArray(aud) ? aud : (aud == null ? [] : [aud]);
      if (audList.indexOf(opts.aud) === -1) {
        errors.push({ code: "aud", message: "Audience mismatch" });
      }
    }
    if (opts.sub != null && payload.sub !== opts.sub) {
      errors.push({ code: "sub", message: "Subject mismatch" });
    }
    return { valid: errors.length === 0, errors: errors };
  }

  function pemToArrayBuffer(pem) {
    var b64 = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  function looksLikePem(k) {
    return typeof k === "string" && /-----BEGIN [A-Z ]+-----/.test(k);
  }

  function crypto() {
    var g = typeof globalThis !== "undefined" ? globalThis
      : (typeof window !== "undefined" ? window : this);
    var c = g.crypto || (typeof require === "function" && require("crypto").webcrypto);
    if (!c || !c.subtle) throw new Error("Web Crypto is not available in this environment");
    return c;
  }

  function importPublicKey(spec, keyData, algHint) {
    var c = crypto();
    var algorithm = { name: spec.name, hash: { name: spec.hash } };
    if (spec.pss) algorithm.saltLength = spec.hash === "SHA-256" ? 32 : spec.hash === "SHA-384" ? 48 : 64;
    if (spec.namedCurve) algorithm.namedCurve = spec.namedCurve;
    var key;
    if (looksLikePem(keyData)) {
      key = pemToArrayBuffer(keyData);
      return c.subtle.importKey("spki", key, algorithm, false, ["verify"]);
    }
    if (keyData && typeof keyData === "object") {
      // Enforce the key type matches the algorithm family.
      if (keyData.kty !== spec.kty) {
        return Promise.reject(new Error("Key type (" + keyData.kty + ") does not match algorithm " + algHint));
      }
      var jwk = Object.assign({}, keyData);
      if (!jwk.alg && algHint) jwk.alg = algHint;
      return c.subtle.importKey("jwk", jwk, algorithm, false, ["verify"]);
    }
    return Promise.reject(new Error("Public key must be PEM SPKI or a JWK object"));
  }

  function importSecret(spec, secret) {
    if (typeof secret !== "string" || secret.length === 0) {
      return Promise.reject(new Error("HMAC requires a non-empty shared secret string"));
    }
    var c = crypto();
    var keyData = new TextEncoder().encode(secret);
    return c.subtle.importKey("raw", keyData, { name: "HMAC", hash: spec.hash }, false, ["verify"]);
  }

  /* Pick a JWKS key: match by kid when the token has one, else use a single
     RSA/EC key. The selected key's family must match the expected alg. */
  function pickJwksKey(jwks, kid, spec) {
    if (!jwks || !Array.isArray(jwks.keys)) throw new Error("JWKS must contain a keys array");
    var matches = jwks.keys.filter(function (k) { return k && typeof k === "object"; });
    if (kid != null) matches = matches.filter(function (k) { return k.kid === kid; });
    if (!matches.length) throw new Error("No matching key found in JWKS" + (kid != null ? " for kid " + kid : ""));
    var compatible = matches.filter(function (k) { return k.kty === spec.kty; });
    if (!compatible.length) {
      throw new Error("No " + spec.kty + " key in JWKS matches the expected algorithm family");
    }
    return compatible[0];
  }

  function asUint8(buf) { return buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf; }

  /* Verify a token's signature. `key` may be:
       - a non-empty string  -> HMAC shared secret (HS* only);
       - a PEM SPKI string  -> RSA/EC public key;
       - a JWK object       -> RSA/EC public key (kty must match);
       - a JWKS object      -> {keys:[...]}, selected by kid.
     opts.alg pins the expected algorithm. If omitted, the key's alg is used
     (JWK) or, for JWKS, the matching key's alg. The token header alg is
     always matched against the expected alg and must agree.
     Returns Promise<{valid, alg, keyMatched, error}>. */
  function verifyToken(raw, key, opts) {
    opts = opts || {};
    var parsed;
    try { parsed = parseToken(raw); }
    catch (e) { return Promise.resolve({ valid: false, error: e.message }); }

    var spec = algSpec(parsed.header.alg);
    var expectedAlg = opts.alg || (key && typeof key === "object" && !Array.isArray(key) && key.kty && key.alg) || null;
    if (expectedAlg && expectedAlg !== parsed.header.alg) {
      return Promise.resolve({ valid: false, error: "Algorithm mismatch: header says " + parsed.header.alg + ", expected " + expectedAlg });
    }

    var keyTask;
    if (spec.kty === "oct") {
      // HMAC: only a symmetric string secret works. Reject anything that
      // looks like a public key (PEM or object) — this is what blocks
      // "sign HS256 with the RSA public key" algorithm confusion.
      if (typeof key !== "string" || looksLikePem(key)) {
        return Promise.resolve({ valid: false, error: "HMAC verification requires the shared secret string (not a public key)" });
      }
      keyTask = importSecret(spec, key);
    } else if (looksLikePem(key)) {
      keyTask = importPublicKey(spec, key, parsed.header.alg);
    } else if (key && typeof key === "object" && Array.isArray(key.keys)) {
      var jwk;
      try { jwk = pickJwksKey(key, parsed.header.kid, spec); }
      catch (e) { return Promise.resolve({ valid: false, error: e.message }); }
      if (jwk.alg && jwk.alg !== parsed.header.alg) {
        return Promise.resolve({ valid: false, error: "JWKS key alg (" + jwk.alg + ") does not match token alg (" + parsed.header.alg + ")" });
      }
      keyTask = importPublicKey(spec, jwk, parsed.header.alg);
    } else if (key && typeof key === "object") {
      keyTask = importPublicKey(spec, key, parsed.header.alg);
    } else {
      return Promise.resolve({ valid: false, error: "A key is required to verify the signature" });
    }

    var signingInput = new TextEncoder().encode(parsed.signingInput);
    var algorithm = { name: spec.name, hash: { name: spec.hash } };
    if (spec.pss) algorithm.saltLength = spec.hash === "SHA-256" ? 32 : spec.hash === "SHA-384" ? 48 : 64;

    return keyTask.then(function (cryptoKey) {
      return crypto().subtle.verify(algorithm, cryptoKey, asUint8(parsed.signature), signingInput);
    }).then(function (ok) {
      if (!ok) return { valid: false, alg: parsed.header.alg, error: "Signature does not match" };
      return { valid: true, alg: parsed.header.alg, keyMatched: true };
    }).catch(function (err) {
      return { valid: false, alg: parsed.header.alg, error: err && err.message ? err.message : String(err) };
    });
  }

  return {
    b64urlDecode: b64urlDecode,
    b64urlEncode: b64urlEncode,
    parseToken: parseToken,
    tryParseToken: tryParseToken,
    observations: observations,
    validateClaims: validateClaims,
    verifyToken: verifyToken,
    SUPPORTED_ALGS: SUPPORTED_ALGS
  };
});
