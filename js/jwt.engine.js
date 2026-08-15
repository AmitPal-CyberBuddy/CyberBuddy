/* ==========================================================================
   CyberBuddy — JWT engine: decode, inspect, verify (JWT-01) and edit,
   generate, sign (JWT-02)

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
   JWT-02 scope:
     - build a compact JWS from header/payload objects and sign it locally:
       HS256/384/512 with a string secret, RS/PS/ES with a private key;
     - private-key input as PEM PKCS#8 or a JWK that carries private
       material (d) — public keys can never sign;
     - local RSA test-key-pair generation for throwaway authorized testing;
     - a semantic original-vs-modified claim diff.
   The engine still never edits-then-sends: no fetch of a JWKS URL, no
   secret testing, no network/storage, and alg:none stays rejected.

   Accuracy rules enforced here:
     - we never trust the token's "alg" header to choose the verifier; the
       caller passes the expected alg (or the key's alg/JWK alg is used and
       matched), and a mismatch fails verification;
     - HMAC algs only accept symmetric (string) keys; RS/PS/ES only accept
       public keys (PEM/JWK/JWKS) for verify and private keys for sign —
       this blocks algorithm-confusion in both directions;
     - decoding is reported separately from signature/claim verification;
       a signed token is a TEST TOKEN until the target honors it.
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

  return {
    b64urlDecode: b64urlDecode,
    b64urlEncode: b64urlEncode,
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
    SUPPORTED_ALGS: SUPPORTED_ALGS
  };
});
