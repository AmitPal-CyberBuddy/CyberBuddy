/* ==========================================================================
   CyberBuddy — JWT secret-test worker (JWT-03)

   Runs the bounded HMAC secret search off the main thread. It loads the
   pure engine (js/jwt.engine.js) for BUILTIN_SECRET_CANDIDATES and
   searchHmacSecret, and performs no network, storage or history access.

   Messages in:
     {type:"run", alg, signingInput, signature, builtin, file,
      candidates, maxCandidates, deadline}
       - alg is HS256/384/512; signature is an ArrayBuffer/Uint8Array;
       - builtin (bool) prepends the small built-in candidate list;
       - file (optional) is an uploaded wordlist File, read HERE in the
         worker (never in the main thread, never persisted);
       - candidates (optional) is a string array (used by the Node tests);
       - maxCandidates caps the combined list; deadline is an epoch-ms
         time limit checked between candidates.
     {type:"cancel"} — stops the search at the next candidate boundary.

   Messages out:
     {type:"note", text}               — e.g. candidate list capped
     {type:"progress", tested, total}  — every 250 candidates
     {type:"done", found, secret, tested, total, cancelled, error}
   ========================================================================== */
"use strict";

importScripts("jwt.engine.js");

var J = self.CyberBuddyJwt;
var cancelled = false;

function handleMessage(msg) {
  if (msg.type === "cancel") {
    cancelled = true;
    return;
  }
  if (msg.type !== "run") return;
  cancelled = false;

  var candidates = [];
  try {
    if (msg.builtin && J && J.BUILTIN_SECRET_CANDIDATES) {
      candidates = candidates.concat(J.BUILTIN_SECRET_CANDIDATES);
    }
    if (msg.candidates && Array.isArray(msg.candidates)) {
      candidates = candidates.concat(msg.candidates);
    }
    if (msg.file) {
      var text = new FileReaderSync().readAsText(msg.file);
      var lines = text.split(/\r?\n/);
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (line) candidates.push(line);
      }
      postMessage({ type: "note", text: "Wordlist read in the worker: " + candidates.length + " candidates (built-in " + (msg.builtin ? "included" : "excluded") + ")." });
    }
    if (msg.maxCandidates && candidates.length > msg.maxCandidates) {
      candidates = candidates.slice(0, msg.maxCandidates);
      postMessage({ type: "note", text: "Candidate list capped at " + msg.maxCandidates + " (your limit)." });
    }
    if (!candidates.length) {
      postMessage({ type: "done", found: false, tested: 0, total: 0, cancelled: false, error: "No candidates to test — enable the built-in list or upload a wordlist." });
      return;
    }
  } catch (err) {
    postMessage({ type: "done", found: false, tested: 0, total: 0, cancelled: false, error: err && err.message ? err.message : String(err) });
    return;
  }

  var deadline = msg.deadline || 0;
  J.searchHmacSecret({
    alg: msg.alg,
    signingInput: msg.signingInput,
    signature: msg.signature,
    candidates: candidates,
    shouldContinue: function () {
      return !cancelled && (deadline === 0 || Date.now() < deadline);
    },
    onProgress: function (p) {
      postMessage({ type: "progress", tested: p.tested, total: candidates.length });
    }
  }).then(function (res) {
    postMessage({
      type: "done",
      found: res.found,
      secret: res.found ? res.secret : null,
      tested: res.tested,
      total: candidates.length,
      cancelled: cancelled,
      error: null
    });
  }).catch(function (err) {
    postMessage({ type: "done", found: false, secret: null, tested: 0, total: candidates.length, cancelled: false, error: err && err.message ? err.message : String(err) });
  });
}

self.onmessage = function (e) {
  handleMessage(e.data || {});
};
