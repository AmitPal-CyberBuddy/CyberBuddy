/* Page bootstrap. Reads what to initialise from <body data-page> /
   <body data-init> instead of an inline <script>, so every page can run
   under a CSP without 'unsafe-inline'. */
"use strict";

window.addEventListener("DOMContentLoaded", function () {
  var body = document.body;
  var page = body.getAttribute("data-page") || "/";
  var init = (body.getAttribute("data-init") || "").split(/\s+/).filter(Boolean);

  if (typeof renderHeader === "function") renderHeader(page);
  if (typeof renderFooter === "function") renderFooter();

  init.forEach(function (name) {
    var fn = window[name];
    if (typeof fn === "function") {
      try { fn(); } catch (err) { /* one bad init must not kill the page */ }
    }
  });

  // AFTER the page initialisers: several of them (renderToolCards,
  // renderBlog) inject .reveal content. initReveal must run last so those
  // nodes are tracked — otherwise they stay at opacity: 0, invisible but
  // clickable. (initReveal also watches for late additions.)
  if (typeof initReveal === "function") initReveal();
});
