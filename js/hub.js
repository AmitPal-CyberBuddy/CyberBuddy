/* CyberBuddy — hub page extras.
   Externalised from an inline <script> so the site can ship a CSP without
   'unsafe-inline'. Depends on js/app.js. */
"use strict";

window.typeConsole = function typeConsole() {
  const c = document.getElementById("demoConsole");
  if (!c) return;
  const lines = [
    '<div><span class="c-prompt">$</span> cyberbuddy scan https://example.com</div>',
    '<div class="c-dim">─ framing protections ─────────────────────</div>',
    '<div><span class="c-red">[missing]</span>&nbsp; CSP frame-ancestors</div>',
    '<div><span class="c-red">[missing]</span>&nbsp; X-Frame-Options</div>',
    '<div><span class="c-red">[missing]</span>&nbsp; Strict-Transport-Security</div>',
    '<div><span class="c-red">[missing]</span>&nbsp; X-Content-Type-Options</div>',
    '<div class="c-dim">──────────────────────────────────────────</div>',
    '<div>risk: <span class="c-red">HIGH</span> &nbsp; grade: <span class="c-red">F</span> &nbsp; <span class="c-dim">via published report</span></div>',
    '<div class="c-dim">─ cached demo · run the suite above for a live scan ─</div>'
  ];
  if (prefersReduced()) {
    c.innerHTML = lines.join("") + '<span class="caret"></span>';
    return;
  }
  c.classList.add("scanning");
  let i = 0;
  const step = () => {
    if (i >= lines.length) {
      c.innerHTML += '<span class="caret"></span>';
      return;
    }
    c.innerHTML += lines[i];
    i++;
    setTimeout(step, 220);
  };
  setTimeout(step, 280);
};
