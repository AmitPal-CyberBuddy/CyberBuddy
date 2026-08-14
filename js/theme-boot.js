/* Applies the stored theme before first paint to avoid a flash.
   Must be loaded synchronously in <head> (no defer). Externalised from an
   inline <script> so the site can ship a CSP without 'unsafe-inline'. */
(function () {
  try {
    var s = localStorage.getItem("cb-theme");
    if (s === "light") {
      document.documentElement.setAttribute("data-theme", "light");
    } else if (!s && window.matchMedia &&
               window.matchMedia("(prefers-color-scheme: light)").matches) {
      document.documentElement.setAttribute("data-theme", "light");
    }
  } catch (_) { /* private mode */ }
})();
