/* 404 page: theme + legacy-URL repair. Runs before paint, so it stays a
   separate synchronous file rather than an inline <script>. */
(function () {
      try {
        var s = localStorage.getItem("cb-theme");
        if (s === "light") document.documentElement.setAttribute("data-theme", "light");
        else if (!s && window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) document.documentElement.setAttribute("data-theme", "light");
      } catch (_) {}
      var path = location.pathname || "/";
      var next = path.replace(/\/js\/app\.js(?=\/)/, "");
      if (!/\/tools\/(clickjacking|headers|cors|csp|csrf)\/?$/.test(next)) {
        next = next.replace(/\/(clickjacking|headers|cors|csp|csrf)\/?$/, "/tools/$1/");
      } else if (next.slice(-1) !== "/") {
        next += "/";
      }
      if (next !== path) {
        location.replace(next + location.search + location.hash);
        return;
      }
      var base = "";
      var m = path.match(/^(\/[^/]+)(?=\/(?:js|css|tools|api)\b)/);
      if (m) base = m[1];
      else {
        var known = path.match(/^(\/CyberBuddy)(?=\/|$)/i);
        if (known) base = known[1];
      }
      window.__CB_BASE = base;
    })();
