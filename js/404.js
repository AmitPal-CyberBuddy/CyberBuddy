/* 404 page: base-aware links + theme toggle. */
(function () {
      var base = window.__CB_BASE || "";
      document.querySelectorAll("a.card[data-slug]").forEach(function (a) {
        a.href = base + "/tools/" + a.getAttribute("data-slug") + "/";
      });
      var guides = document.getElementById("guidesLink");
      if (guides) guides.href = base + "/guides/";
      var method = document.getElementById("methodLink");
      if (method) method.href = base + "/#methodology";
      var home = document.getElementById("home");
      if (home) home.href = base + "/";

      var SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
      var MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
      var btn = document.getElementById("themeToggle");
      if (btn) {
        var paint = function () {
          var light = document.documentElement.getAttribute("data-theme") === "light";
          btn.innerHTML = light ? MOON : SUN;
          btn.setAttribute("aria-label", "Switch to " + (light ? "dark" : "light") + " mode");
          btn.title = "Switch to " + (light ? "dark" : "light") + " mode";
        };
        btn.addEventListener("click", function () {
          var light = document.documentElement.getAttribute("data-theme") === "light";
          if (light) document.documentElement.removeAttribute("data-theme");
          else document.documentElement.setAttribute("data-theme", "light");
          try { localStorage.setItem("cb-theme", light ? "dark" : "light"); } catch (_) {}
          paint();
        });
        paint();
      }
    })();
