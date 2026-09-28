/* Supplement axe's incomplete gradient/translucency checks with rendered
 * background samples. This is a regression sampler, not a WCAG certification:
 * three interior points per text rect cannot prove every pixel/background.
 * Run at deviceScaleFactor=1, reduced motion, with fonts/layout settled.
 * Only the temporary screenshot hides glyphs; page styles are restored.
 */
"use strict";
const assert = require("node:assert/strict");
const { PNG } = require("pngjs");

function luminance(rgb) {
  return rgb.slice(0, 3).map(value => {
    const c = value / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  }).reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i], 0);
}
function contrastRatio(a, b) {
  const x = luminance(a), y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

async function sampleTextContrast(page, scope = "body") {
  // Always establish the same coordinates before gathering ranges and pixels.
  if (scope === "body") await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
  const nodes = await page.evaluate(selector => {
    const root = document.querySelector(selector);
    if (!root) throw new Error("Missing contrast scope: " + selector);
    const out = [];
    const name = e => e.id ? "#" + e.id : e.tagName.toLowerCase() +
      (e.className ? "." + String(e.className).trim().replace(/\s+/g, ".") : "");
    const visible = e => {
      if (e.closest('[disabled],[aria-disabled="true"]')) return false;
      if (!e.checkVisibility({ opacityProperty: true, visibilityProperty: true })) return false;
      // Animated/faded/disabled text is outside this static-state sampler.
      let opacity = 1;
      for (let a = e; a; a = a.parentElement) opacity *= +getComputedStyle(a).opacity;
      return opacity >= 0.99;
    };
    function record(e, text, style, rects, colors) {
      rects = [...rects].filter(r => r.width > 2 && r.height > 2)
        .map(r => ({ x: r.x, y: r.y + scrollY, w: r.width, h: r.height }));
      if (!rects.length) return;
      out.push({ element: name(e), text: text.trim().slice(0, 90), colors, rects,
        threshold: parseFloat(style.fontSize) >= 24 ||
          (parseFloat(style.fontSize) >= 18.6667 && +style.fontWeight >= 700) ? 3 : 4.5 });
    }
    const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walk.nextNode())) {
      const e = n.parentElement;
      if (!n.textContent.trim() || !e || e.closest("script,style,noscript,option,textarea") || !visible(e)) continue;
      const style = getComputedStyle(e), range = document.createRange();
      range.selectNodeContents(n);
      let colors = [style.color];
      // Conservatively test every stop of gradient text, not transparent black.
      if (style.color === "rgba(0, 0, 0, 0)") {
        for (let a = e; a; a = a.parentElement) {
          const s = getComputedStyle(a);
          if (s.backgroundClip === "text" || s.webkitBackgroundClip === "text") {
            colors = s.backgroundImage.match(/rgba?\([^)]+\)/g) || [];
            break;
          }
        }
      }
      record(e, n.textContent, style, range.getClientRects(), colors);
    }
    // TreeWalker cannot see placeholder text or the painted value of a control.
    root.querySelectorAll("input,textarea,select").forEach(e => {
      if (!visible(e) || /^(checkbox|radio|range|hidden|file|color)$/.test(e.type)) return;
      const placeholder = !e.value && e.placeholder;
      const text = placeholder || (e.tagName === "SELECT" ? e.selectedOptions[0]?.textContent : e.value);
      if (!text) return;
      const s = getComputedStyle(e, placeholder ? "::placeholder" : null);
      if (+s.opacity < 0.99) return;
      const r = e.getBoundingClientRect();
      // Sample the text interior, away from the native arrow, border and corners.
      record(e, text, s, [{ x: r.x + 16, y: r.y + 8, width: Math.max(3, r.width - 48),
        height: Math.min(parseFloat(s.lineHeight) || 20, r.height - 16) }], [s.color]);
    });
    return out;
  }, scope);
  assert(nodes.length, "No visible text measured in " + scope);

  // CSSOM changes to a same-origin sheet work under the site's real CSP;
  // there is no CSP bypass and no application CSS changes for the test.
  const saved = await page.evaluate(() => {
    const sheet = [...document.styleSheets].find(s => { try { return !!s.cssRules; } catch (_) { return false; } });
    if (!sheet) throw new Error("No readable stylesheet; page may not have loaded");
    const index = [...document.styleSheets].indexOf(sheet), length = sheet.cssRules.length;
    [
      '* { color:transparent!important; -webkit-text-fill-color:transparent!important; text-shadow:none!important; caret-color:transparent!important; }',
      'input::placeholder,textarea::placeholder { color:transparent!important; -webkit-text-fill-color:transparent!important; }',
      '.hero-title { background-image:none!important; }'
    ].forEach((rule, i) => sheet.insertRule(rule, length + i));
    return { index, length };
  });
  let image;
  try {
    // Wait for compositing; otherwise Chromium may capture the old glyph layer.
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    image = PNG.sync.read(Buffer.from(await page.screenshot({ fullPage: true })));
  } finally {
    await page.evaluate(({ index, length }) => {
      const sheet = document.styleSheets[index];
      while (sheet.cssRules.length > length) sheet.deleteRule(length);
    }, saved);
  }
  const failures = [];
  let measured = 0, minimum = Infinity;
  for (const node of nodes) {
    let lowest = Infinity, evidence;
    for (const rect of node.rects) {
      for (const [u, v] of [[0.2, 0.35], [0.5, 0.5], [0.8, 0.65]]) {
        const x = Math.floor(rect.x + rect.w * u), y = Math.floor(rect.y + rect.h * v);
        if (x < 0 || x >= image.width || y < 0 || y >= image.height) continue;
        const offset = (y * image.width + x) * 4;
        const bg = [...image.data.slice(offset, offset + 3)];
        for (const color of node.colors) {
          const c = (color.match(/[\d.]+/g) || []).map(Number);
          if (c.length < 3 || c[3] === 0) continue;
          const alpha = c[3] ?? 1;
          const fg = c.slice(0, 3).map((value, i) => value * alpha + bg[i] * (1 - alpha));
          const ratio = contrastRatio(fg, bg);
          if (ratio < lowest) { lowest = ratio; evidence = { foreground: color, background: bg }; }
        }
      }
    }
    if (!Number.isFinite(lowest)) continue;
    measured++;
    minimum = Math.min(minimum, lowest);
    if (lowest < node.threshold) failures.push({ element: node.element, text: node.text,
      ratio: +lowest.toFixed(2), required: node.threshold, ...evidence });
  }
  assert(measured > 0, "No supported text colors measured in " + scope);
  return { measured, minimum, failures };
}
module.exports = { sampleTextContrast, contrastRatio };
