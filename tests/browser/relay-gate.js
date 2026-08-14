/* Real-browser regression suite for the relay-consent gate.
 *
 * On GitHub Pages there is no local engine, so a header scan must ask before
 * proxying anything through a public relay. Reviewers reported that gate was
 * easy to misread as a stuck scan:
 *   - the Scan button kept spinning while the gate waited for an answer, so
 *     it looked like work in progress rather than a question;
 *   - the gate rendered below the fold on a phone (measured top: 681px in an
 *     844px viewport) and went unnoticed;
 *   - "Allow - hostname only" was styled btn-primary and read as already
 *     selected;
 *   - the three options had no explanation of how they differ, and none was
 *     marked as recommended.
 *
 * This suite pins all of that. See tests/browser/lib.js for how to run it.
 */
"use strict";

const { launch, newPage, BASE, VIEWPORTS } = require("./lib");
(async()=>{const b=await launch();let pass=0,fail=0;
const chk=(ok,m)=>{console.log((ok?'ok   ':'FAIL ')+m);ok?pass++:fail++;};
async function gatePage(vp,theme,noApi=true){
  const p=await newPage(b,{w:vp[1],h:vp[2],theme});
  if(noApi){await p.setRequestInterception(true);
    p.on('request',r=>{ if(/\/api\//.test(r.url())) return r.abort(); r.continue(); });}
  return p;
}
// 1. gate appearance across viewports/themes
for(const vp of VIEWPORTS) for(const theme of ['dark','light']){
  const p=await gatePage(vp,theme);
  await p.goto(BASE+'/tools/headers/',{waitUntil:'networkidle2'});
  await p.type('#url','https://example.com'); await p.click('#go');
  await new Promise(r=>setTimeout(r,3200));
  const s=await p.evaluate(()=>{
    const h=document.querySelector('.site-header');
    const g=document.getElementById('relayGate');
    const head=g.querySelector('h3').getBoundingClientRect();
    const hb=h&&getComputedStyle(h).position==='sticky'?h.getBoundingClientRect().bottom:0;
    const opts=[...g.querySelectorAll('.relay-option')];
    const go=document.getElementById('go');
    return {n:opts.length, rec:g.querySelectorAll('.relay-option-rec').length,
      primary:g.querySelectorAll('.btn-primary').length,
      headVisible: head.top>=hb-1&&head.bottom<=innerHeight,
      allSay: opts.every(o=>/Sends:/.test(o.textContent)&&/You get:/.test(o.textContent)),
      focused: document.activeElement.classList.contains('relay-consent'),
      spinner: !!go.querySelector('.spinner'), waiting: /Waiting/.test(go.textContent),
      ovf: document.documentElement.scrollWidth-document.documentElement.clientWidth,
      inView: opts.every(o=>{const r=o.getBoundingClientRect();return r.left>=-1&&r.right<=innerWidth+1;})};});
  chk(s.n===3&&s.rec===1&&s.primary===0&&s.headVisible&&s.allSay&&s.focused&&!s.spinner&&s.waiting&&s.ovf===0&&s.inView,
    `gate ${vp[0]} ${theme} ${JSON.stringify(s)}`);
  await p.close();
}
// 2. each choice resolves correctly
for(const mode of ['host','full','deny']){
  const p=await gatePage(['laptop',1366,768],'dark');
  await p.goto(BASE+'/tools/headers/',{waitUntil:'networkidle2'});
  await p.type('#url','https://example.com'); await p.click('#go');
  await new Promise(r=>setTimeout(r,3200));
  await p.evaluate(m=>document.querySelector(`[data-consent="${m}"]`).click(),mode);
  await new Promise(r=>setTimeout(r,2500));
  const s=await p.evaluate(()=>{const go=document.getElementById('go');
    return {gateHidden:document.getElementById('relayGate').classList.contains('hidden'),
      consent:sessionStorage.getItem('cb-relay-consent'),
      btn:go.textContent.trim(), disabled:go.disabled, waitingCls:go.classList.contains('is-waiting'),
      notice:!document.getElementById('staticNotice').classList.contains('hidden'),
      results:!document.getElementById('results').classList.contains('hidden')};});
  const ok = s.gateHidden && s.consent===mode && !s.waitingCls && !/Waiting/.test(s.btn) &&
    (mode==='deny' ? (s.notice && !s.disabled) : true);
  chk(ok,`choice=${mode} ${JSON.stringify(s)}`);
  await p.close();
}
// 3. Escape declines rather than silently relaying
{const p=await gatePage(['laptop',1366,768],'dark');
 await p.goto(BASE+'/tools/headers/',{waitUntil:'networkidle2'});
 await p.type('#url','https://example.com'); await p.click('#go');
 await new Promise(r=>setTimeout(r,3200));
 await p.keyboard.press('Escape'); await new Promise(r=>setTimeout(r,1200));
 const s=await p.evaluate(()=>({consent:sessionStorage.getItem('cb-relay-consent'),
   hidden:document.getElementById('relayGate').classList.contains('hidden'),
   btn:document.getElementById('go').textContent.trim()}));
 chk(s.consent==='deny'&&s.hidden&&!/Waiting/.test(s.btn),`escape declines ${JSON.stringify(s)}`);
 await p.close();}
// 4. gate does NOT appear when the python engine is up
{const p=await newPage(b,{w:1366,h:768});
 await p.goto(BASE+'/tools/headers/',{waitUntil:'networkidle2'});
 await p.type('#url','http://127.0.0.1:8099/'); await p.click('#go');
 await p.waitForFunction(()=>!document.getElementById('results').classList.contains('hidden'),{timeout:20000});
 const s=await p.evaluate(()=>({gate:!document.getElementById('relayGate').classList.contains('hidden'),
   src:document.getElementById('mEngine').textContent}));
 chk(!s.gate&&/python/.test(s.src),`no gate with python engine ${JSON.stringify(s)}`);
 await p.close();}
console.log(`\nGATE: ${pass} passed, ${fail} failed`);
await b.close();process.exit(fail?1:0);})();
