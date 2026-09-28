/* All seven tools: real HTTP-engine results, offline DNS evidence fixtures,
 * browser WebCrypto verification, CSRF option persistence, exports, and axe
 * contrast checks in both themes. Only owned loopback HTTP targets are used.
 */
"use strict";
const assert = require("node:assert/strict");
const { createHmac } = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { AxePuppeteer } = require("@axe-core/puppeteer");
const { BASE, TARGET, launch, newPage, sleep } = require("./lib");
const dnsFixture = JSON.parse(execFileSync("python3", ["-c", `
import json
from dns_security import grade_dns_from_records
records={"A":["192.0.2.1"],"NS":["ns1.example.test","ns2.example.test"],"MX":["10 mail.example.test"],"TXT":["v=spf1 -all"],"_dmarc.TXT":["v=DMARC1; p=reject"],"CAA":['0 issue "ca.example.test"']}
print(json.dumps([grade_dns_from_records("example.test",records,resolver="offline fixture").to_dict(),grade_dns_from_records("example.test",{}, {"A":"NXDOMAIN"},resolver="offline fixture").to_dict()]))
`], { cwd: require("node:path").resolve(__dirname, "../.."), encoding: "utf8" }));
const secret = "local-fixture-secret";
const parts = [Buffer.from('{"alg":"HS256","typ":"JWT"}').toString("base64url"), Buffer.from(JSON.stringify({ sub: "audit-account", exp: Math.floor(Date.now()/1000)+3600 })).toString("base64url")];
const unsigned = parts.join(".");
const token = unsigned + "." + createHmac("sha256", secret).update(unsigned).digest("base64url");
async function fill(page, id, value) {
  await page.$eval(id, (e,v) => { e.value=v; e.dispatchEvent(new Event("input",{bubbles:true})); }, value);
}
(async()=>{
  const browser = await launch();
  try {
    for (const theme of ["light","dark"]) {
      for (const tool of ["headers","csp","cors","clickjacking","dns","csrf","jwt"]) {
        const page = await newPage(browser,{theme,w:Number(process.env.CB_WIDTH || 1366),h:900});
        // Reduced motion is also a supported user setting, not a CSS override.
        await page.emulateMediaFeatures([{name:"prefers-reduced-motion",value:"reduce"}]);
        const errors=[]; page.on("pageerror", e=>errors.push(e.message));
        let dnsData=dnsFixture[0], lastResponse;
        await page.setRequestInterception(true);
        page.on("request", req=>{
          if(req.url().includes("/api/dns?")) return req.respond({status:200,contentType:"application/json",body:JSON.stringify(dnsData)});
          req.continue();
        });
        page.on("response", async res=>{
          if (/\/api\/(headers|csp|cors|scan)\?/.test(res.url())) {
            try { lastResponse=await res.json(); } catch (_) { /* asserted below */ }
          }
        });
        await page.goto(BASE+"/tools/"+tool+"/",{waitUntil:"networkidle2"});
        const checkContrast=async label=>{
          await sleep(100);
          const result=await new AxePuppeteer(page).withRules(["color-contrast"]).analyze();
          assert.deepEqual(result.violations.map(v=>v.nodes.map(n=>({target:n.target,detail:n.failureSummary}))),[],`${theme} ${tool} ${label}`);
        };
        await checkContrast("initial");
        if (["headers","csp","cors","clickjacking"].includes(tool)) {
          await fill(page,"#url",TARGET);
          const responseReady = page.waitForResponse(res => /\/api\/(headers|csp|cors|scan)\?/.test(res.url()), {timeout:25000});
          await page.click("#go");
          lastResponse = await (await responseReady).json();
          await page.waitForFunction(()=>!document.querySelector("#results").classList.contains("hidden") && !document.querySelector("#go").disabled,{timeout:25000});
          assert(lastResponse,`${tool}: real engine response`);
          const exportCheck=await page.evaluate(data=>{
            const env=reportExportEnvelope(data);
            const html=toStandaloneHtml(data), md=toMarkdown(data), csv=toCsv(data);
            return {json:JSON.stringify(env),html,md,csv,rows:reportRows(data).length};
          },lastResponse);
          assert(exportCheck.rows>0); assert(exportCheck.md.includes("CyberBuddy"));
          assert(exportCheck.html.includes("<table>")); assert(exportCheck.csv.includes("record_type"));
          assert(exportCheck.json.includes(TARGET));
          if (tool==="headers") assert.equal(await page.$eval("#grade",e=>e.textContent),lastResponse.grade.toUpperCase());
          if (tool==="csp") assert.equal(await page.$eval("#policy",e=>e.textContent),lastResponse.policy || "(not present)");
          if (tool==="clickjacking") {
            await page.click("#togglePoc");
            assert(await page.$eval("#stage",e=>e.classList.contains("poc")));
            await page.click("#togglePoc");
          }
        } else if(tool==="dns") {
          await fill(page,"#domain","example.test"); await page.click("#go");
          await page.waitForFunction(()=>!document.querySelector("#results").classList.contains("hidden"));
          assert.equal(await page.$eval("#grade",e=>e.textContent),dnsData.grade.toUpperCase());
          assert.equal(await page.$eval("#mScore",e=>e.textContent),dnsData.score+" / 100");
          await checkContrast("graded DNS fixture");
          dnsData=dnsFixture[1]; await page.click("#go");
          await page.waitForFunction(()=>document.querySelector("#verdict").textContent==="UNKNOWN");
          assert.match(await page.$eval("#gauge",e=>e.textContent),/not graded/);
          assert.equal(await page.$eval("#mScore",e=>e.textContent),"—");
        } else if(tool==="csrf") {
          await fill(page,"#request","POST /?csrf=QUERY HTTP/1.1\nHost: example.test\nContent-Type: application/x-www-form-urlencoded\n\ncsrf_token=BODY&value=1");
          await page.click("#generate");
          await page.click('[data-token-uid="q:0"]');
          await page.click('[data-token-uid="b:0"]');
          await page.click("#autoSubmit");
          const state=await page.evaluate(()=>({selected:[...document.querySelectorAll('[data-token-uid]')].map(e=>e.checked),html:document.querySelector("#pocSource").textContent}));
          assert.deepEqual(state.selected,[false,false]); assert(!/QUERY|BODY/.test(state.html));
          await checkContrast("generated");
          await fill(page,"#request","TRACE / HTTP/1.1\nHost: example.test\n\n"); await page.click("#generate");
          assert(await page.$eval("#download",e=>e.disabled));
          assert.match(await page.$eval("#pocSource",e=>e.textContent),/No executable PoC/);
          await fill(page,"#request","bad input"); await page.click("#generate");
          assert(await page.$eval("#copyHtml",e=>e.disabled));
        } else {
          await fill(page,"#jwtToken",token);
          await page.waitForFunction(()=>!document.querySelector("#jwtDecoded").classList.contains("hidden"));
          await fill(page,"#jwtSecret",secret); await page.click("#jwtVerify");
          await page.waitForFunction(()=>document.querySelector("#jwtVerifyResult").classList.contains("jwt-verify-ok"));
          await checkContrast("verified");
          await fill(page,"#jwtSecret","wrong-secret"); await page.click("#jwtVerify");
          await page.waitForFunction(()=>document.querySelector("#jwtVerifyResult").classList.contains("jwt-verify-bad"));
          await checkContrast("wrong signature");
          for(const tab of ["edit","variants","secret"]) {
            await page.click("#jwt-tab-"+tab); await checkContrast(tab);
          }
        }
        await checkContrast("result/error");
        assert.deepEqual(errors,[],`${tool}: runtime errors`);
        console.log(`ok ${theme} ${tool}: results, interactions, contrast`);
        await page.close();
      }
    }
  } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exit(1);});
