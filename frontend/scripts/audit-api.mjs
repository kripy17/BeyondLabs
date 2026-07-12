import { chromium } from "playwright";

const routes = [
  { path: "/nmap", label: "nmap" },
  { path: "/phishing", label: "phishing" },
  { path: "/url", label: "url" },
  { path: "/recon", label: "recon" },
  { path: "/parser", label: "parser" },
  { path: "/detection", label: "detection" },
  { path: "/siem", label: "siem" },
  { path: "/hacking-toolkit", label: "toolkit" },
];

const browser = await chromium.launch({ headless: true });

for (const { path, label } of routes) {
  const page = await browser.newPage();
  const errors = [];
  const apiCalls = [];
  const apiFails = [];
  
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(err.message));
  page.on("response", (resp) => {
    if (resp.url().includes("127.0.0.1:8000")) {
      apiCalls.push(`${resp.status()} ${resp.url().split("/api").pop()}`);
      if (resp.status() >= 400) apiFails.push(`${resp.status()} ${resp.url().split("/api").pop()}`);
    }
  });
  
  await page.goto(`http://localhost:5173${path}`, { waitUntil: "domcontentloaded", timeout: 15000 }).catch(e => {});
  await page.waitForTimeout(4000);
  
  console.log(`\n=== ${label} (${path}) ===`);
  if (errors.length) errors.forEach(e => console.log(`  ❌ ${e.substring(0, 300)}`));
  if (apiFails.length) apiFails.forEach(f => console.log(`  🔴 ${f}`));
  if (!errors.length && !apiFails.length) console.log(`  ✅ clean — ${apiCalls.length} API calls`);
  if (!errors.length && apiFails.length === 0 && apiCalls.length > 0) console.log(`  ✅ all API ok`);
  apiCalls.slice(0, 8).forEach(c => console.log(`  📡 ${c}`));
  
  await page.close();
}

await browser.close();
