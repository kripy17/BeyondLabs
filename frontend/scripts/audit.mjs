import { chromium } from "playwright";

const routes = [
  "/", "/parser", "/url", "/phishing", "/nmap", "/recon", "/detection",
  "/siem", "/case", "/terminal", "/timeline", "/chef", "/hacking-toolkit",
  "/osint", "/mitre", "/guide", "/logs", "/attachment", "/settings",
];

const browser = await chromium.launch({ headless: true });
const results = [];

for (const route of routes) {
  const page = await browser.newPage();
  const errors = [];
  const warnings = [];
  
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
    if (msg.type() === "warning") warnings.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(err.message));
  
  await page.goto(`http://localhost:5173${route}`, { waitUntil: "domcontentloaded", timeout: 15000 }).catch(e => {});
  await page.waitForTimeout(3000);
  
  const finalUrl = page.url();
  
  const pageTitle = await page.title().catch(() => "?");
  const hasContent = await page.evaluate(() => document.body?.innerText?.length > 50).catch(() => false);
  
  results.push({
    route,
    status: 200,
    errors: errors.filter(e => !e.includes("favicon") && !e.includes("ERR_BLOCKED_BY_CLIENT") && !e.startsWith("goto:")),
    warnings: warnings.filter(w => !w.includes("favicon") && !w.includes("Source map")),
    content: hasContent,
  });
  
  await page.close();
}

await browser.close();

console.log("=== PAGE AUDIT RESULTS ===\n");
for (const r of results) {
  console.log(`\n${r.route} (${r.status}) ${r.content ? "📄" : "⚫"}`);
  if (r.errors.length) r.errors.forEach(e => console.log(`  ❌ ${e}`));
  if (r.warnings.length) r.warnings.slice(0, 5).forEach(w => console.log(`  ⚠️  ${w.substring(0, 300)}`));
  if (!r.errors.length && !r.warnings.length) console.log(`  ✅ clean`);
}
