import { chromium } from "playwright";
import { execSync } from "child_process";

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const BASE = "http://127.0.0.1:5173/recon";

const errors = [];
page.on("pageerror", (err) => errors.push(err.message));
page.on("console", (msg) => { if (msg.type() === "error") errors.push(msg.text()); });

async function loadSample(key) {
  await page.goto(BASE, { waitUntil: "networkidle" });
  await page.waitForTimeout(400);
  await page.selectOption("select", key);
  await page.waitForTimeout(800);
  return await page.content();
}

function check(label, condition) {
  console.log(`  ${condition ? "\u2705" : "\u274C"} ${label}: ${condition}`);
}

console.log("=== Recon page smoke tests ===\n");

await page.goto(BASE, { waitUntil: "networkidle" });
await page.waitForTimeout(500);
check("Page loads with title", (await page.title()).includes("BeyondArch"));
check("Select dropdown exists", (await page.locator("select").count()) > 0);
check("Empty state shown", (await page.content()).includes("No target loaded"));

const checks = [
  { key: "phish", label: "Phish domain", panels: ["Risk", "WHOIS", "DNS", "TLS", "HTTP", "Subdomain", "Technology", "Ports", "Certificate Transparency", "Observations", "MITRE"] },
  { key: "bank", label: "Bank domain", panels: ["Risk", "WHOIS", "DNS", "TLS", "HTTP", "Subdomain", "Technology", "Ports", "Certificate Transparency", "Observations"] },
  { key: "startup", label: "Startup", panels: ["Risk", "WHOIS", "DNS", "TLS", "HTTP", "Subdomain", "Technology", "Ports", "Certificate Transparency", "Observations", "MITRE"] },
  { key: "cdn", label: "CDN edge", panels: ["Risk", "WHOIS", "DNS", "TLS", "HTTP", "Subdomain", "Technology", "Ports", "Certificate Transparency", "Observations"] },
];

for (const c of checks) {
  const content = await loadSample(c.key);
  console.log(`\n--- ${c.label} ---`);
  check("Risk banner shown", content.includes("BA-RC-"));
  check("Export button", content.includes("Download Markdown"));
  check("Exposure Risk panel", content.includes("Exposure Risk"));
  for (const p of c.panels) {
    check(p + " panel", content.includes(p));
  }
}

console.log(`\n  Total console errors: ${errors.length === 0 ? "0 ✅" : errors.length}`);
if (errors.length) errors.forEach((e, i) => console.log(`    ${i+1}. ${e}`));

await browser.close();
console.log("\n=== ALL DONE ===");
