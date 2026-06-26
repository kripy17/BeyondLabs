import { chromium } from "playwright";
import { execSync } from "child_process";

const browserPath = execSync("find ~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome -type f 2>/dev/null | head -1").toString().trim();
const browser = await chromium.launch({ executablePath: browserPath, headless: true });
const page = await browser.newPage();
const BASE = "http://127.0.0.1:5173/url";

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

console.log("=== Smoke tests ===\n");

// 1. Load page
await page.goto(BASE, { waitUntil: "networkidle" });
await page.waitForTimeout(500);
check("Page loads with title", (await page.title()).includes("BeyondArch"));
check("Select dropdown exists", (await page.locator("select").count()) > 0);

// 2. Defanged
const d = await loadSample("defanged");
check("Risk banner shown", d.includes("BA-UR-"));
check("Path Analysis panel", d.includes("Path Analysis"));
check("Secrets panel", d.includes("Secrets in URL"));
check("MITRE panel", d.includes("MITRE ATT"));
check("Export button", d.includes("Download Markdown"));
check("Domain Profile panel", d.includes("Domain Profile"));
check("Artifact Summary panel", d.includes("Artifact Summary"));

// 3. Punycode
const p = await loadSample("punycode");
check("Punycode detection", p.includes("xn--"));

// 4. Embedded creds
const e = await loadSample("embedded_creds");
check("Embedded credentials finding", e.includes("Embedded credentials"));
check("Username shown", e.includes("admin"));

// 5. IP-based
const ip = await loadSample("ip_based");
check("Direct IP finding", ip.includes("Direct IP address"));

// 6. Download
const dl = await loadSample("download");
check("File download detection", dl.includes("setup.exe") || dl.includes(".exe") || dl.includes("File download"));

// 7. Non-standard port
const port = await loadSample("suspicious_port");
check("Port 8080 flag", port.includes("8080"));

// 8. High entropy
const ent = await loadSample("high_entropy");
check("Secrets found", ent.includes("GitHub Token") || ent.includes("ghp_"));
check("Domain entropy flag", ent.includes("Domain entropy") || ent.includes("High domain entropy"));
check("Suspicious TLD flag", ent.includes(".ru"));

// 9. Legit (low score expected)
const leg = await loadSample("legit");
check("Low risk badge", leg.includes("low risk") || leg.includes("success"));

// 10. History
await page.goto(BASE, { waitUntil: "networkidle" });
await page.waitForTimeout(500);
check("No Recent URLs on fresh load", !(await page.content()).includes("Recent URLs"));
await page.selectOption("select", "defanged");
await page.waitForTimeout(800);
await page.goto(BASE, { waitUntil: "networkidle" });
await page.waitForTimeout(500);
const histContent = await page.content();
check("Recent URLs shown after sample", histContent.includes("Recent URLs"));

// 11. Errors
console.log(`\n  Total console errors: ${errors.length === 0 ? "0 \u2705" : errors.length}`);
if (errors.length) errors.forEach((e, i) => console.log(`    ${i+1}. ${e}`));

await browser.close();
console.log("\n=== ALL DONE ===");
