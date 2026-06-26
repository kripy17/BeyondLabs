import { chromium } from "playwright";
import { execSync } from "child_process";

const browserPath = execSync("find ~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome -type f 2>/dev/null | head -1").toString().trim();
const browser = await chromium.launch({ executablePath: browserPath, headless: true });
const page = await browser.newPage();
const BASE = "http://127.0.0.1:5173/attachment";

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

console.log("=== Attachment page smoke tests ===\n");

await page.goto(BASE, { waitUntil: "networkidle" });
await page.waitForTimeout(500);
check("Page loads with title", (await page.title()).includes("BeyondArch"));
check("Select dropdown exists", (await page.locator("select").count()) > 0);
check("Empty state shown", (await page.content()).includes("No sample loaded"));

const checks = [
  { key: "docm", label: "DOCM macro", panels: ["Risk Score", "Macro Analysis", "Suspicious Strings", "Embedded URLs", "YARA Matches", "MITRE ATT"] },
  { key: "iso", label: "ISO container", panels: ["Risk Score", "LNK Analysis", "Entropy Scan", "Suspicious Strings", "Embedded URLs", "YARA Matches"] },
  { key: "pdf_js", label: "PDF with JS", panels: ["Risk Score", "Suspicious Strings", "Embedded URLs", "Embedded IPs", "YARA Matches", "MITRE ATT"] },
  { key: "rtf_ole", label: "RTF OLE", panels: ["Risk Score", "OLE Objects", "Suspicious Strings", "YARA Matches", "MITRE ATT"] },
  { key: "lnk_psh", label: "LNK shortcut", panels: ["Risk Score", "LNK Analysis", "Suspicious Strings", "Embedded URLs", "YARA Matches", "MITRE ATT"] },
  { key: "dll_side", label: "DLL side", panels: ["Risk Score", "Suspicious Strings", "Embedded URLs", "YARA Matches", "MITRE ATT"] },
];

for (const c of checks) {
  const content = await loadSample(c.key);
  console.log(`\n--- ${c.label} ---`);
  check("Risk banner shown", content.includes("BA-AT-"));
  check("Export button", content.includes("Download Markdown"));
  check("Hashes shown", content.includes("SHA-256") && content.includes("MD5"));
  const resultBanner = content.includes("ResultBanner") || content.includes("banner") || content.includes("static_review") || content.includes("Verdict");
  check("Result banner present", resultBanner || content.includes("Verdict"));
  for (const p of c.panels) {
    check(p + " panel", content.includes(p));
  }
}

console.log(`\n  Total console errors: ${errors.length === 0 ? "0 ✅" : errors.length}`);
if (errors.length) errors.forEach((e, i) => console.log(`    ${i+1}. ${e}`));

await browser.close();
console.log("\n=== ALL DONE ===");
