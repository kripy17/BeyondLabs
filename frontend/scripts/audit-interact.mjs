import { chromium } from "playwright";

const browser = await chromium.launch({ headless: true });

async function runTest(page, label, fn) {
  const errors = [];
  page.on("console", (msg) => { if (msg.type() === "error") errors.push(msg.text()); });
  page.on("pageerror", (err) => errors.push(err.message));
  
  console.log(`\n=== ${label} ===`);
  try {
    await fn(page);
    await page.waitForTimeout(2000);
  } catch (e) {
    errors.push("EXCEPTION: " + e.message);
  }
  
  if (errors.length) {
    errors.forEach(e => console.log(`  ❌ ${e.substring(0, 400)}`));
  } else {
    console.log(`  ✅ no errors`);
  }
}

// Page 1: URL analyzer — paste a sample URL
await runTest(await browser.newPage(), "URL analyzer", async (page) => {
  await page.goto("http://localhost:5173/url", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
  // Find the IntakeCard textarea and paste
  const textarea = await page.locator('textarea, [contenteditable="true"], input[type="text"]').first();
  if (await textarea.isVisible()) {
    await textarea.fill("hxxps://login.example-bank.com.evil-host.ru/reset");
    // Find analyze/submit button
    const btn = await page.locator('button:has-text("Analyse"), button:has-text("analyze"), button:has-text("Run")').first();
    if (await btn.isVisible()) await btn.click();
  }
});

// Page 2: Parser — paste some text with IOCs
await runTest(await browser.newPage(), "Parser", async (page) => {
  await page.goto("http://localhost:5173/parser", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
  const textarea = await page.locator('textarea, [contenteditable="true"]').first();
  if (await textarea.isVisible()) {
    await textarea.fill("Suspicious IP: 185.220.101.161, domain: evil-host.ru, hash: d41d8cd98f00b204e9800998ecf8427e");
  }
});

// Page 3: Case page
await runTest(await browser.newPage(), "Case page", async (page) => {
  await page.goto("http://localhost:5173/case", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
});

// Page 4: Terminal
await runTest(await browser.newPage(), "Terminal", async (page) => {
  await page.goto("http://localhost:5173/terminal", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
  const input = await page.locator('input[type="text"]').first();
  if (await input.isVisible()) {
    await input.fill("ping -c 1 127.0.0.1");
    await input.press("Enter");
    await page.waitForTimeout(1000);
  }
});

// Page 5: Settings 
await runTest(await browser.newPage(), "Settings", async (page) => {
  await page.goto("http://localhost:5173/settings", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
});

// Page 6: Detection
await runTest(await browser.newPage(), "Detection page", async (page) => {
  await page.goto("http://localhost:5173/detection", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
});

// Page 7: Timeline
await runTest(await browser.newPage(), "Timeline", async (page) => {
  await page.goto("http://localhost:5173/timeline", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2000);
});

await browser.close();
