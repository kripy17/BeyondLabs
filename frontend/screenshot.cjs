const { chromium } = require("playwright");
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.goto("http://localhost:5173/smart-parser", { waitUntil: "networkidle", timeout: 15000 });
  await page.waitForSelector(".s-card", { timeout: 5000 });
  await page.waitForTimeout(500);
  const dims = await page.evaluate(() => ({
    scrollH: document.documentElement.scrollHeight,
    vpHeight: window.innerHeight,
    cardRect: document.querySelector(".s-card")?.getBoundingClientRect(),
    cardBodyRect: document.querySelector(".s-card-body")?.getBoundingClientRect(),
  }));
  console.log(JSON.stringify(dims, null, 2));
  await page.screenshot({ path: "/tmp/smart-parser.png", fullPage: false });
  console.log("Screenshot saved to /tmp/smart-parser.png");
  await browser.close();
})();
