import { test, expect } from "@playwright/test"

test.describe("Core SOC flow", () => {
  test("Parser extracts IOCs → handoff Attach to case → case receives entry", async ({ page }) => {
    await page.goto("/parser")
    await page.waitForLoadState("networkidle")

    const textarea = page.locator("textarea").first()
    await expect(textarea).toBeVisible({ timeout: 15000 })

    const sampleText = `Suspicious connection from 203.0.113.44 to example-malware.com
Hash: d41d8cd98f00b204e9800998ecf8427e
Email: phish@evil.com`

    await textarea.fill(sampleText)
    await page.waitForTimeout(2000)

    // Switch to IPv4 tab
    const ipv4Tab = page.locator("button").filter({ hasText: /ipv4/i }).first()
    await expect(ipv4Tab).toBeVisible()
    await ipv4Tab.click()
    await page.waitForTimeout(200)

    // Find and click the IOC chip
    const ipChip = page.locator("button").filter({ hasText: "203[.]0[.]113[.]44" }).first()
    await ipChip.click()
    await page.waitForTimeout(300)

    // Click "Attach to case"
    const attachBtn = page.locator("button").filter({ hasText: "Attach to case" }).first()
    await expect(attachBtn).toBeVisible()
    await attachBtn.click()

    // Navigate to Cases page
    await page.goto("/case")
    await page.waitForLoadState("networkidle")
    await page.waitForTimeout(1000)

    // Verify the case shows the IOC entry
    // The entry should appear in the timeline as "[from /parser] 203[.]0[.]113[.]44"
    await expect(page.getByText("203[.]0[.]113[.]44")).toBeVisible()
    await expect(page.getByText("from /parser")).toBeVisible()
  })

  test("Parser extracts multiple IOC types", async ({ page }) => {
    await page.goto("/parser")
    await page.waitForLoadState("networkidle")

    const textarea = page.locator("textarea").first()
    await expect(textarea).toBeVisible({ timeout: 15000 })

    const sampleText = `C2 beacon from 10.0.0.5 to evil-c2.xyz:4443
MD5: d41d8cd98f00b204e9800998ecf8427e
Phish from scammer@phish.net with malicious attachment`

    await textarea.fill(sampleText)
    await page.waitForTimeout(2000)

    // All tab should show counts
    const allTab = page.locator("button").filter({ hasText: "all ·" })
    await expect(allTab).toBeVisible()

    // Individual type tabs should be present
    const domainTab = page.locator("button").filter({ hasText: /domain · /i })
    await expect(domainTab).toBeVisible()
    const ipv4Tab = page.locator("button").filter({ hasText: /ipv4 · /i })
    await expect(ipv4Tab).toBeVisible()
    const emailTab = page.locator("button").filter({ hasText: /email · /i })
    await expect(emailTab).toBeVisible()
  })
})
