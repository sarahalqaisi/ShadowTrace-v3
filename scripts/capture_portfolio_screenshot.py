from pathlib import Path
from playwright.sync_api import sync_playwright

output = Path("docs/screenshots/shadowtrace-dashboard.png")
output.parent.mkdir(parents=True, exist_ok=True)
with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    page.goto("http://127.0.0.1:5000", wait_until="networkidle")
    page.get_by_label("Username").fill("portfolio")
    page.get_by_label("Password").fill("PortfolioDemo123!")
    page.get_by_role("button", name="Open workspace").click()
    page.wait_for_load_state("networkidle")
    page.screenshot(path=output, full_page=True)
    browser.close()
