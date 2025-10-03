from playwright.sync_api import sync_playwright, expect
import time

def run(playwright):
    browser = playwright.chromium.launch()
    page = browser.new_page()
    page.goto("http://127.0.0.1:8080")

    # Take a screenshot of the initial page
    page.screenshot(path="jules-scratch/verification/initial_page.png")

    # Fill in the username
    page.fill("#username", "testuser")

    # Click the search button
    page.click("#search-btn")

    # Give the server a moment to respond
    time.sleep(2)

    try:
        # Use expect for a more robust wait
        results_locator = page.locator("#results-content")
        expect(results_locator).to_have_text("Searching...", timeout=5000)

        # Now wait for the search to complete
        expect(results_locator).not_to_have_text("Searching...", timeout=60000)
    except Exception as e:
        print("Playwright script failed. Reading server log...")
        with open("server.log", "r") as f:
            print(f.read())
        raise e

    # Take a screenshot of the results
    page.screenshot(path="jules-scratch/verification/verification.png")

    browser.close()

with sync_playwright() as p:
    run(p)