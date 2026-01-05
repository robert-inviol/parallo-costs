#!/usr/bin/env python3
"""
Refresh Power BI token via browser automation.

This script performs the full login flow in a browser and captures the MWCToken
by intercepting network requests to Power BI.

Environment variables:
    PARALLO_USERNAME - Azure AD email
    PARALLO_PASSWORD - Password
    PARALLO_TOTP_SECRET - TOTP secret for MFA (optional)
    HEADLESS - Set to 'false' for debugging (default: true)
"""

import os
import sys
import json
import asyncio
import re
from playwright.async_api import async_playwright

try:
    import pyotp
except ImportError:
    pyotp = None


# Configuration - import from fetch_parallo_costs
try:
    from fetch_parallo_costs import COMPANY_ID
except ImportError:
    COMPANY_ID = os.environ.get('PARALLO_COMPANY_ID', '')

REPORTS_URL = f"https://portal.parallo.support/companies/{COMPANY_ID}/services/csp/reports"
TOKEN_FILE = "captured_token.txt"


async def refresh_token(username, password, headless=True):
    """Perform full browser login and capture the MWCToken."""

    mwc_token = None
    embed_token = None

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--no-sandbox',
            ]
        )

        context = await browser.new_context(
            user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )

        page = await context.new_page()

        # Capture tokens from network requests
        async def handle_request(request):
            nonlocal mwc_token, embed_token

            url = request.url

            # Capture MWCToken from Power BI requests
            if 'pbidedicated.windows.net' in url:
                auth = request.headers.get('authorization', '')
                if auth.startswith('MWCToken ') and not mwc_token:
                    mwc_token = auth
                    print(f"  Captured MWCToken! (length: {len(auth)})")

            # Capture EmbedToken from exploration requests
            if 'analysis.windows.net' in url and 'explore/reports' in url:
                auth = request.headers.get('authorization', '')
                if auth.startswith('EmbedToken ') and not embed_token:
                    embed_token = auth
                    print(f"  Captured EmbedToken! (length: {len(auth)})")

        page.on('request', handle_request)

        # Start login flow
        print("[1] Navigating to portal...")
        await page.goto('https://portal.parallo.support/')
        await asyncio.sleep(3)
        print(f"    Current URL: {page.url[:60]}...")

        # Click login if needed
        try:
            login_btn = page.locator('text=Login').first
            if await login_btn.is_visible(timeout=5000):
                print("[2] Clicking Login...")
                await login_btn.click()
                await asyncio.sleep(3)
            else:
                print("[2] No login button visible, may already be redirecting...")
        except Exception as e:
            print(f"[2] Login button not found: {e}")

        # Handle B2C identity provider selection
        print("[3] Handling B2C provider selection...")

        # Wait for B2C page to load
        try:
            await page.wait_for_url(re.compile(r'b2clogin\.com'), timeout=15000)
            await asyncio.sleep(2)
            print(f"    On B2C page: {page.url[:60]}...")

            # Click Azure Active Directory button
            try:
                azure_btn = page.locator('button:has-text("Azure Active Directory"), a:has-text("Azure Active Directory"), div.options button:has-text("Azure")').first
                await azure_btn.wait_for(state='visible', timeout=10000)
                await azure_btn.click()
                print("    Clicked Azure AD button")
                await asyncio.sleep(3)
            except Exception as e:
                print(f"    Could not find Azure AD button: {e}")
                await page.screenshot(path='b2c_debug.png')
                print("    Saved b2c_debug.png for debugging")
        except Exception as e:
            print(f"    B2C page not detected: {e}")

        # Wait for Microsoft login page
        print("[4] Waiting for Microsoft login...")
        try:
            await page.wait_for_url('**/login.microsoftonline.com/**', timeout=15000)
        except Exception as e:
            print(f"    Warning: {e}")

        # Enter email
        print("[5] Entering email...")
        try:
            email_input = page.locator('input[type="email"], input[name="loginfmt"]').first
            await email_input.fill(username)
            await page.keyboard.press('Enter')
            await asyncio.sleep(3)
        except Exception as e:
            print(f"  Warning: {e}")

        # Enter password
        print("[6] Entering password...")
        try:
            password_input = page.locator('input[type="password"], input[name="passwd"]').first
            await password_input.wait_for(state='visible', timeout=10000)
            await password_input.fill(password)
            await page.keyboard.press('Enter')
            await asyncio.sleep(3)
        except Exception as e:
            print(f"  Warning: {e}")

        # Handle TOTP/MFA if prompted
        print("[7] Checking for MFA prompt...")
        totp_secret = os.environ.get('PARALLO_TOTP_SECRET')
        try:
            # Look for TOTP input field
            totp_input = page.locator('input[name="otc"], input[aria-label*="code"], input[placeholder*="code"]').first
            if await totp_input.is_visible(timeout=5000):
                if totp_secret and pyotp:
                    totp = pyotp.TOTP(totp_secret)
                    code = totp.now()
                    print(f"    Entering TOTP code...")
                    await totp_input.fill(code)
                    await page.keyboard.press('Enter')
                    await asyncio.sleep(3)
                else:
                    print("    MFA required but no TOTP_SECRET configured!")
        except Exception:
            pass  # No MFA prompt

        # Handle "Stay signed in?" prompt
        print("[8] Handling prompts...")
        try:
            no_btn = page.locator('text=No').first
            await no_btn.click(timeout=5000)
            await asyncio.sleep(2)
        except Exception:
            pass

        # Wait for redirect back to portal
        print("[9] Waiting for portal redirect...")
        try:
            await page.wait_for_url('**/portal.parallo.support/**', timeout=30000)
        except Exception as e:
            print(f"  Redirect timeout: {e}")
            await page.screenshot(path='login_debug.png')
            print("  Saved debug screenshot to login_debug.png")

        # Navigate to reports page
        print("[10] Navigating to reports page...")
        await page.goto(REPORTS_URL)
        await asyncio.sleep(5)

        # Wait for Power BI to load and make requests
        print("[11] Waiting for Power BI to initialize...")
        for i in range(30):
            await asyncio.sleep(1)
            if mwc_token:
                print("    Got token!")
                break
            if i % 5 == 0 and i > 0:
                print(f"    Waiting... ({i}s)")

        # Final screenshot
        await page.screenshot(path='final_state.png')
        print("  Saved final state to final_state.png")

        await browser.close()

    return mwc_token, embed_token


async def main():
    print("=" * 60)
    print("Power BI Token Refresh (Browser Automation)")
    print("=" * 60)
    print()

    username = os.environ.get('PARALLO_USERNAME')
    password = os.environ.get('PARALLO_PASSWORD')
    headless = os.environ.get('HEADLESS', 'true').lower() != 'false'

    if not username or not password:
        print("Error: Set PARALLO_USERNAME and PARALLO_PASSWORD environment variables")
        return 1

    print(f"Username: {username}")
    print(f"Headless: {headless}")
    print()

    mwc_token, embed_token = await refresh_token(username, password, headless)

    if mwc_token:
        # Save the token
        with open(TOKEN_FILE, 'w') as f:
            f.write(mwc_token)
        print()
        print("=" * 60)
        print(f"[SUCCESS] Saved MWCToken to {TOKEN_FILE}")
        print("=" * 60)
        return 0
    else:
        print()
        print("=" * 60)
        print("[FAILED] Could not capture MWCToken")
        if embed_token:
            print("Got EmbedToken but not MWCToken - the report may not have loaded")
        print("Check final_state.png for debugging")
        print("=" * 60)
        return 1


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
