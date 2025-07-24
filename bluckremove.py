# =================================================================================
# --- Israel's C&C Bot 3: Number Removal Utility ---
# =================================================================================
# Version: 1.0
# Author: Israel & Gemini
# Description: This is a standalone utility script for account maintenance.
#              Its sole purpose is to log in and make a single API call to
#              remove all currently held numbers on the account. It should be
#              run manually whenever a full cleanup is required.
# =================================================================================

import requests
from bs4 import BeautifulSoup
import sys

# --- Configuration ---
# Ensure these details match the other bots.
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "akinlabi"
# IMPORTANT: This token is critical and expires. You must get a fresh one.
# See instructions in the acquisition bot script.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNDBjlo19xotbmgW3wxUELyGFCYY6cALpAgUBTdxEXaZ5Kc5TrDdnagYgYkXoXctdQNVP0sVpXKCK-3nzWL8gsS0he49ldq0zo3vPvUsyZel4U1LGQnwWS-buEdP"

# --- API Endpoints (Verified) ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
# This is the page we need to visit to get the correct CSRF token for the removal API.
MY_NUMBERS_URL = f"{BASE_URL}/portal/live/my_sms"
# This is the specific API endpoint for bulk number removal.
REMOVE_ALL_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/return/allnumber/bluck"

def main():
    """Main function to handle login and execute the cleanup."""
    print("="*60)
    print("--- Israel's C&C Bot 3: Number Removal Utility ---")
    print("="*60)

    if "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiWAwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K" in MAGIC_RECAPTCHA_TOKEN:
        print("\n[!!!] FATAL ERROR: You must update the 'MAGIC_RECAPTCHA_TOKEN' variable.")
        print("      Follow the instructions in the other scripts to get a new one.")
        return

    try:
        with requests.Session() as session:
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0'})

            # --- Step 1: Authenticate ---
            print("\n[*] Step 1: Authenticating...")
            response = session.get(LOGIN_URL)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token_login_tag = soup.find('input', {'name': '_token'})
            if not csrf_token_login_tag:
                raise Exception("Could not find the CSRF token on the login page.")
            csrf_token_login = csrf_token_login_tag['value']

            login_payload = {
                '_token': csrf_token_login,
                'email': EMAIL,
                'password': PASSWORD,
                'g-recaptcha-response': MAGIC_RECAPTCHA_TOKEN,
                'submit': 'Log in'
            }
            login_response = session.post(LOGIN_URL, data=login_payload, headers={'Referer': LOGIN_URL})
            login_response.raise_for_status()

            if "login" in login_response.url or "Logout" not in login_response.text:
                print("\n[!!!] AUTHENTICATION FAILED. Check your ReCaptcha token and credentials.")
                sys.exit(1)

            print("[SUCCESS] Authentication complete!")

            # --- Step 2: Perform Cleanup ---
            print("\n[*] Step 2: Performing account cleanup...")
            # We must first visit the 'My Numbers' page to get the CSRF token that is valid for the removal API.
            page_response = session.get(MY_NUMBERS_URL)
            page_response.raise_for_status()
            soup_cleanup = BeautifulSoup(page_response.text, 'html.parser')
            token_cleanup_tag = soup_cleanup.find('meta', {'name': 'csrf-token'})
            if not token_cleanup_tag:
                print("[!] Could not find CSRF token for cleanup on the My Numbers page. Aborting.")
                return

            api_csrf_token = token_cleanup_tag['content']
            print(f"[+] Found cleanup CSRF Token. Sending removal request...")

            # These headers are required for the removal API call.
            headers = {
                'Accept': '*/*',
                'X-CSRF-TOKEN': api_csrf_token,
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': MY_NUMBERS_URL
            }
            # The removal API is a POST request with no payload.
            response = session.post(REMOVE_ALL_NUMBERS_API_URL, headers=headers)
            response.raise_for_status()

            # The success response is a simple string.
            if "NumberDone" in response.text:
                print("\n[SUCCESS] Account cleanup complete. All numbers have been removed.")
            elif "NumberNot" in response.text:
                 print("\n[*] Account is already clean. No numbers were found to remove.")
            else:
                print(f"\n[!] Cleanup command sent, but received an unexpected response: {response.text}")

    except Exception as e:
        print(f"\n[!!!] A critical error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

