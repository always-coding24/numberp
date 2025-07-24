# =================================================================================
# --- Israel's C&C Bot 3: Live SMS Inspector ---
# =================================================================================
# Version: 1.0
# Author: Israel & Gemini
# Description: This tool inspects the 'Client Active SMS' page. It fetches
#              all currently added number ranges, displays them in a list for
#              the user to choose from, and then fetches and displays all the
#              specific numbers within the selected range.
# =================================================================================

import requests
from bs4 import BeautifulSoup
import time
import re
import sys
import signal

# --- Configuration ---
BOT_NAME = "Israel Dev Live SMS Inspector"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "akinlabi"
# IMPORTANT: This token is critical and expires. You must get a fresh one.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNDBjlo19xotbmgW3wxUELyGFCYY6cALpAgUBTdxEXaZ5Kc5TrDdnagYgYkXoXctdQNVP0sVpXKCK-3nzWL8gsS0he49ldq0zo3vPvUsyZel4U1LGQnwWS-buEdP"

# --- API Endpoints ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
# The target page for this bot
LIVE_SMS_PAGE_URL = f"{BASE_URL}/portal/live/my_sms"
# The API endpoint to get numbers for a specific range
GET_NUMBERS_API_URL = f"{BASE_URL}/portal/live/getNumbers"


def graceful_shutdown(signum, frame):
    """Handles Ctrl+C for a clean exit."""
    print("\n\n[!!!] Shutdown signal detected. Exiting.")
    sys.exit(0)

def get_and_display_numbers(session, termination_id, csrf_token):
    """Fetches and displays the numbers for a selected termination ID."""
    print("\n[*] Fetching numbers for the selected range...")
    try:
        payload = {'termination_id': termination_id, '_token': csrf_token}
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': LIVE_SMS_PAGE_URL,
            'X-CSRF-TOKEN': csrf_token,
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': session.headers['User-Agent']
        }
        
        response = session.post(GET_NUMBERS_API_URL, data=payload, headers=headers)
        response.raise_for_status()
        numbers_data = response.json()

        if numbers_data and isinstance(numbers_data, list):
            print("\n" + "="*40)
            print("--- Active Numbers in Selected Range ---")
            for number_info in numbers_data:
                print(f"  `{number_info.get('Number', 'N/A')}`")
            print("="*40)
        else:
            print("[!] No numbers found for this range, or the response was empty.")

    except Exception as e:
        print(f"[!!!] CRITICAL ERROR while fetching numbers: {e}")


def start_inspector(session):
    """
    Main interactive loop to list ranges and let the user inspect them.
    """
    while True:
        try:
            print("\n[*] Refreshing list of active ranges from 'Client Active SMS' page...")
            
            # Navigate to the page to get its content and a valid CSRF token
            response = session.get(LIVE_SMS_PAGE_URL)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            csrf_token_tag = soup.find('meta', {'name': 'csrf-token'})
            if not csrf_token_tag:
                print("[!] Could not find CSRF token on the page. Cannot proceed.")
                return
            csrf_token = csrf_token_tag['content']

            # Find the accordion container and extract all ranges
            accordion = soup.find('div', id='accordion')
            if not accordion:
                print("[!] No ranges found. The 'accordion' container is missing.")
                time.sleep(15)
                continue

            range_links = accordion.find_all('a', class_='d-block')
            
            available_ranges = []
            for link in range_links:
                range_name = link.get_text(strip=True)
                onclick_attr = link.get('onclick', '')
                id_match = re.search(r"GetNumber\(event,(\d+)\)", onclick_attr)
                if range_name and id_match:
                    available_ranges.append({
                        'name': range_name,
                        'id': id_match.group(1)
                    })

            if not available_ranges:
                print("[*] No active ranges found on the page.")
                time.sleep(15)
                continue

            # Display the list of ranges for the user to pick
            print("\n" + "="*40)
            print("--- Your Active Ranges ---")
            for i, range_data in enumerate(available_ranges):
                print(f"  [{i + 1}] {range_data['name']}")
            print("="*40)

            # Get user input
            choice_str = input("Enter the number of the range to inspect (or 'q' to quit): ")
            
            if choice_str.lower() == 'q':
                print("[*] Exiting inspector.")
                break

            try:
                choice_index = int(choice_str) - 1
                if 0 <= choice_index < len(available_ranges):
                    selected_range = available_ranges[choice_index]
                    get_and_display_numbers(session, selected_range['id'], csrf_token)
                else:
                    print("\n[!] Invalid number. Please try again.")
            except (ValueError, IndexError):
                print("\n[!] Invalid input. Please enter a number from the list.")

            input("\nPress Enter to refresh the list and choose another range...")

        except requests.exceptions.RequestException as req_e:
            print(f"[!] Network error: {req_e}. Retrying...")
            time.sleep(15)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in main loop: {e}. Retrying...")
            time.sleep(15)


def main():
    """Main function to handle login and start the inspector bot."""
    signal.signal(signal.SIGINT, graceful_shutdown)

    print("="*60)
    print(f"--- {BOT_NAME} (v1.0) ---")
    print("="*60)

    if "PASTE_YOUR_NEW_FRESH_TOKEN_HERE" in MAGIC_RECAPTCHA_TOKEN:
        print("\n[!!!] FATAL ERROR: You must update the 'MAGIC_RECAPTCHA_TOKEN' variable.")
        return

    try:
        with requests.Session() as session:
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'})

            print("\n[*] Step 1: Authenticating...")
            response = session.get(LOGIN_URL)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token_login = soup.find('input', {'name': '_token'})['value']
            
            login_payload = {
                '_token': csrf_token_login, 'email': EMAIL, 'password': PASSWORD,
                'g-recaptcha-response': MAGIC_RECAPTCHA_TOKEN,
            }
            login_response = session.post(LOGIN_URL, data=login_payload, headers={'Referer': LOGIN_URL})

            if "login" not in login_response.url and "Logout" in login_response.text:
                print("[SUCCESS] Authentication complete!")
                start_inspector(session)
            else:
                print("\n[!!!] AUTHENTICATION FAILED. Check token/credentials.")

    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")

if __name__ == "__main__":
    main()
