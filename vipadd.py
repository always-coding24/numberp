# =================================================================================
# --- Israel's C&C Bot 1: The Acquisition Bot (Refined) ---
# =================================================================================
# Version: 2.2 (Precision Acquisition Fix)
# Author: Israel & Gemini
# Description: A dedicated, high-precision acquisition bot. This version uses
#              the full, correct API parameters for searching to ensure the
#              exact target number is acquired, preventing mismatches.
# =================================================================================

import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
import re
import sys
import signal

# --- Configuration ---
BOT_NAME = "Israel Dev Acquisition Bot"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "akinlabi"
# Updated with the new token provided by Israel.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNDBjlo19xotbmgW3wxUELyGFCYY6cALpAgUBTdxEXaZ5Kc5TrDdnagYgYkXoXctdQNVP0sVpXKCK-3nzWL8gsS0he49ldq0zo3vPvUsyZel4U1LGQnwWS-buEdP"

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN = "8102707574:AAHGG4tI46-LqchScDK4qK8tXT6F_Uk6NQE"
GROUP_CHAT_ID_FOR_LISTS = "-1002782898597-"#"-10026877989(11-1002845743341
DM_CHAT_ID = "-1002782898597"

# --- API Endpoints (Verified for Acquisition) ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
SMS_HISTORY_PAGE_URL = f"{BASE_URL}/portal/sms/test/sms?app=WhatsApp"
SMS_HISTORY_API_URL = f"{BASE_URL}/portal/sms/test/sms"
TEST_NUMBERS_PAGE_URL = f"{BASE_URL}/portal/numbers/test"
TEST_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/test"
ADD_NUMBER_API_URL = f"{BASE_URL}/portal/numbers/termination/number/add"
MY_NUMBERS_URL = f"{BASE_URL}/portal/live/my_sms"
GET_NUMBER_LIST_API_URL = f"{BASE_URL}/portal/live/getNumbers"

# --- Global variable for shutdown handler ---
current_session = None

def send_telegram_message(chat_id, text, is_operational=False):
    """Sends a formatted message to a specific Telegram chat ID."""
    message_to_send = text
    if is_operational:
        message_footer = f"\n\n🤖 _{BOT_NAME}_"
        message_to_send += message_footer

    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': chat_id, 'text': message_to_send, 'parse_mode': 'Markdown'}
    try:
        requests.post(api_url, json=payload, timeout=15)
        if is_operational:
            print(f"[TG] Sent operational message to {chat_id}.")
    except Exception as e:
        print(f"[!] TELEGRAM ERROR: Could not send message. {e}")

def graceful_shutdown(signum, frame):
    """Handles Ctrl+C, providing a clean exit message."""
    print("\n\n[!!!] Shutdown signal detected (Ctrl+C).")
    send_telegram_message(DM_CHAT_ID, "🛑 *Acquisition Bot Shutting Down*\n\nRun the cleanup script to remove numbers if needed.", is_operational=True)
    print("[*] Exiting now. Please run the cleanup script to remove any acquired numbers.")
    sys.exit(0)

def get_and_send_number_list(session, termination_id, csrf_token, range_name):
    """
    After a successful acquisition, this fetches the complete list of all
    numbers in that range and posts it to the group chat.
    """
    print("\n--- Fetching Full Number List for Telegram ---")
    try:
        payload = {'termination_id': termination_id, '_token': csrf_token}
        headers = {
            'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': MY_NUMBERS_URL, 'X-CSRF-TOKEN': csrf_token,
            'X-Requested-With': 'XMLHttpRequest', 'User-Agent': session.headers['User-Agent']
        }
        list_response = session.post(GET_NUMBER_LIST_API_URL, data=payload, headers=headers)
        list_response.raise_for_status()
        numbers_data = list_response.json()

        if numbers_data and isinstance(numbers_data, list):
            number_list_str = "\n".join([f"`{item.get('Number', 'N/A')}`" for item in numbers_data])
            message_text = (f"**💎 New Asset Package Acquired: {range_name}**\n\n"
                            f"_{len(numbers_data)} items are now active and being monitored:_\n"
                            f"{number_list_str}\n\n"
                            f"_SMS Fetcher will report any incoming OTPs._")
            send_telegram_message(GROUP_CHAT_ID_FOR_LISTS, message_text)
            print(f"[+] Successfully posted {len(numbers_data)} numbers to the group.")
        else:
            print("[!] The acquired number list was empty or in an unexpected format.")
    except Exception as e:
        print(f"[!] Error getting or sending the full number list: {e}")

def acquire_number(session, range_name, phone_number):
    """
    The core acquisition workflow, using the proven logic. It searches for the
    number to get its internal ID, then uses that ID to add it.
    """
    print(f"\n--- Initiating Acquisition for: {phone_number} ---")
    try:
        page_response = session.get(TEST_NUMBERS_PAGE_URL)
        page_response.raise_for_status()
        soup = BeautifulSoup(page_response.text, 'html.parser')
        token_tag = soup.find('meta', {'name': 'csrf-token'})
        if not token_tag:
            raise Exception("Could not find CSRF token on TEST_NUMBERS_PAGE_URL.")
        csrf_token = token_tag['content']
        print(f"[+] Acquired fresh CSRF Token for this operation.")

        # --- CORRECTED SEARCH PARAMETERS ---
        # Using the full, exact parameters from your working script to ensure a precise search.
        params = {
            'draw': '1', 'columns[0][data]': 'range', 'columns[1][data]': 'test_number',
            'columns[2][data]': 'term', 'columns[3][data]': 'P2P', 'columns[4][data]': 'A2P',
            'columns[5][data]': 'Limit_Range', 'columns[6][data]': 'limit_cli_a2p',
            'columns[7][data]': 'limit_did_a2p', 'columns[8][data]': 'limit_cli_did_a2p',
            'columns[9][data]': 'limit_cli_p2p', 'columns[10][data]': 'limit_did_p2p',
            'columns[11][data]': 'limit_cli_did_p2p', 'columns[12][data]': 'updated_at',
            'columns[13][data]': 'action', 'columns[13][searchable]': 'false', 'columns[13][orderable]': 'false',
            'order[0][column]': '1', 'order[0][dir]': 'asc', 'start': '0', 'length': '50',
            'search[value]': phone_number, '_': int(time.time() * 1000),
        }
        search_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': TEST_NUMBERS_PAGE_URL, 'X-CSRF-TOKEN': csrf_token,
            'X-Requested-With': 'XMLHttpRequest', 'User-Agent': session.headers['User-Agent']
        }
        search_response = session.get(TEST_NUMBERS_API_URL, params=params, headers=search_headers)
        search_response.raise_for_status()
        search_data = search_response.json()

        if not search_data.get('data'):
            print(f"[!] Search failed. Number {phone_number} may have been taken or is invalid.")
            send_telegram_message(DM_CHAT_ID, f"⚠️ *Acquisition Search Failed*\n\nThe number `{phone_number}` could not be found.", is_operational=True)
            return False

        termination_id = search_data['data'][0].get('id')
        if not termination_id:
            print(f"[!] Could not extract 'id' for {phone_number} from search results.")
            return False
        print(f"[+] Found Target Termination ID: {termination_id}")

        print(f"--- Sending 'Add' request for {phone_number} ---")
        add_payload = {'_token': csrf_token, 'id': termination_id}
        add_headers = search_headers.copy()
        add_headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'

        add_response = session.post(ADD_NUMBER_API_URL, data=add_payload, headers=add_headers)
        add_response.raise_for_status()
        add_data = add_response.json()

        if "done" in add_data.get("message", "").lower():
            print(f"[SUCCESS] Server confirmed '{phone_number}' has been added.")
            send_telegram_message(DM_CHAT_ID, f"✅ *Number Added Successfully*\n\n`{phone_number}` is now part of your assets.", is_operational=True)
            get_and_send_number_list(session, termination_id, csrf_token, range_name)
            return True
        else:
            error_message = add_data.get("message", "Unknown error from server.")
            print(f"[!] Add action FAILED: {error_message}")
            send_telegram_message(DM_CHAT_ID, f"❌ *Add Failed*\n\nCould not add `{phone_number}`. Reason: `{error_message}`", is_operational=True)
            return False

    except Exception as e:
        print(f"[!!!] CRITICAL ERROR during acquisition for {phone_number}: {e}")
        send_telegram_message(DM_CHAT_ID, f"❌ *Acquisition System Error*\n\nAn error occurred: `{e}`", is_operational=True)
        return False

def start_acquisition_scanner(session):
    """The main scanner loop. It finds fresh targets and prompts the user for action."""
    print("\n[*] Step 2: Starting interactive acquisition scanner...")
    send_telegram_message(DM_CHAT_ID, "🛰️ *Acquisition Bot is online and scanning for targets...*", is_operational=True)
    processed_numbers = set()
    scan_count = 0

    while True:
        scan_count += 1
        print(f"\n[*] Scan #{scan_count}: Checking public SMS feed for fresh targets...")
        try:
            page_response = session.get(SMS_HISTORY_PAGE_URL)
            page_response.raise_for_status()
            soup = BeautifulSoup(page_response.text, 'html.parser')

            server_time_button = soup.find('button', class_='btn-sidebar')
            server_time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', server_time_button.text) if server_time_button else None

            if not server_time_match:
                print("[!] Could not determine server time. Retrying...")
                time.sleep(10)
                continue
            server_time_obj = datetime.strptime(server_time_match.group(0), '%Y-%m-%d %H:%M:%S')

            params = {
                'app': 'WhatsApp', 'draw': '1', 'columns[0][data]': 'range', 'columns[0][orderable]': 'false',
                'columns[1][data]': 'termination.test_number', 'columns[1][searchable]': 'false', 'columns[1][orderable]': 'false',
                'columns[2][data]': 'originator', 'columns[2][orderable]': 'false', 'columns[3][data]': 'messagedata',
                'columns[3][orderable]': 'false', 'columns[4][data]': 'senttime', 'columns[4][searchable]': 'false',
                'order[0][column]': '4', 'order[0][dir]': 'desc', 'start': '0', 'length': '25', 'search[value]': '',
                '_': int(time.time() * 1000),
            }
            headers = {
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'Referer': SMS_HISTORY_PAGE_URL, 'X-Requested-With': 'XMLHttpRequest'
            }
            api_response = session.get(SMS_HISTORY_API_URL, params=params, headers=headers)
            api_response.raise_for_status()
            data = api_response.json()

            for message in data.get('data', []):
                message_time_obj = datetime.strptime(message.get('senttime'), '%Y-%m-%d %H:%M:%S')
                time_diff = abs((server_time_obj - message_time_obj).total_seconds())

                if time_diff <= 60:
                    phone_number = BeautifulSoup(message.get('termination', {}).get('test_number', ''), 'html.parser').get_text(strip=True)
                    
                    if phone_number and phone_number not in processed_numbers:
                        range_name = message.get('range', 'Unknown Range')
                        print(f"\n[!] TARGET SPOTTED! (Active within {int(time_diff)}s)")
                        print(f"    > Range: {range_name}")
                        print(f"    > Number: {phone_number}")
                        processed_numbers.add(phone_number)
                        
                        choice = input(f"[?] Do you want to acquire this number? (y/n): ").lower().strip()
                        if choice == 'y':
                            send_telegram_message(DM_CHAT_ID, f"🎯 *Acquisition Command Received*\n\nExecuting order for `{phone_number}`...", is_operational=True)
                            acquire_number(session, range_name, phone_number)
                        else:
                            print("[*] Target skipped by user.")
                        break

            time.sleep(7)

        except requests.exceptions.RequestException as req_e:
            print(f"[!!!] Network error in scanner loop: {req_e}. Retrying...")
            time.sleep(30)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in scanner loop: {e}. Retrying...")
            time.sleep(30)

def main():
    """Main function to handle login and start the acquisition bot."""
    global current_session
    signal.signal(signal.SIGINT, graceful_shutdown)

    print("="*60)
    print("--- Israel's C&C Bot 1: The Acquisition Bot (Refined) ---")
    print("="*60)

    if "PASTE_YOUR_NEW_FRESH_TOKEN_HERE" in MAGIC_RECAPTCHA_TOKEN:
        print("\n[!!!] FATAL ERROR: You must update the 'MAGIC_RECAPTCHA_TOKEN' variable.")
        send_telegram_message(DM_CHAT_ID, "❌ *Acquisition Bot Startup Failed*\n\n`MAGIC_RECAPTCHA_TOKEN` is missing.", is_operational=True)
        return

    try:
        with requests.Session() as session:
            current_session = session
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0'})

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
                send_telegram_message(DM_CHAT_ID, "🔐 *Authentication Successful*\n\nSession established.", is_operational=True)
                start_acquisition_scanner(session)
            else:
                print("\n[!!!] AUTHENTICATION FAILED. Check token/credentials.")
                send_telegram_message(DM_CHAT_ID, "❌ *Authentication Failed*\n\nThe login was rejected. Please generate a new `MAGIC_RECAPTCHA_TOKEN`.", is_operational=True)

    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")
        send_telegram_message(DM_CHAT_ID, f"❌ *Bot Startup Error*\n\nAn error occurred: `{e}`.", is_operational=True)

if __name__ == "__main__":
    main()

