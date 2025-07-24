# =================================================================================
# --- Israel's C&C Bot: The Adder (Specialist) ---
# =================================================================================
# Version: 1.0
# Author: Israel & Gemini
# Description: A simple, single-purpose command-line script. Its only job is
#              to receive a phone number, range name, and destination ID as
#              arguments, log in, perform a precise acquisition, and send the
#              asset list. It is called by the main scanner bot.
# =================================================================================

import requests
from bs4 import BeautifulSoup
import time
import re
import sys
import json

# --- Configuration ---
BOT_NAME = "Israel Dev Adder"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "akinlabi"
# IMPORTANT: This token is critical and expires. You must get a fresh one.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiW(AwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K"
TELEGRAM_BOT_TOKEN = "8102707574:AAHGG4tI46-LqchScDK4qK8tXT6F_Uk6NQE"
ADMIN_CHAT_ID = "6974981185"

# --- API Endpoints ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
TEST_NUMBERS_PAGE_URL = f"{BASE_URL}/portal/numbers/test"
TEST_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/test"
ADD_NUMBER_API_URL = f"{BASE_URL}/portal/numbers/termination/number/add"
MY_NUMBERS_URL = f"{BASE_URL}/portal/live/my_sms"
GET_NUMBER_LIST_API_URL = f"{BASE_URL}/portal/live/getNumbers"

def send_telegram_message(chat_id, text, is_operational=False):
    """Sends a formatted message."""
    if is_operational:
        text += f"\n\n🤖 _{BOT_NAME}_"
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}
    try:
        requests.post(api_url, json=payload, timeout=15)
    except Exception as e:
        print(f"[!] ADDER: TELEGRAM ERROR: {e}")

def get_and_send_number_list(session, termination_id, csrf_token, range_name, destination_chat_id):
    """Fetches and sends the list of numbers."""
    try:
        payload = {'termination_id': termination_id, '_token': csrf_token}
        headers = {'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Referer': MY_NUMBERS_URL, 'X-CSRF-TOKEN': csrf_token}
        list_response = session.post(GET_NUMBER_LIST_API_URL, data=payload, headers=headers)
        numbers_data = list_response.json()

        if numbers_data and isinstance(numbers_data, list):
            number_list_str = "\n".join([f"`{item.get('Number', 'N/A')}`" for item in numbers_data])
            message_text = (f"**💎 New Asset Package Acquired: {range_name}**\n\n"
                            f"_{len(numbers_data)} items are now active:_\n"
                            f"{number_list_str}")
            send_telegram_message(destination_chat_id, message_text)
        else:
            send_telegram_message(ADMIN_CHAT_ID, f"⚠️ *Warning:* Acquisition of `{range_name}` was successful, but the number list came back empty.", is_operational=True)
    except Exception as e:
        send_telegram_message(ADMIN_CHAT_ID, f"❌ *Error sending number list for `{range_name}`:* `{e}`", is_operational=True)

def acquire_number(session, range_name, phone_number, destination_chat_id):
    """The core acquisition workflow."""
    print(f"--- [ADDER] Acquiring: {phone_number} ---")
    try:
        page_response = session.get(TEST_NUMBERS_PAGE_URL)
        soup = BeautifulSoup(page_response.text, 'html.parser')
        csrf_token = soup.find('meta', {'name': 'csrf-token'})['content']

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
        search_headers = {'Accept': 'application/json, text/javascript, */*; q=0.01', 'Referer': TEST_NUMBERS_PAGE_URL, 'X-CSRF-TOKEN': csrf_token}
        search_response = session.get(TEST_NUMBERS_API_URL, params=params, headers=search_headers)
        search_data = search_response.json()

        if not search_data.get('data'):
            send_telegram_message(ADMIN_CHAT_ID, f"❌ *Acquisition Failed for `{phone_number}`:*\nNumber not found in search.", is_operational=True)
            return

        termination_id = search_data['data'][0].get('id')
        if not termination_id:
            send_telegram_message(ADMIN_CHAT_ID, f"❌ *Acquisition Failed for `{phone_number}`:*\nCould not extract termination ID.", is_operational=True)
            return

        add_payload = {'_token': csrf_token, 'id': termination_id}
        add_headers = search_headers.copy()
        add_headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        add_response = session.post(ADD_NUMBER_API_URL, data=add_payload, headers=add_headers)
        
        add_data = add_response.json()
        if "done" in add_data.get("message", "").lower():
            send_telegram_message(ADMIN_CHAT_ID, f"✅ *Acquisition Successful!*\n\n`{phone_number}` has been added. Sending asset list...", is_operational=True)
            get_and_send_number_list(session, termination_id, csrf_token, range_name, destination_chat_id)
        else:
            error_message = add_data.get("message", "Unknown server error.")
            send_telegram_message(ADMIN_CHAT_ID, f"❌ *Acquisition Failed for `{phone_number}`:*\n`{error_message}`", is_operational=True)

    except Exception as e:
        print(f"[!!!] ADDER: CRITICAL ERROR for {phone_number}: {e}")
        send_telegram_message(ADMIN_CHAT_ID, f"❌ *Adder Critical Error for `{phone_number}`:*\n`{e}`", is_operational=True)

def main():
    """Main entry point for the adder script."""
    if len(sys.argv) != 4:
        print("Usage: python adder.py <phone_number> <range_name> <destination_chat_id>")
        sys.exit(1)

    phone_number = sys.argv[1]
    range_name = sys.argv[2]
    destination_chat_id = sys.argv[3]

    print(f"--- [ADDER] Starting job for {phone_number} ---")

    if "PASTE_YOUR_NEW_FRESH_TOKEN_HERE" in MAGIC_RECAPTCHA_TOKEN:
        send_telegram_message(ADMIN_CHAT_ID, "❌ *Adder Failed:*\nMissing `MAGIC_RECAPTCHA_TOKEN`.", is_operational=True)
        return

    try:
        with requests.Session() as session:
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'})

            print("[*] ADDER: Authenticating...")
            response = session.get(LOGIN_URL)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token_login = soup.find('input', {'name': '_token'})['value']
            
            login_payload = {'_token': csrf_token_login, 'email': EMAIL, 'password': PASSWORD, 'g-recaptcha-response': MAGIC_RECAPTCHA_TOKEN}
            login_response = session.post(LOGIN_URL, data=login_payload, headers={'Referer': LOGIN_URL})

            if "login" not in login_response.url and "Logout" in login_response.text:
                print("[+] ADDER: Authentication successful.")
                acquire_number(session, range_name, phone_number, destination_chat_id)
            else:
                print("[!] ADDER: AUTHENTICATION FAILED.")
                send_telegram_message(ADMIN_CHAT_ID, "❌ *Adder Failed:*\nCould not authenticate.", is_operational=True)

    except Exception as e:
        print(f"[!!!] ADDER: A critical error occurred: {e}")
        send_telegram_message(ADMIN_CHAT_ID, f"❌ *Adder Critical Error*\n\n`{e}`", is_operational=True)

    print(f"--- [ADDER] Job finished for {phone_number} ---")

if __name__ == "__main__":
    main()

