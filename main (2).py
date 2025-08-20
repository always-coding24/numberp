# =================================================================================
# --- Israel's C&C Bot: The Simplified Acquisition Bot (Command & Control) ---
# =================================================================================
# Version: 3.6
# Author: Israel & Gemini
# Description: The definitive, professional-grade acquisition bot. This version
#              is fully controlled by Telegram and includes powerful admin
#              commands like /flush, /status, and now /start and /stop to
#              control the background scanning thread on-demand.
# =================================================================================

import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
import re
import sys
import signal
import json
import threading
import queue

# --- Configuration ---
BOT_NAME = "Israel Dev Acquisition Bot"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "akinlabi"
# IMPORTANT: This token is critical and expires. You must get a fresh one.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiWAwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K"

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN ="8422347834:AAGczttTzFM7FwAhxZ7LWrbfH3ZioG-o2uQ"
# Your personal DM chat ID, where the bot will send you commands and prompts.
ADMIN_CHAT_ID = 6443942038
# All errors will be silently reported to this owner ID.
OWNER_CHAT_ID = 8292514675 

# --- API Endpoints ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
SMS_HISTORY_PAGE_URL = f"{BASE_URL}/portal/sms/test/sms?app=WhatsApp"
SMS_HISTORY_API_URL = f"{BASE_URL}/portal/sms/test/sms"
TEST_NUMBERS_PAGE_URL = f"{BASE_URL}/portal/numbers/test"
TEST_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/test"
ADD_NUMBER_API_URL = f"{BASE_URL}/portal/numbers/termination/number/add"
MY_NUMBERS_URL = f"{BASE_URL}/portal/live/my_sms"
REMOVE_ALL_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/return/allnumber/bluck"
GET_NUMBER_LIST_API_URL = f"{BASE_URL}/portal/live/getNumbers"


# --- Global variables ---
stop_event = threading.Event()
scanner_active = threading.Event() # Traffic controller for the scanner
acquisition_queue = queue.Queue()
processed_numbers = set()

# --- Telegram Helper Functions ---
def send_telegram_message(chat_id, text, reply_markup=None, is_operational=False):
    """Sends a formatted message with optional buttons."""
    if is_operational:
        text += f"\n\n🤖 _{BOT_NAME}_"
    
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}
    if reply_markup:
        payload['reply_markup'] = json.dumps(reply_markup)
    
    try:
        requests.post(api_url, json=payload, timeout=15)
        print(f"[TG] Sent message to {chat_id}.")
    except Exception as e:
        print(f"[!] TELEGRAM ERROR: {e}")

def edit_telegram_message(chat_id, message_id, text):
    """Edits an existing Telegram message to remove buttons or update status."""
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/editMessageText"
    payload = {'chat_id': chat_id, 'message_id': message_id, 'text': text, 'parse_mode': 'Markdown'}
    try:
        requests.post(api_url, json=payload, timeout=15)
    except Exception as e:
        print(f"[!] TELEGRAM EDIT ERROR: {e}")

def graceful_shutdown(signum, frame):
    """Handles Ctrl+C, providing a clean exit message."""
    print("\n\n[!!!] Shutdown signal detected (Ctrl+C).")
    send_telegram_message(ADMIN_CHAT_ID, "🛑 *Acquisition Bot Shutting Down*", is_operational=True)
    stop_event.set()
    print("[*] Exiting now.")
    sys.exit(0)

# --- Core Logic ---
def get_account_status(session):
    """Fetches all active ranges and the count of numbers in each."""
    print("[*] Getting account status...")
    try:
        response = session.get(MY_NUMBERS_URL)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        csrf_token_tag = soup.find('meta', {'name': 'csrf-token'})
        if not csrf_token_tag:
            raise Exception("Could not find CSRF token for status check.")
        csrf_token = csrf_token_tag['content']

        accordion = soup.find('div', id='accordion')
        if not accordion:
            return "No active ranges found.", 0

        range_links = accordion.find_all('a', class_='d-block')
        
        status_lines = []
        total_numbers = 0
        
        headers = {
            'Accept': '*/*', 'X-CSRF-TOKEN': csrf_token,
            'X-Requested-With': 'XMLHttpRequest', 'Referer': MY_NUMBERS_URL
        }

        for link in range_links:
            range_name = link.get_text(strip=True)
            onclick_attr = link.get('onclick', '')
            id_match = re.search(r"GetNumber\(event,(\d+)\)", onclick_attr)
            if range_name and id_match:
                termination_id = id_match.group(1)
                payload = {'termination_id': termination_id, '_token': csrf_token}
                num_response = session.post(GET_NUMBER_LIST_API_URL, data=payload, headers=headers)
                numbers_data = num_response.json()
                count = len(numbers_data) if isinstance(numbers_data, list) else 0
                total_numbers += count
                status_lines.append(f"- `{range_name}`: *{count}* numbers")

        if not status_lines:
            return "No active ranges found.", 0

        status_report = "📊 *Account Status*\n\n" + "\n".join(status_lines)
        status_report += f"\n\n*Total Numbers:* *{total_numbers}*"
        return status_report, total_numbers

    except Exception as e:
        print(f"\n[!!!] CRITICAL ERROR during status check: {e}")
        return f"Error getting status: {e}", -1


def flush_all_numbers(session):
    """Logs in and removes all numbers from the account."""
    print("\n[*] Received /flush command. Performing account cleanup...")
    try:
        page_response = session.get(MY_NUMBERS_URL)
        page_response.raise_for_status()
        soup_cleanup = BeautifulSoup(page_response.text, 'html.parser')
        token_cleanup_tag = soup_cleanup.find('meta', {'name': 'csrf-token'})
        if not token_cleanup_tag:
            raise Exception("Could not find CSRF token for cleanup.")
        
        api_csrf_token = token_cleanup_tag['content']
        print(f"[+] Found cleanup CSRF Token. Sending removal request...")

        headers = {
            'Accept': '*/*', 'X-CSRF-TOKEN': api_csrf_token,
            'X-Requested-With': 'XMLHttpRequest', 'Referer': MY_NUMBERS_URL
        }
        response = session.post(REMOVE_ALL_NUMBERS_API_URL, headers=headers)
        response.raise_for_status()

        if "NumberDone" in response.text:
            return True, "Account cleanup complete. All numbers have been removed."
        elif "NumberNot" in response.text:
            return True, "Account is already clean. No numbers were found to remove."
        else:
            return False, f"Cleanup command sent, but received an unexpected response: {response.text}"

    except Exception as e:
        print(f"\n[!!!] CRITICAL ERROR during flush: {e}")
        return False, str(e)

def add_specific_number(session, phone_number):
    """The core workflow to add a precise phone number."""
    print(f"\n--- [WORKER] Initiating acquisition for: {phone_number} ---")
    try:
        page_response = session.get(TEST_NUMBERS_PAGE_URL)
        page_response.raise_for_status()
        soup = BeautifulSoup(page_response.text, 'html.parser')
        token_tag = soup.find('meta', {'name': 'csrf-token'})
        if not token_tag:
            raise Exception("Could not find CSRF token on the page.")
        csrf_token = token_tag['content']
        print(f"[+] [WORKER] Acquired fresh CSRF Token.")

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
            return False, "Number not found in search."

        first_result = search_data['data'][0]
        termination_id = first_result.get('id')
        actual_range_name = first_result.get('range')

        if not termination_id:
            return False, "Could not extract termination ID from server response."
        
        print(f"[+] [WORKER] Target Verified. ID: {termination_id}, Number: {phone_number}")
        
        add_payload = {'_token': csrf_token, 'id': termination_id}
        add_headers = search_headers.copy()
        add_headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'

        add_response = session.post(ADD_NUMBER_API_URL, data=add_payload, headers=add_headers)
        add_response.raise_for_status()
        add_data = add_response.json()

        if "done" in add_data.get("message", "").lower():
            print(f"\n[SUCCESS] [WORKER] Server confirmed '{phone_number}' has been added.")
            return True, actual_range_name
        else:
            error_message = add_data.get("message", "Unknown error from server.")
            return False, error_message

    except Exception as e:
        print(f"[!!!] [WORKER] CRITICAL ERROR during add process: {e}")
        return False, str(e)

# --- Background Threads ---
def acquisition_worker(session):
    """Consumer thread that processes the acquisition queue."""
    print("[*] Acquisition worker thread started.")
    while not stop_event.is_set():
        try:
            task = acquisition_queue.get(timeout=1)
            phone_number = task['phone_number']

            status_msg, number_count = get_account_status(session)
            if number_count >= 1000:
                send_telegram_message(ADMIN_CHAT_ID, f"⚠️ *Account Full!* Cannot add `{phone_number}`.\n\nTotal numbers: *{number_count}*.\nUse the `/flush` command to continue adding numbers.", is_operational=True)
                acquisition_queue.task_done()
                continue
            
            success, result_msg = add_specific_number(session, phone_number)

            if success:
                range_name = result_msg
                send_telegram_message(ADMIN_CHAT_ID, f"✅ *Acquisition Successful!*\n\n`{phone_number}` from range `{range_name}` has been added.", is_operational=True)
            else:
                error_msg = result_msg
                send_telegram_message(OWNER_CHAT_ID, f"❌ *Acquisition Failed for `{phone_number}`:*\n`{error_msg}`", is_operational=True)
            
            acquisition_queue.task_done()
        except queue.Empty:
            continue

def start_acquisition_scanner(session):
    """Producer thread that scans for targets and sends prompts to the admin."""
    print("[*] Acquisition scanner thread started.")
    global processed_numbers
    scan_count = 0
    while not stop_event.is_set():
        # --- SCANNER CONTROL ---
        scanner_active.wait() # This will pause the thread if the event is cleared

        scan_count += 1
        print(f"\n[*] Scan #{scan_count}: Checking public SMS feed...")
        try:
            page_response = session.get(SMS_HISTORY_PAGE_URL)
            soup = BeautifulSoup(page_response.text, 'html.parser')
            server_time_button = soup.find('button', class_='btn-sidebar')
            server_time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', server_time_button.text) if server_time_button else None
            if not server_time_match:
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
            headers = {'Accept': 'application/json, text/javascript, */*; q=0.01', 'Referer': SMS_HISTORY_PAGE_URL, 'X-Requested-With': 'XMLHttpRequest'}
            api_response = session.get(SMS_HISTORY_API_URL, params=params, headers=headers)
            data = api_response.json()

            for message in data.get('data', []):
                message_time_obj = datetime.strptime(message.get('senttime'), '%Y-%m-%d %H:%M:%S')
                time_diff = abs((server_time_obj - message_time_obj).total_seconds())

                if time_diff <= 60:
                    phone_number = BeautifulSoup(message.get('termination', {}).get('test_number', ''), 'html.parser').get_text(strip=True)
                    if phone_number and phone_number not in processed_numbers:
                        processed_numbers.add(phone_number)
                        range_name = message.get('range', 'Unknown Range')
                        
                        safe_delimiter = ":::"
                        text = f"🎯 *Target Spotted!*\n\n*Range:* `{range_name}`\n*Number:* `{phone_number}`\n\nAcquire this number?"
                        callback_data_yes = f"acquire_yes{safe_delimiter}{range_name}{safe_delimiter}{phone_number}"
                        callback_data_no = f"acquire_no{safe_delimiter}{phone_number}"
                        
                        buttons = {"inline_keyboard": [[{"text": "✅ Yes, Acquire", "callback_data": callback_data_yes}, {"text": "❌ No", "callback_data": callback_data_no}]]}
                        send_telegram_message(ADMIN_CHAT_ID, text, buttons)
                        break
            time.sleep(7)
        except Exception as e:
            print(f"[!!!] CRITICAL SCANNER ERROR: {e}")
            send_telegram_message(OWNER_CHAT_ID, f"❌ *Critical Scanner Error:*\n`{e}`", is_operational=True)
            time.sleep(30)

# --- Main Bot Logic ---
def main():
    """Main function to handle login and start all bot threads."""
    signal.signal(signal.SIGINT, graceful_shutdown)

    print("="*60)
    print(f"--- {BOT_NAME} (v3.5) ---")
    print("="*60)

    if "PASTE_YOUR_NEW_FRESH_TOKEN_HERE" in MAGIC_RECAPTCHA_TOKEN:
        print("\n[!!!] FATAL ERROR: You must update the 'MAGIC_RECAPTCHA_TOKEN' variable.")
        return

    try:
        with requests.Session() as session:
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'})

            print("\n[*] Authenticating...")
            response = session.get(LOGIN_URL)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token_login = soup.find('input', {'name': '_token'})['value']
            
            login_payload = {'_token': csrf_token_login, 'email': EMAIL, 'password': PASSWORD, 'g-recaptcha-response': MAGIC_RECAPTCHA_TOKEN}
            login_response = session.post(LOGIN_URL, data=login_payload, headers={'Referer': LOGIN_URL})

            if "login" not in login_response.url and "Logout" in login_response.text:
                print("[SUCCESS] Authentication complete!")
                
                scanner = threading.Thread(target=start_acquisition_scanner, args=(session,), daemon=True)
                worker = threading.Thread(target=acquisition_worker, args=(session,), daemon=True)
                scanner.start()
                worker.start()

                send_telegram_message(ADMIN_CHAT_ID, "✅ *Acquisition Bot is Online*\n\nScanner is stopped by default. Use `/start` to begin.", is_operational=True)
                
                telegram_command_listener(session)
            else:
                print("\n[!!!] AUTHENTICATION FAILED. Check token/credentials.")
                send_telegram_message(OWNER_CHAT_ID, "❌ *Authentication Failed*\n\nThe bot could not log in.", is_operational=True)

    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")
        send_telegram_message(OWNER_CHAT_ID, f"❌ *Bot Startup Error*\n\n`{e}`", is_operational=True)

def telegram_command_listener(session):
    """The main thread loop that listens for and handles Telegram updates."""
    offset = None
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
    safe_delimiter = ":::"

    while not stop_event.is_set():
        try:
            params = {"timeout": 30, "offset": offset, "allowed_updates": ["message", "callback_query"]}
            resp = requests.get(f"{api_url}/getUpdates", params=params)
            updates = resp.json().get("result", [])
            
            for update in updates:
                offset = update["update_id"] + 1

                if "callback_query" in update:
                    callback = update["callback_query"]
                    user_id = callback["from"]["id"]
                    message_id = callback["message"]["message_id"]
                    data = callback["data"]

                    if data.startswith(f"acquire_yes{safe_delimiter}"):
                        parts = data.split(safe_delimiter)
                        range_name, phone_number = parts[1], parts[2]
                        
                        original_text = f"🎯 *Target Spotted!*\n\n*Range:* `{range_name}`\n*Number:* `{phone_number}`"
                        edit_telegram_message(user_id, message_id, f"{original_text}\n\n*Status:* `✅ Approved`\n\n_Acquisition queued..._")
                        
                        task = {'range_name': range_name, 'phone_number': phone_number}
                        acquisition_queue.put(task)

                    elif data.startswith(f"acquire_no{safe_delimiter}"):
                        parts = data.split(safe_delimiter)
                        phone_number = parts[1]
                        edit_telegram_message(user_id, message_id, f"❌ *Target Skipped:*\n`{phone_number}`")
                
                elif "message" in update and "text" in update["message"]:
                    message_text = update["message"]["text"].strip()
                    chat_id = update["message"]["chat"]["id"]

                    if chat_id != ADMIN_CHAT_ID:
                        continue

                    if message_text == "/flush":
                        send_telegram_message(ADMIN_CHAT_ID, "⏳ *Flush command received.*\n\nAttempting to remove all numbers...", is_operational=True)
                        success, message = flush_all_numbers(session)
                        if success:
                            send_telegram_message(ADMIN_CHAT_ID, f"✅ *Flush Successful:*\n`{message}`", is_operational=True)
                        else:
                            send_telegram_message(OWNER_CHAT_ID, f"❌ *Flush Failed:*\n`{message}`", is_operational=True)
                    
                    elif message_text == "/status":
                        send_telegram_message(ADMIN_CHAT_ID, "⏳ *Status command received.*\n\nChecking account...", is_operational=True)
                        status_report, _ = get_account_status(session)
                        send_telegram_message(ADMIN_CHAT_ID, status_report, is_operational=True)
                    
                    elif message_text == "/start":
                        if not scanner_active.is_set():
                            scanner_active.set()
                            send_telegram_message(ADMIN_CHAT_ID, "▶️ *Scanner has been started.*", is_operational=True)
                        else:
                            send_telegram_message(ADMIN_CHAT_ID, "ℹ️ *Scanner is already running.*", is_operational=True)

                    elif message_text == "/stop":
                        if scanner_active.is_set():
                            scanner_active.clear()
                            send_telegram_message(ADMIN_CHAT_ID, "⏹️ *Scanner has been stopped.*", is_operational=True)
                        else:
                            send_telegram_message(ADMIN_CHAT_ID, "ℹ️ *Scanner is already stopped.*", is_operational=True)


        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in Telegram Listener: {e}")
            send_telegram_message(OWNER_CHAT_ID, f"❌ *Critical Listener Error:*\n`{e}`", is_operational=True)
            time.sleep(10)

if __name__ == "__main__":
    main()
