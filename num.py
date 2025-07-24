# =================================================================================
# --- Israel's C&C Bot 1: The Acquisition Bot (Telegram C&C) ---
# =================================================================================
# Version: 3.2 (Precision Scan Fix)
# Author: Israel & Gemini
# Description: This version fixes a critical scanning flaw by restoring the
#              full, proven API parameters. The scanner will now correctly
#              identify new targets. The bot remains fully multi-threaded and
#              controlled via Telegram.
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
import sqlite3
import os

# --- Configuration ---
BOT_NAME = "Israel Dev Acquisition Bot"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "akinlabi"
# IMPORTANT: This token is critical and expires. You must get a fresh one.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiWAwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K"
DB_FILE = "destinations.db"

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN = "8102707574:AAHGG4tI46-LqchScDK4qK8tXT6F_Uk6NQE"
# Your personal DM chat ID, where the bot will send you commands and prompts.
ADMIN_CHAT_ID = "6974981185"

# --- API Endpoints ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
SMS_HISTORY_PAGE_URL = f"{BASE_URL}/portal/sms/test/sms?app=WhatsApp"
SMS_HISTORY_API_URL = f"{BASE_URL}/portal/sms/test/sms"
TEST_NUMBERS_PAGE_URL = f"{BASE_URL}/portal/numbers/test"
TEST_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/test"
ADD_NUMBER_API_URL = f"{BASE_URL}/portal/numbers/termination/number/add"
MY_NUMBERS_URL = f"{BASE_URL}/portal/live/my_sms"
GET_NUMBER_LIST_API_URL = f"{BASE_URL}/portal/live/getNumbers"

# --- Global variables ---
current_session = None
stop_event = threading.Event()
acquisition_queue = queue.Queue()
# Dictionary to hold user states, e.g., {user_id: 'awaiting_destination'}
user_states = {}

# --- Database Functions ---
def setup_database():
    """Initializes the SQLite database for storing destinations."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS destinations (
                    id INTEGER PRIMARY KEY,
                    chat_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL
                )
            ''')
            conn.commit()
            print(f"[*] Database '{DB_FILE}' connected and ready.")
    except sqlite3.Error as e:
        print(f"[!!!] DATABASE ERROR: {e}")
        sys.exit(1)

def get_destinations():
    """Retrieves all saved destinations from the database."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM destinations ORDER BY name")
        return [dict(row) for row in cursor.fetchall()]

def add_destination(chat_id, name, type):
    """Adds a new destination to the database, ignoring duplicates."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO destinations (chat_id, name, type) VALUES (?, ?, ?)",
                       (chat_id, name, type))
        conn.commit()

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

# --- Core Acquisition Logic ---
def get_and_send_number_list(session, termination_id, csrf_token, range_name, destination_chat_id):
    """Fetches and sends the list of numbers to the chosen destination."""
    print(f"[*] Fetching number list for range '{range_name}'...")
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
            print(f"[+] Successfully sent {len(numbers_data)} numbers to {destination_chat_id}.")
        else:
            send_telegram_message(ADMIN_CHAT_ID, f"⚠️ *Warning:* Acquisition of `{range_name}` was successful, but the number list came back empty.", is_operational=True)
    except Exception as e:
        print(f"[!] Error sending number list: {e}")
        send_telegram_message(ADMIN_CHAT_ID, f"❌ *Error sending number list for `{range_name}`:* `{e}`", is_operational=True)

def acquire_number(session, range_name, phone_number, destination_chat_id):
    """The core acquisition workflow, now called by the worker thread."""
    print(f"--- [WORKER] Acquiring: {phone_number} ---")
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
            send_telegram_message(ADMIN_CHAT_ID, f"✅ *Acquisition Successful!*\n\n`{phone_number}` has been added. Sending asset list to destination...", is_operational=True)
            get_and_send_number_list(session, termination_id, csrf_token, range_name, destination_chat_id)
        else:
            error_message = add_data.get("message", "Unknown server error.")
            send_telegram_message(ADMIN_CHAT_ID, f"❌ *Acquisition Failed for `{phone_number}`:*\n`{error_message}`", is_operational=True)

    except Exception as e:
        print(f"[!!!] CRITICAL WORKER ERROR for {phone_number}: {e}")
        send_telegram_message(ADMIN_CHAT_ID, f"❌ *Critical Worker Error for `{phone_number}`:*\n`{e}`", is_operational=True)

# --- Background Threads ---
def acquisition_worker(session):
    """Consumer thread that processes the acquisition queue."""
    print("[*] Acquisition worker thread started.")
    while not stop_event.is_set():
        try:
            task = acquisition_queue.get(timeout=1)
            acquire_number(session, task['range_name'], task['phone_number'], task['destination_chat_id'])
            acquisition_queue.task_done()
        except queue.Empty:
            continue

def start_acquisition_scanner(session):
    """Producer thread that scans for targets and sends prompts to the admin."""
    print("[*] Acquisition scanner thread started.")
    processed_numbers = set()
    scan_count = 0
    while not stop_event.is_set():
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

            # --- DEFINITIVE FIX: Using the full, correct parameters from your proven script ---
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
            time.sleep(30)

# --- Main Bot Logic ---
def main():
    """Main function to handle login and start all bot threads."""
    global current_session
    signal.signal(signal.SIGINT, graceful_shutdown)
    setup_database()

    print("="*60)
    print(f"--- {BOT_NAME} (v3.2) ---")
    print("="*60)

    if "PASTE_YOUR_NEW_FRESH_TOKEN_HERE" in MAGIC_RECAPTCHA_TOKEN:
        print("\n[!!!] FATAL ERROR: You must update the 'MAGIC_RECAPTCHA_TOKEN' variable.")
        return

    try:
        with requests.Session() as session:
            current_session = session
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

                send_telegram_message(ADMIN_CHAT_ID, "✅ *Acquisition Bot is Online*\n\nThe scanner is now running. You will receive prompts for new targets here.", is_operational=True)
                
                telegram_command_listener()
            else:
                print("\n[!!!] AUTHENTICATION FAILED. Check token/credentials.")
                send_telegram_message(ADMIN_CHAT_ID, "❌ *Authentication Failed*\n\nThe bot could not log in.", is_operational=True)

    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")
        send_telegram_message(ADMIN_CHAT_ID, f"❌ *Bot Startup Error*\n\n`{e}`", is_operational=True)

def telegram_command_listener():
    """The main thread loop that listens for and handles Telegram updates."""
    global user_states
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
                        edit_telegram_message(user_id, message_id, f"{original_text}\n\n*Status:* `✅ Approved`\n\nPlease select a destination for the asset list:")
                        
                        destinations = get_destinations()
                        buttons = []
                        for dest in destinations:
                            buttons.append([{"text": f"{dest['name']} ({dest['type']})", "callback_data": f"dest{safe_delimiter}{dest['chat_id']}{safe_delimiter}{range_name}{safe_delimiter}{phone_number}"}])
                        buttons.append([{"text": "➡️ Enter New ID", "callback_data": f"dest_new{safe_delimiter}{range_name}{safe_delimiter}{phone_number}"}])
                        
                        send_telegram_message(user_id, "Select a destination:", {"inline_keyboard": buttons})

                    elif data.startswith(f"acquire_no{safe_delimiter}"):
                        parts = data.split(safe_delimiter)
                        phone_number = parts[1]
                        edit_telegram_message(user_id, message_id, f"❌ *Target Skipped:*\n`{phone_number}`")

                    elif data.startswith(f"dest_new{safe_delimiter}"):
                        parts = data.split(safe_delimiter)
                        range_name, phone_number = parts[1], parts[2]
                        user_states[user_id] = {'state': 'awaiting_destination', 'range': range_name, 'number': phone_number}
                        send_telegram_message(user_id, "Please send the new User or Group ID now.")

                    elif data.startswith(f"dest{safe_delimiter}"):
                        parts = data.split(safe_delimiter)
                        chat_id, range_name, phone_number = parts[1], parts[2], parts[3]
                        task = {'range_name': range_name, 'phone_number': phone_number, 'destination_chat_id': chat_id}
                        acquisition_queue.put(task)
                        send_telegram_message(user_id, f"✅ *Acquisition Queued!*\n\n*Number:* `{phone_number}`\n*Destination:* `{chat_id}`")

                elif "message" in update:
                    msg = update["message"]
                    user_id = msg["from"]["id"]
                    text = msg.get("text", "").strip()

                    if user_states.get(user_id, {}).get('state') == 'awaiting_destination':
                        if text.lstrip('-').isdigit():
                            chat_id = text
                            is_group = text.startswith('-')
                            
                            try:
                                chat_info = requests.get(f"{api_url}/getChat", params={'chat_id': chat_id}).json().get('result', {})
                                name = chat_info.get('title') or chat_info.get('username') or chat_info.get('first_name', 'Unknown')
                            except:
                                name = f"ID: {chat_id}"
                            
                            add_destination(chat_id, name, "Group" if is_group else "User")
                            
                            task_info = user_states[user_id]
                            task = {'range_name': task_info['range'], 'phone_number': task_info['number'], 'destination_chat_id': chat_id}
                            acquisition_queue.put(task)
                            
                            send_telegram_message(user_id, f"✅ *Acquisition Queued!*\n\n*Number:* `{task['phone_number']}`\n*New Destination:* `{name} ({chat_id})`")
                            del user_states[user_id]
                        else:
                            send_telegram_message(user_id, "That doesn't look like a valid ID.")

        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in Telegram Listener: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()

