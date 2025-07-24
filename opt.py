# =================================================================================
# --- Israel's C&C Bot 4: The Autobot ---
# =================================================================================
# Version: 1.4 (Final Config)
# Author: Israel & Gemini
# Description: The definitive, fully automatic bot with Israel's credentials.
#              It intelligently detects and reports new asset lists and monitors
#              all ranges for new SMS, sending them in a custom format.
# =================================================================================

import requests
from bs4 import BeautifulSoup
import time
import re
import sys
import signal
import sqlite3
import os
import threading
import hashlib
import queue

# --- Configuration ---
BOT_NAME = "Israel Dev Autobot"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "akinlabi"
# IMPORTANT: This token is critical and expires. You must get a fresh one.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiWAwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K"
DB_FILE = "sms_database.db"

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN = "8102707574:AAHGG4tI46-LqchScDK4qK8tXT6F_Uk6NQE"
# This is the hardcoded destination for all SMS and new range notifications.
DESTINATION_CHAT_ID = "-1002782898597"
# This is for operational messages (like startup/shutdown alerts).
DM_CHAT_ID = "7253290918"

# --- API Endpoints ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
MY_ACTIVE_SMS_PAGE_URL = f"{BASE_URL}/portal/live/my_sms"
GET_SMS_NUMBERS_IN_RANGE_URL = f"{BASE_URL}/portal/sms/received/getsms/number"
GET_SMS_MESSAGES_FOR_NUMBER_URL = f"{BASE_URL}/portal/sms/received/getsms/number/sms"
RECEIVED_SMS_PAGE_URL = f"{BASE_URL}/portal/sms/received"
GET_NUMBER_LIST_API_URL = f"{BASE_URL}/portal/live/getNumbers" # For fetching asset lists

# --- Global variables ---
db_connection = None
stop_event = threading.Event()
reported_sms_hashes_cache = set()
sent_ranges_cache = set()

class TelegramSender:
    """A dedicated class to handle sending messages to Telegram in a separate thread."""
    def __init__(self, token):
        self.token = token
        self.queue = queue.Queue()
        self.thread = threading.Thread(target=self._worker, daemon=True)

    def start(self):
        self.thread.start()
        print("[*] Telegram Sender thread started.")

    def _worker(self):
        while not stop_event.is_set():
            try:
                chat_id, text, item_hash, is_sms, parse_mode = self.queue.get(timeout=1)
                if self._send_message(chat_id, text, parse_mode):
                    if is_sms:
                        add_sms_to_reported_db(item_hash)
                self.queue.task_done()
            except queue.Empty:
                continue

    def _send_message(self, chat_id, text, parse_mode):
        """Sends a single message and handles rate limiting."""
        api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {'chat_id': chat_id, 'text': text, 'parse_mode': parse_mode}
        while not stop_event.is_set():
            try:
                response = requests.post(api_url, json=payload, timeout=20)
                if response.status_code == 200:
                    print(f"[TG] Successfully sent notification to {chat_id}.")
                    return True
                elif response.status_code == 429:
                    retry_after = response.json().get('parameters', {}).get('retry_after', 30)
                    print(f"[!] Telegram rate limit hit. Cooling down for {retry_after} seconds...")
                    time.sleep(retry_after)
                else:
                    print(f"[!] TELEGRAM API ERROR: Status {response.status_code}, Response: {response.text}")
                    return False
            except requests.exceptions.RequestException as e:
                print(f"[!] TELEGRAM NETWORK ERROR: {e}. Retrying in 30 seconds...")
                time.sleep(30)
        return False

    def queue_message(self, chat_id, text, item_hash=None, is_sms=False, parse_mode='Markdown'):
        """Adds a message to the sending queue."""
        self.queue.put((chat_id, text, item_hash, is_sms, parse_mode))

telegram_sender = TelegramSender(TELEGRAM_BOT_TOKEN)

def setup_database():
    """Initializes the SQLite database and loads existing data into memory."""
    global db_connection, reported_sms_hashes_cache, sent_ranges_cache
    try:
        db_connection = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = db_connection.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS reported_sms (hash TEXT PRIMARY KEY)')
        cursor.execute("SELECT hash FROM reported_sms")
        reported_sms_hashes_cache = {row[0] for row in cursor.fetchall()}
        
        cursor.execute('CREATE TABLE IF NOT EXISTS sent_ranges (name TEXT PRIMARY KEY)')
        cursor.execute("SELECT name FROM sent_ranges")
        sent_ranges_cache = {row[0] for row in cursor.fetchall()}
        
        db_connection.commit()
        print(f"[*] Database '{DB_FILE}' connected.")
        print(f"    > Loaded {len(reported_sms_hashes_cache)} SMS hashes.")
        print(f"    > Loaded {len(sent_ranges_cache)} sent range names.")
        return True
    except sqlite3.Error as e:
        print(f"[!!!] DATABASE ERROR: {e}")
        return False

def add_sms_to_reported_db(sms_hash):
    """Adds a new SMS hash to the database."""
    try:
        cursor = db_connection.cursor()
        cursor.execute("INSERT OR IGNORE INTO reported_sms (hash) VALUES (?)", (sms_hash,))
        db_connection.commit()
    except sqlite3.Error as e:
        print(f"[!] DB_INSERT_ERROR (SMS): {e}")

def add_ranges_to_sent_db(range_names):
    """Adds a list of new range names to the database."""
    try:
        cursor = db_connection.cursor()
        cursor.executemany("INSERT OR IGNORE INTO sent_ranges (name) VALUES (?)", [(name,) for name in range_names])
        db_connection.commit()
    except sqlite3.Error as e:
        print(f"[!] DB_INSERT_ERROR (Ranges): {e}")

def send_operational_message(chat_id, text, add_footer=True):
    """Sends a non-queued, immediate operational message."""
    message_to_send = text
    if add_footer:
        message_to_send += f"\n\n🤖 _{BOT_NAME}_"
    
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': chat_id, 'text': message_to_send, 'parse_mode': 'Markdown'}
    try:
        requests.post(api_url, json=payload, timeout=15)
        print(f"[TG] Sent operational message to {chat_id}.")
    except Exception as e:
        print(f"[!] TELEGRAM ERROR (Operational): {e}")

def graceful_shutdown(signum, frame):
    """Handles Ctrl+C for a clean exit."""
    print("\n\n[!!!] Shutdown signal detected. Bot is stopping.")
    send_operational_message(DM_CHAT_ID, "🛑 *Autobot Shutting Down*")
    stop_event.set()
    if db_connection:
        db_connection.close()
        print("[*] Database connection closed.")
    time.sleep(2)
    sys.exit(0)

def get_polling_csrf_token(session):
    """Fetches a fresh CSRF token for API calls."""
    try:
        response = session.get(MY_ACTIVE_SMS_PAGE_URL, timeout=20)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        token_tag = soup.find('meta', {'name': 'csrf-token'})
        if token_tag:
            return token_tag['content']
        raise Exception("CSRF token meta tag not found.")
    except Exception as e:
        print(f"[!] Error getting CSRF token: {e}")
        return None

def get_and_queue_number_list(session, termination_id, csrf_token, range_name):
    """Fetches the full list of numbers for a new range and queues it for sending."""
    try:
        payload = {'termination_id': termination_id, '_token': csrf_token}
        headers = {'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Referer': MY_ACTIVE_SMS_PAGE_URL, 'X-CSRF-TOKEN': csrf_token}
        list_response = session.post(GET_NUMBER_LIST_API_URL, data=payload, headers=headers)
        numbers_data = list_response.json()

        if numbers_data and isinstance(numbers_data, list):
            number_list_str = "\n".join([f"`{item.get('Number', 'N/A')}`" for item in numbers_data])
            message_text = (f"**💎 New Asset Package Detected: {range_name}**\n\n"
                            f"_{len(numbers_data)} items are now being monitored:_\n"
                            f"{number_list_str}")
            telegram_sender.queue_message(DESTINATION_CHAT_ID, message_text)
    except Exception as e:
        print(f"[!] Error fetching number list for new range '{range_name}': {e}")

def _process_and_queue_sms(phone_number, message_content, range_name):
    """Processes a single SMS and queues it for sending with the custom format."""
    global reported_sms_hashes_cache
    sms_hash = hashlib.md5(f"{phone_number}-{message_content}".encode('utf-8')).hexdigest()

    if sms_hash not in reported_sms_hashes_cache:
        reported_sms_hashes_cache.add(sms_hash)
        print(f"[+] New SMS Queued! Range: '{range_name}', Number: {phone_number}")

        # Use HTML tags for clean formatting and to prevent Markdown errors
        notification_text = (
            f"From: <b>{range_name}</b>\n"
            f"For: <code>{phone_number}</code>\n"
            f"Full message: <code>{message_content}</code>\n"
            f"--- \n"
            f"Life is a suya\n"
            f"--- \n"
            f"Developed by Israel Dev @israeldev001"
        )
        
        telegram_sender.queue_message(DESTINATION_CHAT_ID, notification_text, sms_hash, is_sms=True, parse_mode='HTML')

def start_automatic_monitor(session):
    """Main automatic loop to scan all active ranges."""
    polling_interval = 5
    
    while not stop_event.is_set():
        try:
            print("\n[*] Scanning for all active ranges...")
            response = session.get(MY_ACTIVE_SMS_PAGE_URL, timeout=20)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            current_active_ranges = {}
            accordion = soup.find('div', id='accordion')
            if accordion:
                range_links = accordion.find_all('a', class_='d-block')
                for link in range_links:
                    range_name = link.get_text(strip=True)
                    onclick_attr = link.get('onclick', '')
                    id_match = re.search(r"GetNumber\(event,(\d+)\)", onclick_attr)
                    if range_name and id_match:
                        current_active_ranges[range_name] = id_match.group(1)

            if not current_active_ranges:
                print("[*] No active ranges found. Waiting...")
                time.sleep(polling_interval)
                continue
            
            csrf_token = get_polling_csrf_token(session)
            if not csrf_token:
                time.sleep(polling_interval)
                continue
            
            newly_added_range_names = set(current_active_ranges.keys()) - sent_ranges_cache
            if newly_added_range_names:
                print(f"[+] Detected {len(newly_added_range_names)} new range(s). Fetching number lists...")
                for new_range in newly_added_range_names:
                    termination_id = current_active_ranges[new_range]
                    get_and_queue_number_list(session, termination_id, csrf_token, new_range)
                
                sent_ranges_cache.update(newly_added_range_names)
                add_ranges_to_sent_db(newly_added_range_names)

            print(f"[*] Found {len(current_active_ranges)} active range(s). Checking each for new messages...")
            
            headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-CSRF-TOKEN': csrf_token}

            for target_range in current_active_ranges:
                if stop_event.is_set(): break
                print(f"    > Checking range: '{target_range}'")
                payload_numbers = {'_token': csrf_token, 'range': target_range}
                response_numbers = session.post(GET_SMS_NUMBERS_IN_RANGE_URL, data=payload_numbers, headers=headers)
                soup_numbers = BeautifulSoup(response_numbers.text, 'html.parser')
                
                number_divs = soup_numbers.find_all('div', onclick=re.compile(r"getDetialsNumber"))
                for number_div in number_divs:
                    phone_match = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)'", number_div['onclick'])
                    if not phone_match: continue
                    phone_number = phone_match.group(1)

                    payload_messages = {'_token': csrf_token, 'Number': phone_number, 'Range': target_range}
                    response_messages = session.post(GET_SMS_MESSAGES_FOR_NUMBER_URL, data=payload_messages, headers=headers)
                    soup_messages = BeautifulSoup(response_messages.text, 'html.parser')
                    
                    for card in soup_messages.find_all('div', class_='card-body'):
                        p_tag = card.find('p', class_='mb-0')
                        if p_tag:
                            msg_content = p_tag.get_text(strip=True)
                            if msg_content:
                                _process_and_queue_sms(phone_number, msg_content, target_range)
            
            print(f"[*] Scan cycle complete. Next scan in {polling_interval} seconds.")
            time.sleep(polling_interval)

        except requests.exceptions.RequestException as req_e:
            print(f"[!] Network error: {req_e}. Retrying...")
            time.sleep(polling_interval)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in main loop: {e}. Retrying...")
            time.sleep(polling_interval)

def main():
    """Main function to handle setup, login, and start the bot."""
    signal.signal(signal.SIGINT, graceful_shutdown)

    print("="*60)
    print(f"--- {BOT_NAME} (v1.4) ---")
    print("="*60)

    if not setup_database(): return
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
            
            login_payload = {'_token': csrf_token_login, 'email': EMAIL, 'password': PASSWORD, 'g-recaptcha-response': MAGIC_RECAPTCHA_TOKEN}
            login_response = session.post(LOGIN_URL, data=login_payload, headers={'Referer': LOGIN_URL})

            if "login" not in login_response.url and "Logout" in login_response.text:
                print("[SUCCESS] Authentication complete!")
                
                startup_message = f"🚀 *{BOT_NAME} is Online* 🚀\n\nNow monitoring all active ranges in real-time. New SMS and newly added ranges will be reported here."
                send_operational_message(DESTINATION_CHAT_ID, startup_message, add_footer=False)
                send_operational_message(DM_CHAT_ID, "✅ *Autobot Started Successfully*")

                telegram_sender.start()
                start_automatic_monitor(session)
            else:
                print("\n[!!!] AUTHENTICATION FAILED. Check token/credentials.")
                send_operational_message(DM_CHAT_ID, "❌ *Autobot Authentication Failed*")

    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")
        send_operational_message(DM_CHAT_ID, f"❌ *Autobot Startup Error*\n\n`{e}`")

if __name__ == "__main__":
    main()

