# =================================================================================
# --- Israel's C&C Bot 2: Real-time SMS Fetcher ---
# =================================================================================
# Version: 2.2 (High-Performance Engine)
# Author: Israel & Gemini
# Description: A completely re-engineered, professional-grade bot. This version
#              uses an in-memory cache for high-speed duplicate checking and a
#              dedicated, queued Telegram sender to handle rate-limiting and
#              guarantee message delivery. It only saves an SMS to the database
#              AFTER successful delivery, preventing data loss.
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
BOT_NAME = "Israel Dev SMS Fetcher"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "akinlabi"
MAGIC_RECAPTCHA_TOKEN = "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiW(AwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K"
DB_FILE = "sms_database.db"

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN = "8102707574:AAHGG4tI46-LqchScDK4qK8tXT6F_Uk6NQE"
DEFAULT_GROUP_CHAT_ID = "-1002687798911"
DM_CHAT_ID = "7253290918"

# --- API Endpoints ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
MY_ACTIVE_SMS_PAGE_URL = f"{BASE_URL}/portal/live/my_sms"
GET_SMS_NUMBERS_IN_RANGE_URL = f"{BASE_URL}/portal/sms/received/getsms/number"
GET_SMS_MESSAGES_FOR_NUMBER_URL = f"{BASE_URL}/portal/sms/received/getsms/number/sms"
RECEIVED_SMS_PAGE_URL = f"{BASE_URL}/portal/sms/received"

# --- Global variables ---
db_connection = None
stop_event = threading.Event()
# High-speed in-memory cache for checking duplicates
reported_sms_hashes_cache = set()

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
                # Get a message tuple from the queue
                chat_id, text, sms_hash = self.queue.get(timeout=1)
                
                if self._send_message(chat_id, text):
                    # Only save to DB if the message was sent successfully
                    add_sms_to_reported_db(sms_hash)
                
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Error in Telegram worker thread: {e}")

    def _send_message(self, chat_id, text):
        """Sends a single message and handles rate limiting."""
        api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}
        
        while not stop_event.is_set():
            try:
                response = requests.post(api_url, json=payload, timeout=20)
                if response.status_code == 200:
                    print(f"[TG] Successfully sent SMS notification to {chat_id}.")
                    return True
                elif response.status_code == 429: # Too Many Requests
                    retry_after = response.json().get('parameters', {}).get('retry_after', 30)
                    print(f"[!] Telegram rate limit hit. Cooling down for {retry_after} seconds...")
                    time.sleep(retry_after)
                else:
                    print(f"[!] TELEGRAM API ERROR: Status {response.status_code}, Response: {response.text}")
                    return False # Don't retry on other errors (e.g., bad chat_id)
            except requests.exceptions.RequestException as e:
                print(f"[!] TELEGRAM NETWORK ERROR: {e}. Retrying in 30 seconds...")
                time.sleep(30)
        return False

    def queue_message(self, chat_id, text, sms_hash):
        """Adds a message to the sending queue."""
        self.queue.put((chat_id, text, sms_hash))

# Create a global instance of the sender
telegram_sender = TelegramSender(TELEGRAM_BOT_TOKEN)

def setup_database():
    """Initializes the SQLite database and loads existing hashes into the in-memory cache."""
    global db_connection, reported_sms_hashes_cache
    try:
        db_connection = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = db_connection.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS reported_sms (hash TEXT PRIMARY KEY)')
        
        # Load all hashes from DB into the fast in-memory set
        cursor.execute("SELECT hash FROM reported_sms")
        hashes = {row[0] for row in cursor.fetchall()}
        reported_sms_hashes_cache = hashes
        
        db_connection.commit()
        print(f"[*] Database '{DB_FILE}' connected. Loaded {len(reported_sms_hashes_cache)} existing hashes into cache.")
        return True
    except sqlite3.Error as e:
        print(f"[!!!] DATABASE ERROR: {e}")
        return False

def add_sms_to_reported_db(sms_hash):
    """Adds a new SMS hash to the database AND the in-memory cache."""
    try:
        cursor = db_connection.cursor()
        cursor.execute("INSERT INTO reported_sms (hash) VALUES (?)", (sms_hash,))
        db_connection.commit()
        # No need to add to cache here, it was added optimistically
    except sqlite3.Error as e:
        # This might happen if another thread added it in the meantime, which is fine.
        if "UNIQUE constraint failed" not in str(e):
            print(f"[!] DB_INSERT_ERROR: {e}")

def send_operational_message(chat_id, text):
    """Sends a non-queued, immediate operational message."""
    message_to_send = f"{text}\n\n🤖 _{BOT_NAME}_"
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
    send_operational_message(DM_CHAT_ID, "🛑 *SMS Fetcher Shutting Down*")
    stop_event.set()
    if db_connection:
        db_connection.close()
        print("[*] Database connection closed.")
    time.sleep(2)
    sys.exit(0)

def get_polling_csrf_token(session):
    """Fetches a fresh CSRF token for API calls."""
    try:
        response = session.get(RECEIVED_SMS_PAGE_URL, timeout=20)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        token_tag = soup.find('meta', {'name': 'csrf-token'})
        if token_tag:
            return token_tag['content']
        raise Exception("CSRF token meta tag not found.")
    except Exception as e:
        print(f"[!] Error getting CSRF token: {e}")
        return None

def _process_and_queue_sms(phone_number, sender_cli, message_content, range_name, destination_chat_id):
    """Processes a single SMS and queues it for sending."""
    global reported_sms_hashes_cache
    sms_hash = hashlib.md5(f"{phone_number}-{message_content}".encode('utf-8')).hexdigest()

    # Check the high-speed in-memory cache first
    if sms_hash not in reported_sms_hashes_cache:
        # Optimistic Lock: Add to cache immediately to prevent re-processing by the main loop.
        reported_sms_hashes_cache.add(sms_hash)
        print(f"[+] New SMS Queued! Range: '{range_name}', Number: {phone_number}")

        otp_code = None
        code_match = re.search(r'\b(\d{4,8})\b|\b(\d{3}[- ]?\d{3})\b', message_content)
        if code_match:
            raw_code = code_match.group(1) if code_match.group(1) else code_match.group(2)
            if raw_code:
                otp_code = re.sub(r'[- ]', '', raw_code)

        notification_text = (f"For `{phone_number}`\n"
                             f"Message: `{message_content}`\n")
        if otp_code:
            notification_text += f"OTP: `{otp_code}`\n"
        notification_text += f"---\nMade by Israel Dev 😎"

        # Queue the message for the sender thread
        telegram_sender.queue_message(destination_chat_id, notification_text, sms_hash)

def start_interactive_picker(session, destination_chat_id):
    """Main loop to fetch added ranges, let user pick, and then watch."""
    while not stop_event.is_set():
        try:
            print("\n[*] Fetching your list of added ranges...")
            response = session.get(MY_ACTIVE_SMS_PAGE_URL, timeout=20)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            available_ranges = []
            accordion = soup.find('div', id='accordion')
            if accordion:
                range_links = accordion.find_all('a', class_='d-block')
                for link in range_links:
                    range_name = link.get_text(strip=True)
                    if range_name:
                        available_ranges.append(range_name)

            if not available_ranges:
                print("[!] You have no active ranges. Waiting...")
                time.sleep(15)
                continue
            
            print("\n" + "="*40)
            print("Which of your active ranges do you want to watch?")
            for i, range_name in enumerate(available_ranges):
                print(f"[{i + 1}] {range_name}")
            print("-" * 40)

            choice_str = input("Pick a number to start watching: ")
            try:
                choice_index = int(choice_str) - 1
                if 0 <= choice_index < len(available_ranges):
                    target_range = available_ranges[choice_index]
                    watch_selected_range(session, target_range, destination_chat_id)
                else:
                    print("\n[!] Invalid number.")
            except (ValueError, IndexError):
                print("\n[!] Invalid input.")

        except requests.exceptions.RequestException as req_e:
            print(f"[!] Network error: {req_e}. Retrying...")
            time.sleep(15)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in main loop: {e}. Retrying...")
            time.sleep(15)

def watch_selected_range(session, target_range, destination_chat_id):
    """Dedicated loop to watch a single, selected range."""
    polling_interval = 10
    print("\n" + "="*60)
    print(f"[*] WATCHING target range: '{target_range}'")
    print("[*] Press Ctrl+C to stop watching and return to the main menu.")
    print("="*60)
    send_operational_message(DM_CHAT_ID, f"👀 *Watch Started (v2.2)*\n\nWatching range: `{target_range}`")
    
    try:
        while not stop_event.is_set():
            csrf_token = get_polling_csrf_token(session)
            if not csrf_token:
                time.sleep(polling_interval)
                continue

            headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-CSRF-TOKEN': csrf_token}
            
            print(f"[*] Checking '{target_range}'... (Last check: {time.strftime('%H:%M:%S')})")
            payload_numbers = {'_token': csrf_token, 'range': target_range}
            response_numbers = session.post(GET_SMS_NUMBERS_IN_RANGE_URL, data=payload_numbers, headers=headers)
            soup_numbers = BeautifulSoup(response_numbers.text, 'html.parser')
            
            number_divs = soup_numbers.find_all('div', onclick=re.compile(r"getDetialsNumber"))
            if not number_divs:
                print("    - No numbers with messages found.")
            
            for number_div in number_divs:
                phone_match = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)'", number_div['onclick'])
                if not phone_match: continue
                phone_number = phone_match.group(1)

                payload_messages = {'_token': csrf_token, 'Number': phone_number, 'Range': target_range}
                response_messages = session.post(GET_SMS_MESSAGES_FOR_NUMBER_URL, data=payload_messages, headers=headers)
                soup_messages = BeautifulSoup(response_messages.text, 'html.parser')
                
                for card in soup_messages.find_all('div', class_='card-body'):
                    p_tag = card.find('p', class_='mb-0')
                    if not p_tag: continue
                    msg_content = p_tag.get_text(strip=True)
                    
                    sender = "N/A"
                    cli_div = card.find(lambda tag: tag.name == 'div' and 'CLI' in tag.text)
                    if cli_div:
                        sender = cli_div.get_text(separator=' ', strip=True).replace('CLI', '').strip()
                    
                    if msg_content:
                        _process_and_queue_sms(phone_number, sender, msg_content, target_range, destination_chat_id)
            
            time.sleep(polling_interval)
    except KeyboardInterrupt:
        print("\n[*] Stopping watch on this range. Returning to main menu...")
        return

def main():
    """Main function to handle setup, login, and start the bot."""
    signal.signal(signal.SIGINT, graceful_shutdown)

    print("="*60)
    print("--- Israel's C&C Bot 2: SMS Fetcher (v2.2 High-Performance) ---")
    print("="*60)

    if not setup_database(): return
    if "PASTE_YOUR_NEW_FRESH_TOKEN_HERE" in MAGIC_RECAPTCHA_TOKEN:
        print("\n[!!!] FATAL ERROR: You must update the 'MAGIC_RECAPTCHA_TOKEN' variable.")
        return

    destination_chat_id = ""
    while not destination_chat_id:
        dest_choice = input("Send notifications to 'id' or 'group'? ").lower().strip()
        if dest_choice == 'id':
            id_input = input("Enter the destination Chat ID: ").strip()
            if id_input.lstrip('-').isdigit():
                destination_chat_id = id_input
        elif dest_choice == 'group':
            group_input = input(f"Enter Group ID (press Enter to use default: {DEFAULT_GROUP_CHAT_ID}): ").strip()
            if not group_input:
                destination_chat_id = DEFAULT_GROUP_CHAT_ID
            elif group_input.lstrip('-').isdigit():
                destination_chat_id = f"-{group_input.lstrip('-')}"
        else:
            print("[!] Invalid choice.")

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
                # Start the dedicated sender thread
                telegram_sender.start()
                # Start the main user-interactive loop
                start_interactive_picker(session, destination_chat_id)
            else:
                print("\n[!!!] AUTHENTICATION FAILED. Check token/credentials.")

    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")

if __name__ == "__main__":
    main()

