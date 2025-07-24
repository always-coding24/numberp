# =================================================================================
# --- Israel's C&C Bot 2: Real-time SMS Fetcher ---
# =================================================================================
# Version: 1.6 (Automatic Real-time & Persistent DB)
# Author: Israel & Gemini
# Description: This is a fully automatic, real-time bot. It continuously
#              scans for active number ranges, automatically selects the LAST
#              one in the list, and fetches its SMS messages. It uses a
#              persistent SQLite database (sms_database.db) to store hashes
#              of sent messages, preventing duplicate notifications forever,
#              even after restarts. No user input is required.
# =================================================================================

import requests
from bs4 import BeautifulSoup
import time
import re
import sys
import signal
import threading
from collections import deque
import hashlib
import sqlite3
import os

# --- Configuration ---
BOT_NAME = "Israel Dev SMS Fetcher"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "israel2411"
# IMPORTANT: This token is critical and expires. You must get a fresh one.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNDBjlo19xotbmgW3wxUELyGFCYY6cALpAgUBTdxEXaZ5Kc5TrDdnagYgYkXoXctdQNVP0sVpXKCK-3nzWL8gsS0he49ldq0zo3vPvUsyZel4U1LGQnwWS-buEdP"
DB_FILE = "sms_database.db"

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN = "8102707574:AAHGG4tI46-LqchScDK4qK8tXT6F_Uk6NQE"
GROUP_CHAT_ID_FOR_LISTS = "-1002782898597"
DM_CHAT_ID = "7253290918"

# --- API Endpoints (Verified for Polling) ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
RECEIVED_SMS_PAGE_URL = f"{BASE_URL}/portal/sms/received"
GET_SMS_RANGES_URL = f"{BASE_URL}/portal/sms/received/getsms"
GET_SMS_NUMBERS_IN_RANGE_URL = f"{BASE_URL}/portal/sms/received/getsms/number"
GET_SMS_MESSAGES_FOR_NUMBER_URL = f"{BASE_URL}/portal/sms/received/getsms/number/sms"

# --- Global variables ---
current_session = None
db_connection = None
sms_getter_stop_event = threading.Event()

def setup_database():
    """Initializes the SQLite database and creates the table if it doesn't exist."""
    global db_connection
    try:
        db_connection = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = db_connection.cursor()
        # Create table to store hashes of sent messages
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reported_sms (
                hash TEXT PRIMARY KEY
            )
        ''')
        db_connection.commit()
        print(f"[*] Database '{DB_FILE}' connected and ready.")
        return True
    except sqlite3.Error as e:
        print(f"[!!!] DATABASE ERROR: Could not connect to or set up database: {e}")
        return False

def is_sms_already_reported(sms_hash):
    """Checks the database to see if an SMS hash has already been reported."""
    try:
        cursor = db_connection.cursor()
        cursor.execute("SELECT 1 FROM reported_sms WHERE hash = ?", (sms_hash,))
        return cursor.fetchone() is not None
    except sqlite3.Error as e:
        print(f"[!] DB_CHECK_ERROR: {e}")
        return True # Assume it's reported to avoid spam on error

def add_sms_to_reported_db(sms_hash):
    """Adds a new SMS hash to the database after it has been reported."""
    try:
        cursor = db_connection.cursor()
        cursor.execute("INSERT INTO reported_sms (hash) VALUES (?)", (sms_hash,))
        db_connection.commit()
    except sqlite3.Error as e:
        print(f"[!] DB_INSERT_ERROR: {e}")

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
            print(f"[TG] Sent message to {chat_id}.")
    except Exception as e:
        print(f"[!] TELEGRAM ERROR: Could not send message. {e}")

def graceful_shutdown(signum, frame):
    """Handles Ctrl+C, closes DB connection, and exits."""
    print("\n\n[!!!] Shutdown signal detected (Ctrl+C). Bot is stopping.")
    send_telegram_message(DM_CHAT_ID, "🛑 *SMS Fetcher Shutting Down*\n\nPolling will stop.", is_operational=True)
    sms_getter_stop_event.set()
    if db_connection:
        db_connection.close()
        print("[*] Database connection closed.")
    time.sleep(2)
    sys.exit(0)

def get_polling_csrf_token(session):
    """Fetches a fresh CSRF token from the /sms/received page."""
    try:
        response = session.get(RECEIVED_SMS_PAGE_URL)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        token_tag = soup.find('meta', {'name': 'csrf-token'})
        if token_tag:
            return token_tag['content']
        raise Exception("CSRF token meta tag not found.")
    except Exception as e:
        print(f"[!] Error getting polling CSRF token: {e}")
        return None

def _process_and_report_sms(phone_number, sender_cli, message_content, range_name):
    """Hashes, checks DB, formats, and sends a single SMS to Telegram."""
    sms_hash = hashlib.md5(f"{phone_number}-{message_content}".encode('utf-8')).hexdigest()

    if not is_sms_already_reported(sms_hash):
        print(f"[+] New SMS Detected! Range: '{range_name}', Number: {phone_number}")

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
        notification_text += f"---\n life is a suya \nvip life is good \nMade by Israel Dev 😎"

        send_telegram_message(GROUP_CHAT_ID_FOR_LISTS, notification_text)
        add_sms_to_reported_db(sms_hash) # Save to DB after sending
    else:
        print(f"[*] Old SMS ignored for number {phone_number}.")


def start_automatic_polling(session):
    """Main automatic loop to check the latest range for SMS."""
    print("\n[*] Step 2: Starting Automatic Real-time SMS Polling...")
    send_telegram_message(DM_CHAT_ID, f"📡 *{BOT_NAME} Online (v1.6 Automatic)*\n\nContinuously monitoring the latest number range.", is_operational=True)

    polling_interval = 5 # seconds

    while not sms_getter_stop_event.is_set():
        try:
            print("\n[*] Refreshing list of available ranges...")
            csrf_token = get_polling_csrf_token(session)
            if not csrf_token:
                print("[!] Could not get a CSRF token. Retrying...")
                time.sleep(polling_interval)
                continue

            headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-CSRF-TOKEN': csrf_token}
            payload_ranges = {'_token': csrf_token}
            response_ranges = session.post(GET_SMS_RANGES_URL, data=payload_ranges, headers=headers)
            response_ranges.raise_for_status()
            soup_ranges = BeautifulSoup(response_ranges.text, 'html.parser')
            
            range_items = soup_ranges.find_all('div', class_='item')
            if not range_items:
                print("[*] No active number ranges found. Waiting...")
                time.sleep(polling_interval)
                continue

            # --- Automatically select the LAST range ---
            last_item = range_items[-1]
            card = last_item.find('div', class_='card', onclick=re.compile(r"getDetials\("))
            if not card: continue

            name_match = re.search(r"getDetials\('([^']+)'\)", card['onclick'])
            if not name_match: continue
            selected_range_name = name_match.group(1)
            
            print(f"[*] Automatically selected last range: '{selected_range_name}'. Checking for SMS...")

            # --- Process Only the Selected Range ---
            payload_numbers = {'_token': csrf_token, 'range': selected_range_name}
            response_numbers = session.post(GET_SMS_NUMBERS_IN_RANGE_URL, data=payload_numbers, headers=headers)
            soup_numbers = BeautifulSoup(response_numbers.text, 'html.parser')
            
            number_divs = soup_numbers.find_all('div', onclick=re.compile(r"getDetialsNumber"))
            if not number_divs:
                print(f"      - No numbers with messages found in this range.")
            else:
                print(f"      - Found {len(number_divs)} number(s). Fetching content...")

            for number_div in number_divs:
                phone_number_match = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)'", number_div['onclick'])
                if not phone_number_match: continue
                phone_number = phone_number_match.group(1)

                payload_messages = {'_token': csrf_token, 'Number': phone_number, 'Range': selected_range_name}
                response_messages = session.post(GET_SMS_MESSAGES_FOR_NUMBER_URL, data=payload_messages, headers=headers)
                soup_messages = BeautifulSoup(response_messages.text, 'html.parser')
                
                all_message_cards = soup_messages.find_all('div', class_='card-body')
                for msg_card in all_message_cards:
                    message_p = msg_card.find('p', class_='mb-0')
                    if not message_p: continue
                    message_content = message_p.get_text(strip=True)

                    sender_cli = "N/A"
                    cli_container = msg_card.find(lambda tag: tag.name == 'div' and 'CLI' in tag.text)
                    if cli_container:
                        sender_cli = cli_container.get_text(separator=' ', strip=True).replace('CLI', '').strip()

                    if message_content:
                        _process_and_report_sms(phone_number, sender_cli, message_content, selected_range_name)
            
            print(f"[*] Cycle complete. Next check in {polling_interval} seconds...")
            time.sleep(polling_interval)

        except requests.exceptions.RequestException as req_e:
            print(f"[!] Network error: {req_e}. Retrying...")
            time.sleep(polling_interval)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR: {e}. Retrying...")
            time.sleep(polling_interval)

def main():
    global current_session
    signal.signal(signal.SIGINT, graceful_shutdown)

    print("="*60)
    print("--- Israel's C&C Bot 2: SMS Fetcher (v1.6 Automatic) ---")
    print("="*60)

    if not setup_database():
        return # Stop if the database can't be set up

    if "PASTE_YOUR_NEW_FRESH_TOKEN_HERE" in MAGIC_RECAPTCHA_TOKEN:
        print("\n[!!!] FATAL ERROR: You must update the 'MAGIC_RECAPTCHA_TOKEN' variable.")
        return

    try:
        with requests.Session() as session:
            current_session = session
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
                start_automatic_polling(session)
            else:
                print("\n[!!!] AUTHENTICATION FAILED. Check token/credentials.")

    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")

if __name__ == "__main__":
    main()

