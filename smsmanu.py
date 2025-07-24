# =================================================================================
# --- Israel's C&C Bot 2: Real-time SMS Fetcher ---
# =================================================================================
# Version: 1.5 (Precision Interactive Mode)
# Author: Israel & Gemini
# Description: This bot operates in an interactive mode. It scans and displays
#              a list of all available number ranges with their stats, parsed
#              with high precision based on direct HTML analysis. The user is
#              then prompted to choose a specific range to check for SMS
#              messages, allowing for targeted fetching.
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

# --- Configuration ---
BOT_NAME = "Israel Dev SMS Fetcher"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "akinlabi"
# IMPORTANT: This token is critical and expires. You must get a fresh one.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNDBjlo19xotbmgW3wxUELyGFCYY6cALpAgUBTdxEXaZ5Kc5TrDdnagYgYkXoXctdQNVP0sVpXKCK-3nzWL8gsS0he49ldq0zo3vPvUsyZel4U1LGQnwWS-buEdP"

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN = "8102707574:AAHGG4tI46-LqchScDK4qK8tXT6F_Uk6NQE"
GROUP_CHAT_ID_FOR_LISTS = "-1002687798911"
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
sms_getter_stop_event = threading.Event()
reported_sms_hashes = deque(maxlen=2000)

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
        # We only print TG notifications for operational messages to keep the console clean.
        if is_operational:
            print(f"[TG] Sent message to {chat_id}.")
    except Exception as e:
        print(f"[!] TELEGRAM ERROR: Could not send message. {e}")

def graceful_shutdown(signum, frame):
    """Handles Ctrl+C, sets the stop event, and exits."""
    print("\n\n[!!!] Shutdown signal detected (Ctrl+C). Bot is stopping.")
    send_telegram_message(DM_CHAT_ID, "🛑 *SMS Fetcher Shutting Down*\n\nPolling will stop.", is_operational=True)
    sms_getter_stop_event.set()
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
        raise Exception("CSRF token meta tag not found on the received SMS page.")
    except Exception as e:
        print(f"[!] Error getting polling CSRF token: {e}")
        return None

def _process_and_report_sms(phone_number, sender_cli, message_content, range_name):
    """Hashes, formats, and sends a single SMS to Telegram, avoiding duplicates."""
    sms_hash = hashlib.md5(f"{phone_number}-{message_content}".encode('utf-8')).hexdigest()

    if sms_hash not in reported_sms_hashes:
        reported_sms_hashes.append(sms_hash)
        print(f"[+] New SMS Detected! Range: '{range_name}', Number: {phone_number}, Sender: {sender_cli}")

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

        send_telegram_message(GROUP_CHAT_ID_FOR_LISTS, notification_text, is_operational=False)

def start_interactive_sms_getter(session):
    """The main interactive loop to choose and check a specific range."""
    print("\n[*] Step 2: Starting Interactive SMS Getter...")
    send_telegram_message(DM_CHAT_ID, f"📡 *{BOT_NAME} Online (v1.5 Interactive)*\n\nReady for your command.", is_operational=True)

    while not sms_getter_stop_event.is_set():
        try:
            # --- Stage 1: Fetch and Display Ranges for User Selection ---
            print("\n[*] Refreshing list of available ranges...")
            csrf_token = get_polling_csrf_token(session)
            if not csrf_token:
                print("[!] Could not get a CSRF token. Retrying in 15s.")
                time.sleep(15)
                continue

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-CSRF-TOKEN': csrf_token, 'Referer': RECEIVED_SMS_PAGE_URL,
            }
            payload_ranges = {'_token': csrf_token}
            response_ranges = session.post(GET_SMS_RANGES_URL, data=payload_ranges, headers=headers)
            response_ranges.raise_for_status()
            soup_ranges = BeautifulSoup(response_ranges.text, 'html.parser')
            
            available_ranges = []
            range_items = soup_ranges.find_all('div', class_='item')

            for item in range_items:
                card = item.find('div', class_='card', onclick=re.compile(r"getDetials\("))
                if not card: continue

                name_match = re.search(r"getDetials\('([^']+)'\)", card['onclick'])
                if not name_match: continue
                range_name = name_match.group(1)
                
                columns = card.find('div', class_='row').find_all('div', class_=re.compile(r'col-'))
                
                stats = []
                if len(columns) > 4:
                    for col in columns[1:5]:
                        p_tag = col.find('p')
                        if p_tag:
                            stats.append(p_tag.get_text(strip=True))
                
                if len(stats) == 4:
                    available_ranges.append({'name': range_name, 'stats': stats})

            if not available_ranges:
                print("[*] No active number ranges found. Waiting...")
                time.sleep(15)
                continue

            print("\n" + "="*40)
            print("What did I want to pick?")
            print("="*40)
            for i, range_data in enumerate(available_ranges):
                print(f"[{i + 1}] {range_data['name']}")
                for stat in range_data['stats']:
                    stat_number = re.search(r'[\d\.]+', stat)
                    if stat_number:
                        print(stat_number.group(0))
                print("-" * 20)

            # --- Stage 2: Get User Input ---
            choice_str = input("Tell me what to pick with a number: ")
            selected_range_name = ""
            try:
                choice_index = int(choice_str) - 1
                if 0 <= choice_index < len(available_ranges):
                    selected_range_name = available_ranges[choice_index]['name']
                else:
                    print("\n[!] Invalid number. Refreshing list...")
                    time.sleep(2)
                    continue
            except (ValueError, IndexError):
                print("\n[!] Invalid input. Please enter a valid number. Refreshing...")
                time.sleep(2)
                continue

            # --- Stage 3: Process Only the Selected Range ---
            print(f"\n[*] Checking selected range: '{selected_range_name}'...")
            
            payload_numbers = {'_token': csrf_token, 'range': selected_range_name}
            response_numbers = session.post(GET_SMS_NUMBERS_IN_RANGE_URL, data=payload_numbers, headers=headers)
            soup_numbers = BeautifulSoup(response_numbers.text, 'html.parser')
            
            number_divs = soup_numbers.find_all('div', onclick=re.compile(r"getDetialsNumber"))
            if not number_divs:
                print(f"      - No numbers with messages found in this range.")
            else:
                print(f"      - Found {len(number_divs)} number(s). Fetching SMS...")

            for number_div in number_divs:
                phone_number_match = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)'", number_div['onclick'])
                if not phone_number_match: continue
                phone_number = phone_number_match.group(1)

                payload_messages = {'_token': csrf_token, 'Number': phone_number, 'Range': selected_range_name}
                response_messages = session.post(GET_SMS_MESSAGES_FOR_NUMBER_URL, data=payload_messages, headers=headers)
                soup_messages = BeautifulSoup(response_messages.text, 'html.parser')
                
                all_message_cards = soup_messages.find_all('div', class_='card-body')
                for card in all_message_cards:
                    message_p = card.find('p', class_='mb-0')
                    if not message_p: continue
                    message_content = message_p.get_text(strip=True)

                    sender_cli = "N/A"
                    cli_container = card.find(lambda tag: tag.name == 'div' and 'CLI' in tag.text)
                    if cli_container:
                        sender_cli = cli_container.get_text(separator=' ', strip=True).replace('CLI', '').strip()

                    if message_content:
                        _process_and_report_sms(phone_number, sender_cli, message_content, selected_range_name)
            
            print(f"\n[*] Check complete for '{selected_range_name}'. Preparing to refresh the list...")
            time.sleep(5)

        except requests.exceptions.RequestException as req_e:
            print(f"[!] Network error: {req_e}. Retrying...")
            time.sleep(15)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR: {e}. Retrying...")
            time.sleep(15)

def main():
    global current_session
    signal.signal(signal.SIGINT, graceful_shutdown)

    print("="*60)
    print("--- Israel's C&C Bot 2: SMS Fetcher (v1.5 Interactive) ---")
    print("="*60)

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
                start_interactive_sms_getter(session)
            else:
                print("\n[!!!] AUTHENTICATION FAILED. Check token/credentials.")

    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")

if __name__ == "__main__":
    main()
