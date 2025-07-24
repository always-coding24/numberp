import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
import re
import sys
import signal
import threading

# =================================================================================
# --- Israel's Final Command & Control Bot ---
# =================================================================================
# Version: FINAL
# Author: Israel & Gemini
# Description: This is the definitive bot, built on the exact proven logic
#              provided by Israel. It features an interactive acquisition loop
#              and a separate, stable Telegram Group Assistant that replies
#              dynamically to any group it's in.
# =================================================================================

# --- Configuration ---
BOT_NAME = "Israel Dev paid numbers"
EMAIL = "akinlabiisreal24@gmail.com"
PASSWORD = "israel2411"
# You may need to generate a new token if you get authentication errors.
# IMPORTANT: Replace this with a fresh token obtained from a browser session
# on the ivasms.com login page. E.g., using developer tools, network tab,
# copy the g-recaptcha-response value from a successful login request.
MAGIC_RECAPTCHA_TOKEN = "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiWAwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K" 

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN = "8102707574:AAHGG4tI46-LqchScDK4qK8tXT6F_Uk6NQE" 
# The Group ID is ONLY for posting the main asset list.
# The on-demand code checker will reply to whatever group it gets a message from.
GROUP_CHAT_ID_FOR_LISTS = "-1002687798911" 
# Your personal DM chat ID for private operational messages.
DM_CHAT_ID = "7253290918"

# --- API Endpoints (Verified) ---
BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
# SMS_HISTORY_PAGE_URL and SMS_HISTORY_API_URL are kept for the Telegram listener
# which still uses this general SMS history for on-demand checks.
SMS_HISTORY_PAGE_URL = f"{BASE_URL}/portal/sms/test/sms?app=WhatsApp"
SMS_HISTORY_API_URL = f"{BASE_URL}/portal/sms/test/sms"
TEST_NUMBERS_PAGE_URL = f"{BASE_URL}/portal/numbers/test"
TEST_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/test"
ADD_NUMBER_API_URL = f"{BASE_URL}/portal/numbers/termination/number/add"
MY_NUMBERS_URL = f"{BASE_URL}/portal/live/my_sms"
GET_NUMBER_LIST_API_URL = f"{BASE_URL}/portal/live/getNumbers"
REMOVE_ALL_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/return/allnumber/bluck"

# --- New API Endpoints for Real-time OTP Fetcher ---
# This is the main page for "Received SMS" from which we'll fetch tokens and initiate requests.
RECEIVED_SMS_PAGE_URL = f"{BASE_URL}/portal/sms/received" 
GET_SMS_RANGES_URL = f"{BASE_URL}/portal/sms/received/getsms"
GET_SMS_NUMBERS_IN_RANGE_URL = f"{BASE_URL}/portal/sms/received/getsms/number"
GET_SMS_MESSAGES_FOR_NUMBER_URL = f"{BASE_URL}/portal/sms/received/getsms/number/sms"


# --- Global variables for the shutdown handler ---
current_session = None
# This CSRF token will primarily be used for "My Numbers" and "Test Numbers" API calls.
# A more specific token is fetched for the /sms/received endpoints.
api_csrf_token = None 

# =================================================================================
# --- Core Bot & Helper Functions ---
# =================================================================================

def send_telegram_message(chat_id, text, is_operational=False):
    """Sends a formatted message to a specific chat ID."""
    message_to_send = text
    if is_operational:
        message_footer = f"\n\n🤖 _{BOT_NAME}_"
        message_to_send += message_footer
        
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': chat_id, 'text': message_to_send, 'parse_mode': 'Markdown'}
    try:
        requests.post(api_url, json=payload, timeout=10)
        print(f"[TG] Sent to {chat_id}: \"{text[:70].replace(chr(10), ' ')}...\"")
    except Exception as e:
        print(f"[!] TELEGRAM ERROR: {e}")

def clear_all_existing_numbers(session):
    """Called once after login or on exit to ensure a clean slate."""
    global api_csrf_token # This token is for /portal/numbers/ termination APIs
    print("\n[*] Performing account cleanup...")
    try:
        # Get CSRF token from a relevant page for cleanup operation
        page_response = session.get(TEST_NUMBERS_PAGE_URL)
        page_response.raise_for_status()
        soup = BeautifulSoup(page_response.text, 'html.parser')
        token = soup.find('meta', {'name': 'csrf-token'})
        if not token:
            print("[!] Could not find CSRF token for cleanup. Skipping cleanup.")
            return False
        api_csrf_token = token['content'] # Update the global CSRF token for general API use
        
        headers = {'Accept': '*/*', 'X-CSRF-TOKEN': api_csrf_token, 'X-Requested-With': 'XMLHttpRequest', 'Referer': MY_NUMBERS_URL}
        response = session.post(REMOVE_ALL_NUMBERS_API_URL, headers=headers)
        response.raise_for_status()

        if "NumberDone" in response.text:
            print("[SUCCESS] Account cleanup complete.")
            return True
        else:
            print("[*] No existing numbers to clean up.")
            return False
    except Exception as e:
        print(f"[!] Could not perform cleanup: {e}")
        return False

def remove_all_numbers_on_exit(signum, frame):
    """Graceful shutdown handler called on Ctrl+C."""
    print("\n\n[!!!] Shutdown signal detected (Ctrl+C). Initiating cleanup sequence.")
    send_telegram_message(DM_CHAT_ID, "🛑 *Shutdown Signal Detected*\n\nAttempting to remove all numbers...", is_operational=True)

    if not current_session:
        sys.exit(1)

    if clear_all_existing_numbers(current_session):
        send_telegram_message(DM_CHAT_ID, "✅ *Shutdown Cleanup Complete*\n\nAll numbers removed. Bot is offline.", is_operational=True)
    else:
        send_telegram_message(DM_CHAT_ID, "❌ *Shutdown Cleanup Failed*\n\nPlease check your account manually.", is_operational=True)
    
    print("[*] Exiting now.")
    sys.exit(0)

def get_and_send_number_list(session, termination_id, current_api_csrf_token, range_name):
    """Fetches the full list of numbers and posts it to the group chat.
       Uses the current valid CSRF token.
    """
    print("\n--- Fetching Full Number List ---")
    try:
        payload = {'termination_id': termination_id, '_token': current_api_csrf_token}
        headers = {
            'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': MY_NUMBERS_URL, 'X-CSRF-TOKEN': current_api_csrf_token,
            'X-Requested-With': 'XMLHttpRequest', 'User-Agent': session.headers['User-Agent']
        }
        list_response = session.post(GET_NUMBER_LIST_API_URL, data=payload, headers=headers)
        list_response.raise_for_status()
        numbers_data = list_response.json()

        if numbers_data and isinstance(numbers_data, list):
            number_list_str = "\n".join([f"`{item.get('Number', 'N/A')}`" for item in numbers_data])
            message_text = f"**New Asset Package Acquired: {range_name}**\n\n_{len(numbers_data)} items available:_\n{number_list_str}"
            send_telegram_message(GROUP_CHAT_ID_FOR_LISTS, message_text)
    except Exception as e:
        print(f"[!] Error getting full number list: {e}")

def realtime_otp_fetcher(session, phone_number_to_watch, acquired_range_name):
    """
    Polls the real-time SMS received pages to find the OTP for a specific number.
    This replaces the previous watch_for_code function.
    """
    print(f"\n--- Real-time OTP Fetcher for {phone_number_to_watch} (Range: {acquired_range_name}) ---")
    send_telegram_message(DM_CHAT_ID, f"👀 *Real-time OTP Watch*\n\nMonitoring for a code on acquired number:\n`{phone_number_to_watch}` (Range: `{acquired_range_name}`)\nThis will continue until you stop the script (Ctrl+C).", is_operational=True)

    while True:
        try:
            print(f"[*] Scanning for OTP for {phone_number_to_watch} in range {acquired_range_name}...")

            # --- CRITICAL FIX: Get a fresh CSRF token from the specific /sms/received page context ---
            received_page_response = session.get(RECEIVED_SMS_PAGE_URL)
            received_page_response.raise_for_status()
            soup_received_page = BeautifulSoup(received_page_response.text, 'html.parser')
            
            # Look for the CSRF token in a meta tag (common) or a hidden input within a form (also common)
            current_otp_csrf_token = None
            new_csrf_token_tag = soup_received_page.find('meta', {'name': 'csrf-token'})
            if new_csrf_token_tag:
                current_otp_csrf_token = new_csrf_token_tag['content']
                # print(f"[+] Fresh OTP Fetcher CSRF Token from meta tag: {current_otp_csrf_token}") # Debug
            else:
                hidden_token_input = soup_received_page.find('input', {'name': '_token'})
                if hidden_token_input:
                    current_otp_csrf_token = hidden_token_input['value']
                    # print(f"[+] Fresh OTP Fetcher CSRF Token from input: {current_otp_csrf_token}") # Debug
            
            if not current_otp_csrf_token:
                raise Exception("Could not find CSRF token on /portal/sms/received page for OTP fetcher.")
            
            # Define headers for POST requests in this section
            headers_post = {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Accept': 'text/html, */*; q=0.01',
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': RECEIVED_SMS_PAGE_URL, # Ensure Referer is always this specific page
                'User-Agent': session.headers['User-Agent']
            }
            
            # Step 1: Request the dynamic content for ranges
            # This POST request usually returns HTML that JavaScript then renders.
            # We perform it to maintain session state and validate the CSRF token for subsequent calls.
            payload_ranges_initial = {'_token': current_otp_csrf_token} 
            response_ranges_page = session.post(
                GET_SMS_RANGES_URL,
                data=payload_ranges_initial,
                headers=headers_post
            )
            response_ranges_page.raise_for_status()
            # We don't need to parse the content of `response_ranges_page.text` directly here
            # as we already know the `acquired_range_name` from the acquisition process.

            # Step 2: Request numbers within the acquired range
            print(f"[*] Requesting numbers for range: {acquired_range_name}")
            payload_numbers_in_range = {
                '_token': current_otp_csrf_token,
                'start': '', # These fields are typically for pagination/filtering
                'end': '',
                'range': acquired_range_name 
            }
            response_numbers_in_range = session.post(
                GET_SMS_NUMBERS_IN_RANGE_URL,
                data=payload_numbers_in_range,
                headers=headers_post
            )
            response_numbers_in_range.raise_for_status()
            soup_numbers = BeautifulSoup(response_numbers_in_range.text, 'html.parser')

            # Find the specific number's div within the range to extract its internal ID
            target_number_div = None
            for div_tag in soup_numbers.find_all('div', onclick=True):
                onclick_value = div_tag.get('onclick', '')
                # Regex to extract the phone number and its second ID from the onclick attribute
                match = re.search(r"getDetialsNumberZDJ1h\('(\d+)','(\d+)'\)", onclick_value)
                if match:
                    number_found_in_html = match.group(1)
                    if number_found_in_html == phone_number_to_watch:
                        target_number_div = div_tag
                        break
            
            if not target_number_div:
                print(f"[*] Number {phone_number_to_watch} not yet visible in the received SMS list for range {acquired_range_name}. Retrying...")
                time.sleep(10)
                continue

            onclick_match = re.search(r"getDetialsNumberZDJ1h\('(\d+)','(\d+)'\)", target_number_div['onclick'])
            if not onclick_match:
                print(f"[!] Could not parse onclick for {phone_number_to_watch}. Missing second ID. Retrying...")
                time.sleep(10)
                continue
            
            extracted_number_id = onclick_match.group(1) # This is the phone number itself
            extracted_id_number = onclick_match.group(2) # This is the second ID, e.g., '67402004'

            # Step 3: Request SMS messages for the specific number
            print(f"[*] Requesting SMS messages for number: {phone_number_to_watch} (Internal ID: {extracted_id_number})")
            payload_sms_messages = {
                '_token': current_otp_csrf_token, # Use the freshly acquired token
                'start': '',
                'end': '',
                'Number': extracted_number_id,
                'Range': acquired_range_name 
            }
            response_sms_messages = session.post(
                GET_SMS_MESSAGES_FOR_NUMBER_URL,
                data=payload_sms_messages,
                headers=headers_post
            )
            response_sms_messages.raise_for_status()
            soup_messages = BeautifulSoup(response_sms_messages.text, 'html.parser')

            # Extract the actual message data and look for the OTP
            # The messages are typically within a div with class "Message"
            message_text_div = soup_messages.find('div', class_='Message')
            
            whatsapp_code = None
            if message_text_div:
                message_content = message_text_div.get_text(strip=True)
                print(f"[*] Raw message content for {phone_number_to_watch}: {message_content}")
                # More robust regex to capture various OTP formats (e.g., 3-7 digits, with/without spaces/hyphens)
                code_match = re.search(r'\b(\d{3,7})\b|\b(\d{3}[- ]?\d{3,4})\b', message_content) 
                if code_match:
                    # Prioritize the first matching group (direct digits), then the one with separators
                    whatsapp_code = code_match.group(1) if code_match.group(1) else code_match.group(2)
                    if whatsapp_code:
                        whatsapp_code = re.sub(r'[- ]', '', whatsapp_code) # Clean any spaces or hyphens
                    
            if whatsapp_code:
                print(f"\n[SUCCESS] OTP Intercepted: {whatsapp_code}")
                notification_text = f"✅ *OTP Acquired! (Real-time Fetch)*\n\n*Number:* `{phone_number_to_watch}`\n*OTP:* `{whatsapp_code}`"
                send_telegram_message(DM_CHAT_ID, notification_text, is_operational=True)
                return True
            else:
                print(f"[*] OTP not yet found for {phone_number_to_watch}. Retrying in 10 seconds...")
            
            time.sleep(10) # Poll every 10 seconds

        except requests.exceptions.RequestException as req_e:
            print(f"[!] Network or HTTP error during OTP fetch for {phone_number_to_watch}: {req_e}")
            send_telegram_message(DM_CHAT_ID, f"⚠️ *Network Error (OTP Fetch)*\n\nCould not fetch OTP for `{phone_number_to_watch}` due to network issue: `{req_e}`. Retrying in 30 seconds.", is_operational=True)
            time.sleep(30)
        except Exception as e:
            print(f"[!] General error during OTP fetch for {phone_number_to_watch}: {e}")
            send_telegram_message(DM_CHAT_ID, f"❌ *OTP Fetch Error*\n\nAn error occurred while fetching OTP for `{phone_number_to_watch}`: `{e}`. Retrying in 30 seconds.", is_operational=True)
            time.sleep(30)

def acquire_and_process_number(session, number_range_name, phone_number_to_process):
    """The acquisition workflow, based on Israel's proven logic."""
    global api_csrf_token # This global token is used for acquisition APIs
    print(f"\n--- Acquiring Number: {phone_number_to_process} ---")
    try:
        # Re-fetch the CSRF token from a test numbers page for acquisition specific calls
        page_response = session.get(TEST_NUMBERS_PAGE_URL)
        page_response.raise_for_status()
        soup = BeautifulSoup(page_response.text, 'html.parser')
        token_tag = soup.find('meta', {'name': 'csrf-token'})
        if not token_tag:
            raise Exception("Could not find CSRF token on TEST_NUMBERS_PAGE_URL for acquisition.")
        api_csrf_token = token_tag['content']
        print(f"[+] Acquired API CSRF Token for acquisition: {api_csrf_token}")

        params = {
            'draw': '1', 'columns[0][data]': 'range', 'columns[1][data]': 'test_number',
            'columns[2][data]': 'term', 'columns[3][data]': 'P2P', 'columns[4][data]': 'A2P',
            'columns[5][data]': 'Limit_Range', 'columns[6][data]': 'limit_cli_a2p',
            'columns[7][data]': 'limit_did_a2p', 'columns[8][data]': 'limit_cli_did_a2p', # Corrected this back to original based on context, if it was 'limit_did_a2p' twice.
            'columns[9][data]': 'limit_cli_p2p', 'columns[10][data]': 'limit_did_p2p',
            'columns[11][data]': 'limit_cli_did_p2p', 'columns[12][data]': 'updated_at',
            'columns[13][data]': 'action', 'columns[13][searchable]': 'false', 'columns[13][orderable]': 'false',
            'order[0][column]': '1', 'order[0][dir]': 'asc', 'start': '0', 'length': '50',
            'search[value]': phone_number_to_process, '_': int(time.time() * 1000),
        }
        search_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': TEST_NUMBERS_PAGE_URL, 'X-CSRF-TOKEN': api_csrf_token,
            'X-Requested-With': 'XMLHttpRequest', 'User-Agent': session.headers['User-Agent']
        }
        search_response = session.get(TEST_NUMBERS_API_URL, params=params, headers=search_headers)
        search_response.raise_for_status()
        search_data = search_response.json()

        if not search_data.get('data') or not search_data['data']:
            print(f"[!] Search failed. Number {phone_number_to_process} may have been taken or not found.")
            return False
        
        found_number_id = search_data['data'][0].get('id')
        if not found_number_id:
            print(f"[!] Could not find 'id' for {phone_number_to_process} in search data (response missing 'id').")
            return False
        print(f"[+] Found Termination ID: {found_number_id}")

        print(f"\n--- Attempting to Add {phone_number_to_process} ---")
        add_payload = {'_token': api_csrf_token, 'id': found_number_id}
        add_headers = search_headers.copy()
        add_headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        
        add_response = session.post(ADD_NUMBER_API_URL, data=add_payload, headers=add_headers)
        add_response.raise_for_status()
        add_data = add_response.json()

        if "done" in add_data.get("message", "").lower():
            print("[SUCCESS] Server responded 'done'.")
            send_telegram_message(DM_CHAT_ID, f"✅ *Number Added*\n\nSuccessfully added `{phone_number_to_process}` to the account.", is_operational=True)
            
            # Use the same api_csrf_token for the number list fetch
            get_and_send_number_list(session, found_number_id, api_csrf_token, number_range_name)
            
            # --- CALL NEW REAL-TIME OTP FETCHER ---
            realtime_otp_fetcher(session, phone_number_to_process, number_range_name)
            return True
        else:
            error_message = add_data.get("message", "Unknown error or 'message' not in response.")
            print(f"[!] Add action FAILED: {error_message}")
            send_telegram_message(DM_CHAT_ID, f"❌ *Add Failed*\n\nCould not add `{phone_number_to_process}`. Reason: `{error_message}`", is_operational=True)
            return False
            
    except Exception as e:
        print(f"[!] Error during acquisition for {phone_number_to_process}: {e}")
        send_telegram_message(DM_CHAT_ID, f"❌ *Acquisition Error*\n\nAn error occurred during acquisition of `{phone_number_to_process}`: `{e}`", is_operational=True)
        return False

def start_interactive_acquisition_loop(session):
    """The main loop that finds numbers and asks for user confirmation."""
    print("\n[*] Step 3: Starting interactive acquisition scanner...")
    send_telegram_message(DM_CHAT_ID, "🛰️ *Acquisition Bot is online and scanning for targets...*", is_operational=True)
    processed_numbers = set()
    scan_count = 0
    while True:
        scan_count += 1
        print(f"\n[*] Scan #{scan_count}: Checking public SMS feed...")
        try:
            # Use SMS_HISTORY_PAGE_URL to get current server time and overall public feed
            page_response = session.get(SMS_HISTORY_PAGE_URL) 
            page_response.raise_for_status()
            soup = BeautifulSoup(page_response.text, 'html.parser')
            # Extract server time from the button, if it exists
            server_time_button = soup.find('button', class_='btn-sidebar')
            server_time_match = None
            if server_time_button:
                server_time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', server_time_button.text)
            
            if not server_time_match:
                print("[!] Could not find server time on SMS History page. Retrying...")
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
            api_response.raise_for_status()
            data = api_response.json()

            for message in data.get('data', []):
                message_time_obj = datetime.strptime(message.get('senttime'), '%Y-%m-%d %H:%M:%S')
                # Check for recent messages (within 45 seconds of server time)
                if abs((server_time_obj - message_time_obj).total_seconds()) <= 45: 
                    # Extract phone number, handling HTML entities if present
                    phone_number_html = message.get('termination', {}).get('test_number', '')
                    phone_number = BeautifulSoup(phone_number_html, 'html.parser').get_text(strip=True)
                    
                    if phone_number and phone_number not in processed_numbers:
                        number_range_name = message.get('range')
                        print(f"\n[!] TARGET SPOTTED! Name: {number_range_name}, Number: {phone_number}")
                        processed_numbers.add(phone_number) 
                        
                        choice = input(f"[?] Found target: {number_range_name}. Do you want to acquire this number? (y/n): ").lower().strip()
                        
                        if choice == 'y':
                            send_telegram_message(DM_CHAT_ID, f"🎯 *Target Acquired*\n\nAcquiring `{number_range_name}` (`{phone_number}`) on your command...", is_operational=True)
                            if acquire_and_process_number(session, number_range_name, phone_number):
                                print("[*] MISSION COMPLETE. The bot's primary task is finished (acquisition and OTP fetch).")
                                send_telegram_message(DM_CHAT_ID, "✅ *Mission Complete*\n\nThe bot has acquired the number and is now in permanent OTP watch mode for that number. The acquisition loop will stop.", is_operational=True)
                                return # Exit this loop and implicitly this thread
                            else:
                                print("[!] Acquisition failed. Continuing scan.")
                        else:
                            print("[*] Target skipped by user. Resuming scan.")
                        
                        # Break after processing a spotted target to avoid multiple prompts from same scan data
                        break 
            
            time.sleep(5) # Wait before next scan iteration

        except requests.exceptions.RequestException as req_e:
            print(f"[!!!] Network or HTTP error in main acquisition loop: {req_e}")
            send_telegram_message(DM_CHAT_ID, f"❌ *Bot Error*\n\nNetwork issue in acquisition loop: `{req_e}`. Retrying in 30 seconds.", is_operational=True)
            time.sleep(30)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in main acquisition loop: {e}")
            send_telegram_message(DM_CHAT_ID, f"❌ *Bot Error*\n\nAn unexpected error occurred in the main acquisition loop: `{e}`. Retrying in 30 seconds.", is_operational=True)
            time.sleep(30)

def telegram_listener_task(session):
    """Continuously listens for user commands in any group, based on Israel's proven code."""
    print("[*] Starting Telegram Group Assistant...")
    offset = None
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

    while True:
        try:
            params = {"timeout": 30, "offset": offset, "allowed_updates": ["message"]}
            resp = requests.get(f"{api_url}/getUpdates", params=params)
            resp.raise_for_status()
            updates = resp.json()["result"]
            
            for update in updates:
                offset = update["update_id"] + 1

                if "message" not in update:
                    continue

                msg = update.get("message", {})
                chat = msg.get("chat", {})
                user = msg.get("from", {})
                text = msg.get("text", "").strip()
                chat_id = chat.get("id") 
                is_group = chat.get("type", "").endswith("group")

                # Only respond to commands in groups if the text is a number and long enough
                if is_group and text.isdigit() and len(text) > 8:
                    username = user.get("username", user.get("first_name", "User"))
                    print(f"--- On-Demand Code Check for {text} requested by @{username} in chat {chat_id} ---")
                    
                    # This part still uses the older SMS_HISTORY_API_URL for quick checks.
                    # It's less detailed than the new real-time fetcher but sufficient for a quick check.
                    params_sms_history = {'app': 'WhatsApp', 'search[value]': text, '_': int(time.time() * 1000)}
                    headers_sms_history = {'Accept': 'application/json, text/javascript, */*; q=0.01', 'Referer': SMS_HISTORY_PAGE_URL, 'X-Requested-With': 'XMLHttpRequest'}
                    api_response_sms_history = session.get(SMS_HISTORY_API_URL, params=params_sms_history, headers=headers_sms_history)
                    api_response_sms_history.raise_for_status()
                    data_sms_history = api_response_sms_history.json()
                    
                    reply_text = f"❌ @{username}, code not received for `{text}`"
                    if data_sms_history.get('data'):
                        # Look for the relevant message from the target number
                        for sms_entry in data_sms_history['data']:
                            sms_number = BeautifulSoup(sms_entry.get('termination', {}).get('test_number', ''), 'html.parser').get_text(strip=True)
                            if sms_number == text: # Ensure it's the message for the requested number
                                message_data = sms_entry.get('messagedata', '')
                                code_match = re.search(r'\b(\d{3,7})\b|\b(\d{3}[- ]?\d{3,4})\b', message_data) # Use same robust regex
                                if code_match:
                                    whatsapp_code = code_match.group(1) if code_match.group(1) else code_match.group(2)
                                    if whatsapp_code:
                                        whatsapp_code = re.sub(r'[- ]', '', whatsapp_code)
                                        reply_text = f"✅ @{username}, code for `{text}` is: `{whatsapp_code}`"
                                        break # Found code for this number, exit inner loop
                        
                    send_telegram_message(chat_id, reply_text)

        except requests.exceptions.RequestException as req_e:
            print(f"[!!!] Network or HTTP error in Telegram Listener thread: {req_e}")
            # Do not send Telegram message here to avoid loop if TG API itself is down
            time.sleep(10)
        except Exception as e:
            print(f"[!!!] CRITICAL ERROR in Telegram Listener thread: {e}")
            time.sleep(10)

def main():
    """Main function to handle login, cleanup, and start the bot threads."""
    global current_session
    signal.signal(signal.SIGINT, remove_all_numbers_on_exit)

    # Check for placeholder Recaptcha token
    if MAGIC_RECAPTCHA_TOKEN == "09ANMylNCcYBQ6yzuazWc7Wq698PRe_i-EfYOLcTKsGj0CgpTJLSVzeIKoZ7dc13o1Vpye2GewcWkSh5yyL_6-Kx43Bd6whJI6qRXm0jRvKj2q3Q554TbZPLdi32MlflE" or "PASTE_YOUR_NEW_FRESH_TOKEN_HERE" in MAGIC_RECAPTCHA_TOKEN:
        print("\n" + "="*70)
        print("[!!!] FATAL ERROR: You have not updated the MAGIC_RECAPTCHA_TOKEN.")
        print("      Please follow the instructions in the script to get a new one.")
        print("="*70)
        send_telegram_message(DM_CHAT_ID, "❌ *Bot Startup Failed*\n\n`MAGIC_RECAPTCHA_TOKEN` is missing or invalid. Please update it.", is_operational=True)
        return

    send_telegram_message(DM_CHAT_ID, f"🚀 *{BOT_NAME} is Starting Up*\n\nTo shut down gracefully and remove all numbers, press `Ctrl+C`.", is_operational=True)
    
    try:
        with requests.Session() as session:
            current_session = session
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Android 11; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0'})
            
            print("\n[*] Step 1: Authenticating...")
            response = session.get(LOGIN_URL)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token_login_tag = soup.find('input', {'name': '_token'})
            if not csrf_token_login_tag:
                raise Exception("Could not find CSRF token on login page for initial login.")
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

            if "login" not in login_response.url and "Logout" in login_response.text:
                 print("[SUCCESS] Authentication complete!")
                 send_telegram_message(DM_CHAT_ID, "🔐 *Authentication Successful*\n\nSession established.", is_operational=True)
                 
                 # Perform initial cleanup and set the global api_csrf_token for subsequent main API calls
                 clear_all_existing_numbers(session)
                 
                 acquisition_thread = threading.Thread(target=start_interactive_acquisition_loop, args=(session,), daemon=True)
                 listener_thread = threading.Thread(target=telegram_listener_task, args=(session,), daemon=True)

                 acquisition_thread.start()
                 listener_thread.start()

                 print("\n[SUCCESS] Bot is fully operational.")
                 print("   > The Interactive Acquisition Bot is running in this terminal.")
                 print("   > The Group Assistant is running in the background.")
                 
                 # Wait for the acquisition thread to complete (after a number is acquired and OTP fetched)
                 acquisition_thread.join()
                 print("\n[*] Main acquisition task complete. The script will continue running the Telegram listener until explicitly stopped (Ctrl+C).")
                 
                 # Keep the main thread alive as long as daemon threads are running
                 while True:
                     time.sleep(1) # Sleep to prevent busy-waiting
            else:
                print("\n[!!!] AUTHENTICATION FAILED. The ReCaptcha token is likely invalid or expired, or credentials are wrong.")
                send_telegram_message(DM_CHAT_ID, "❌ *Authentication Failed*\n\nThe login was rejected. Please generate a new `MAGIC_RECAPTCHA_TOKEN` and restart the bot, or check credentials.", is_operational=True)
    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")
        send_telegram_message(DM_CHAT_ID, f"❌ *Bot Startup Error*\n\nA critical error occurred: `{e}`. The bot will shut down.", is_operational=True)

if __name__ == "__main__":
    main()
