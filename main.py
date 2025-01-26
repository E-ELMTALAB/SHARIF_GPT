import asyncio
import re
import psycopg2
from telethon import TelegramClient, events
from telethon.errors import RPCError
from datetime import datetime, timedelta  # Imported timedelta
import base64
import pickle
import os
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import nest_asyncio
import random

nest_asyncio.apply()

# ------------------ Configuration ------------------

# ------------------ Telegram Configuration ------------------

# 1. Telegram API Credentials
API_ID = 123456  # <-- Replace with your API ID
API_HASH = '0123456789abcdef0123456789abcdef'  # <-- Replace with your API Hash
SESSION_NAME = 'sharifgpt_admin_sendToAll.session'  # Arbitrary session name without path

# Admin User IDs (List of Telegram user IDs who can manually assign accounts)
ADMIN_USER_IDS = [6190752091]   # Replace with actual admin Telegram user IDs

# ------------------ Database Configuration ------------------

# PostgreSQL Database URL
DATABASE_URL = 'postgresql://posts_owner:jYw1bfDnOHW2@ep-holy-glitter-a287uyrp.eu-central-1.aws.neon.tech/sharifgpt%20admin?sslmode=require'  # Replace with your PostgreSQL Database URL

# ------------------ Request Keywords and Messages ------------------

# Farsi Keywords indicating a request for a free account
REQUEST_KEYWORDS = [
    "رایگان",
    "اکانت رایگان",
    "اکانت تست"
    "مجانی",
    "دریافت اکانت",
    "chatgpt رایگان"
]

# Regex pattern to detect Gmail addresses
GMAIL_REGEX = r'[\w\.-]+@gmail\.com'

# Regex pattern to extract Gmail address and password
# Expected message format:
# ایمیل: `user@gmail.com`
# رمز عبور: `password123`
GMAIL_ASSIGN_REGEX = r'([\w\.-]+@gmail\.com)\s+([\w\W]+)'

# Farsi Messages
MESSAGES = {
    'welcome': "سلام! برای دریافت حساب رایگان ChatGPT پیام دهید.",
    'no_accounts': """دوست عزیز به دلیل حجم زیاد پیام ها 
چند دقیقه ای زمان میبره تا اکانت خدمتتون ارسال بشه 
ممنون از صبوری شما 🙏""",
    'account_sent': "تقدیم به شما . لطفا این ایمیل و پسوورد رو توی سایت chatgpt.com وارد کنید ",
    'error': "مشکلی پیش آمد. لطفاً دوباره تلاش کنید.",
    'invalid_command': "دستور نامعتبر. لطفاً از فرمت صحیح استفاده کنید.",
    'assign_success': "حساب `{email}` به شما اختصاص داده شد.",
    'assign_failure': "حساب `{email}` قابل دسترسی نیست یا قبلاً اختصاص یافته است.",
    'permission_denied': "شما اجازه دسترسی به این دستور را ندارید.",
    'code_sent': "کد تأیید شما: `{code}`",
    'invalid_email_format': "فرمت ایمیل نامعتبر است. لطفاً یک ایمیل معتبر وارد کنید.",
}

# ------------------ Gmail Configuration ------------------

# Gmail API scope and credentials
SCOPES = ['https://mail.google.com/']  # Using modify to allow marking emails as read/delete
GMAIL_CREDENTIALS_FILE = 'client.json'                # Path to Gmail API credentials
GMAIL_TOKEN_PICKLE = 'token.pickle'                   # Path to store Gmail API tokens

# Forwarded email details
EMAIL_SUBJECT = 'Your ChatGPT code'  # Subject of the verification email
CODE_REGEX = r'\b\d{6}\b'  # Regex to extract the 6-digit code

# --------------------------------------------------

# Initialize Telegram client
print("Initializing Telegram client...")
client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
print("Telegram client initialized.")

# ------------------ Database Functions ------------------

def get_db_connection():
    """Establish a connection to the PostgreSQL database."""
    print("Attempting to connect to the PostgreSQL database...")
    try:
        conn = psycopg2.connect(DATABASE_URL)
        print("Successfully connected to the PostgreSQL database.")
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None
import random

def get_available_account():
    """Fetch all available Gmail accounts from the database and randomly select one."""
    print("Fetching all available Gmail accounts from the database...")
    conn = get_db_connection()
    if conn is None:
        print("Failed to establish a database connection.")
        return None
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT id, email, password FROM accounts
            WHERE state = 'available'
        ''')
        results = cursor.fetchall()  # Fetch all matching rows
        if results:
            # Randomly choose one of the available accounts
            chosen_account = random.choice(results)
            account = {"id": chosen_account[0], "email": chosen_account[1], "password": chosen_account[2]}
            print(f"Randomly selected account: {account['email']}")
        else:
            account = None
            print("No available accounts found.")
    except Exception as e:
        print(f"Error fetching available accounts: {e}")
        account = None
    finally:
        cursor.close()
        conn.close()
    return account


def assign_account_to_user(email, password, user_id):
    """
    Assign a specific Gmail account to a user (used by admins or manual assignments).
    Returns True if successful, False otherwise.
    """
    print(f"Assigning account {email} to user {user_id}...")
    conn = get_db_connection()
    if conn is None:
        print("Failed to establish a database connection.")
        return False
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE accounts
            SET state = 'pending', user_id = %s, last_assigned = %s, password = %s
            WHERE email = %s AND state = 'available'
        ''', (user_id, datetime.utcnow(), password, email))
        if cursor.rowcount == 0:
            # No account was updated
            print(f"Failed to assign account {email}: Account is not available or already assigned.")
            cursor.close()
            conn.close()
            return False
        conn.commit()
        print(f"Successfully assigned account {email} to user {user_id}.")
    except Exception as e:
        print(f"Error assigning account {email} to user {user_id}: {e}")
        cursor.close()
        conn.close()
        return False
    cursor.close()
    conn.close()
    return True

def mark_account_pending(account_id, user_id):
    """Mark an account as pending in the database (for automated assignments)."""
    print(f"Marking account ID {account_id} as pending for user {user_id}...")
    conn = get_db_connection()
    if conn is None:
        print("Failed to establish a database connection.")
        return
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE accounts
            SET state = 'pending', user_id = %s, last_assigned = %s
            WHERE id = %s
        ''', (user_id, datetime.utcnow(), account_id))
        conn.commit()
        print(f"Account ID {account_id} marked as pending for user {user_id}.")
    except Exception as e:
        print(f"Error marking account {account_id} as pending: {e}")
    cursor.close()
    conn.close()

def reset_pending_accounts():
    """Reset accounts labeled as 'pending' back to 'available' if they have been pending for over 2 minutes."""
    print("Resetting pending accounts if they have been pending for over 2 minutes...")
    conn = get_db_connection()
    if conn is None:
        print("Failed to establish a database connection.")
        return
    cursor = conn.cursor()
    try:
        two_minutes_ago = datetime.utcnow() - timedelta(minutes=2)
        cursor.execute('''
            UPDATE accounts
            SET state = 'available', user_id = NULL, last_assigned = NULL
            WHERE state = 'pending' AND last_assigned <= %s
        ''', (two_minutes_ago,))
        affected_rows = cursor.rowcount
        if affected_rows > 0:
            print(f"Reset {affected_rows} account(s) from 'pending' to 'available'.")
        else:
            print("No accounts needed to be reset.")
        conn.commit()
    except Exception as e:
        print(f"Error resetting pending accounts: {e}")
    cursor.close()
    conn.close()

# ------------------ Gmail Authentication and Processing ------------------

def authenticate_gmail():
    """Authenticate with Gmail API using OAuth2."""
    print("Authenticating with Gmail API...")
    creds = None
    if os.path.exists(GMAIL_TOKEN_PICKLE):
        print(f"Loading Gmail credentials from {GMAIL_TOKEN_PICKLE}...")
        with open(GMAIL_TOKEN_PICKLE, 'rb') as token:
            creds = pickle.load(token)
    else:
        print(f"Missing {GMAIL_TOKEN_PICKLE}. Ensure the token file exists.")
        return None
    # Refresh the token if it's expired
    if creds and creds.expired and creds.refresh_token:
        print("Refreshing Gmail credentials...")
        try:
            creds.refresh(Request())
            with open(GMAIL_TOKEN_PICKLE, 'wb') as token:
                pickle.dump(creds, token)
            print("Gmail credentials refreshed successfully.")
        except Exception as e:
            print(f"Error refreshing Gmail credentials: {e}")
            return None
    elif not creds or not creds.valid:
        print("Gmail credentials are invalid. Please ensure token.pickle is valid.")
        return None
    try:
        service = build('gmail', 'v1', credentials=creds)
        print("Gmail service built successfully.")
        return service
    except Exception as e:
        print(f"Failed to build Gmail service: {e}")
        return None

def extract_email_body(payload):
    """Extract the email body (text/plain) from the payload."""
    try:
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    return base64.urlsafe_b64decode(data).decode("utf-8")
        elif payload.get('body', {}).get('data'):
            return base64.urlsafe_b64decode(payload['body']['data']).decode("utf-8")
    except Exception as e:
        print(f"Error decoding email body: {e}")
    return ""

def extract_verification_code(body):
    """Extract the verification code from the email body using regex."""
    try:
        match = re.search(CODE_REGEX, body)
        if match:
            code = match.group(0)
            print(f"Verification code extracted: {code}")
            return code
    except Exception as e:
        print(f"Error extracting verification code: {e}")
    return None

async def process_message(service, message):
    """Process a single Gmail message to extract verification code and notify the user."""
    print(f"Processing message ID {message['id']}...")
    try:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        payload = msg['payload']
        headers = payload.get('headers', [])
        to_email = None

        for header in headers:
            if header['name'].lower() == 'to':
                to_email = header['value']
                break

        if not to_email:
            print(f"No 'To' header found in message {message['id']}. Skipping.")
            return

        print(f"Extracting email body from message ID {message['id']}...")
        body = extract_email_body(payload)
        verification_code = extract_verification_code(body)

        if verification_code:
            print(f"Extracted code: {verification_code} from email to {to_email}")

            # Fetch user_id from the database using the to_email (Gmail address)
            print(f"Fetching user ID associated with email {to_email}...")
            conn = get_db_connection()
            if conn is None:
                print("Failed to connect to the database.")
                return
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_id FROM accounts WHERE email = %s AND state = 'pending'
            ''', (to_email,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            if result:
                user_id = result[0]
                print(f"Found user ID {user_id} for email {to_email}.")

                # Send the verification code to the user via Telegram
                try:
                    print(f"Sending verification code to user {user_id}...")
                    await client.send_message(user_id, MESSAGES['code_sent'].format(code=verification_code), parse_mode='markdown')
                    print(f"Verification code sent to user {user_id} successfully.")

                    # Update the account in the database
                    print(f"Updating account state to 'completed' for email {to_email}...")
                    conn = get_db_connection()
                    if conn is None:
                        print("Failed to connect to the database.")
                        return
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE accounts
                        SET state = 'available', verification_code = %s, user_id = NULL, last_assigned = NULL
                        WHERE email = %s
                    ''', (verification_code, to_email))
                    conn.commit()
                    cursor.close()
                    conn.close()
                    print(f"Account for email {to_email} marked as 'completed'.")
                except RPCError as e:
                    print(f"Error sending message to user {user_id}: {e}")
            else:
                print(f"No pending account found for email: {to_email}")

        # Mark the message as read to avoid reprocessing
        try:
            print(f"Marking message ID {message['id']} as read...")
            service.users().messages().modify(
                userId='me',
                id=message['id'],
                body={'removeLabelIds': ['UNREAD']}
            ).execute()
            print(f"Message ID {message['id']} marked as read.")
        except Exception as e:
            print(f"Error marking message {message['id']} as read: {e}")

    except Exception as e:
        print(f"Error processing message {message['id']}: {e}")

async def get_appropriate_code(target_user_id):
    """
    Fetch the latest email from the user's Gmail account, extract the verification code,
    and send it to the target user.
    """
    try:
        # Fetch the chat history with the target user
        print(f"Fetching chat history for user {target_user_id}...")
        async for message in client.iter_messages(target_user_id, reverse=False):
            print(message.text)
            if re.search(GMAIL_REGEX, message.text):
                # Extract Gmail from the message
                gmail_address = re.search(GMAIL_REGEX, message.text).group()
                print(f"Found Gmail in chat: {gmail_address}")

                # Authenticate Gmail and search for the latest forwarded email from this address
                service = authenticate_gmail()
                if not service:
                    print("Failed to authenticate with Gmail API.")
                    await client.send_message(target_user_id, MESSAGES['error'])
                    return

                print(f"Searching for latest email forwarded from: {gmail_address}...")
                query = f"from: ChatGPT <noreply@tm.openai.com> to:{gmail_address}"
                response = service.users().messages().list(userId='me', q=query).execute()
                messages = response.get('messages', [])

                if not messages:
                    print("No emails found from this Gmail address.")
                    await client.send_message(target_user_id, MESSAGES['no_accounts'])
                    return

                # Process the latest email
                message_id = messages[0]['id']
                print(f"Processing email with ID: {message_id}...")
                msg = service.users().messages().get(userId='me', id=message_id).execute()
                payload = msg['payload']
                body = extract_email_body(payload)

                # Extract verification code
                print("/////////////////////////////////////////////")
                print(body)
                print("/////////////////////////////////////////////")
                verification_code = extract_verification_code(str(body))
                if verification_code:
                    print(f"Extracted verification code: {verification_code}")

                    # Send the code to the user via Telegram
                    await client.send_message(target_user_id, MESSAGES['code_sent'].format(code=verification_code), parse_mode='markdown')

                    # Mark the email as read
                    service.users().messages().modify(
                        userId='me',
                        id=message_id,
                        body={'removeLabelIds': ['UNREAD']}
                    ).execute()
                    print("Email marked as read.")
                else:
                    print("No verification code found in the email.")
                    await client.send_message(target_user_id, MESSAGES['error'])

                return

        print("No Gmail address found in the recent chat history.")
        await client.send_message(target_user_id, MESSAGES['invalid_email_format'])

    except Exception as e:
        print(f"Error in get_appropriate_code: {e}")
        await client.send_message(target_user_id, MESSAGES['error'])

async def monitor_gmail():
    """Continuously monitor Gmail for incoming verification codes."""
    print("Starting Gmail monitoring...")
    service = authenticate_gmail()
    if not service:
        print("Failed to authenticate Gmail. Exiting Gmail monitor.")
        return

    print("Gmail monitoring started successfully.")

    while True:
        try:
            # Search for unread emails with the specific subject
            query = f'subject:"{EMAIL_SUBJECT}" is:unread'
            print(f"Searching for emails with query: '{query}'")
            response = service.users().messages().list(userId='me', q=query).execute()
            messages = response.get('messages', [])

            if not messages:
                print("No new verification emails found.")
            else:
                print(f"Found {len(messages)} new verification email(s). Processing...")
                for message in messages:
                    await process_message(service, message)

            print("Gmail monitoring cycle complete. Waiting for 60 seconds before next check.")
            await asyncio.sleep(10)  # Wait for 60 seconds before checking again
        except Exception as e:
            print(f"Error during Gmail monitoring: {e}")
            print("Waiting for 60 seconds before retrying...")
            await asyncio.sleep(10)  # Wait before retrying in case of error

# ------------------ New Background Task: Reset Pending Accounts ------------------

async def background_reset_pending_accounts():
    """Background task to reset pending accounts back to available if they have been pending for over 2 minutes."""
    print("Starting background task to reset pending accounts...")
    while True:
        try:
            reset_pending_accounts()
        except Exception as e:
            print(f"Error in background_reset_pending_accounts: {e}")
        await asyncio.sleep(10)  # Run this check every 60 seconds

# ------------------ Telegram Event Handlers ------------------

def contains_request_keywords(message_text):
    """Check if the message contains any of the request keywords."""
    return any(keyword in message_text for keyword in REQUEST_KEYWORDS)

async def user_sent_keyword(client, user_id, keyword="رایگان", num_messages=10):
    """
    Check if the user has sent a specific keyword in their last N messages.

    Args:
        client (TelegramClient): The Telethon client.
        user_id (int): The user's Telegram ID.
        keyword (str): The keyword to look for. Defaults to "رایگان".
        num_messages (int): The number of recent messages to check. Defaults to 10.

    Returns:
        bool: True if the keyword is found, False otherwise.
    """
    try:
        num = 0
        print(f"Checking the last {num_messages} messages from user {user_id} for keyword '{keyword}'...")
        async for message in client.iter_messages(user_id, limit=num_messages , reverse=False):
            if keyword in message.text:
                print(f"Keyword '{keyword}' found in message: {message.text}")
                num += 1
                if num >= 2:
                  return True
        print(f"Keyword '{keyword}' not found in the last {num_messages} messages from user {user_id}.")
        return False
    except Exception as e:
        print(f"Error checking messages for user {user_id}: {e}")
        return False

def contains_gmail_assignment(message_text):
    """Check if the message contains a Gmail assignment."""
    return re.search(GMAIL_ASSIGN_REGEX, message_text)

@client.on(events.NewMessage(incoming=True))
async def handler_incoming(event):
    """Handle incoming messages from users requesting free accounts."""
    try:
        user_message = event.message.message.strip()
        user_id = event.sender_id
        print(f"Received message from user {user_id}: '{user_message}'")

        # Check if the user is requesting a free account
        if contains_request_keywords(user_message):

            # Check if the user has mentioned "رایگان" in the last 10 messages
            if await user_sent_keyword(client, user_id, "رایگان", 20):
                print(f"User {user_id} has recently requested a free account.")
                return

            print(f"User {user_id} is requesting a free account.")
            account = get_available_account()
            if account:
                # Mark account as pending
                mark_account_pending(account['id'], user_id)
                account_details = f"ایمیل:\n `{account['email']}`\nرمز عبور: \n`{account['password']}`"
                await event.respond(f"{MESSAGES['account_sent']}\n\n{account_details}")
                print(f"Assigned account {account['email']} to user {user_id}.")
            else:
                await event.respond(MESSAGES['no_accounts'])
                print(f"No available accounts to assign to user {user_id}.")
        else:
            # Optionally, send a welcome message or ignore
            print(f"Message from user {user_id} does not contain request keywords.")
            pass  # You can uncomment the next line to send a welcome message
            # await event.respond(MESSAGES['welcome'])
    except Exception as e:
        print(f"Error handling incoming message from user {user_id}: {e}")
        await event.respond(MESSAGES['error'])


@client.on(events.NewMessage())
async def handler_outgoing(event):
    """Handle outgoing messages from admins assigning Gmail accounts manually."""
    try:
        sender = await event.get_sender()
        sender_id = sender.id
        message_text = event.message.message.strip()
        print(f"Admin {sender_id} sent a message: '{message_text}'")

        # Check if the sender is an admin
        if sender_id not in ADMIN_USER_IDS:
            print(f"Sender {sender_id} is not authorized to assign accounts.")
            return  # Ignore messages from non-admins for manual assignments

        # Check if the message contains a Gmail assignment
        match = re.search(GMAIL_ASSIGN_REGEX, message_text)
        if match:

            gmail_email = match.group(1)
            gmail_password = match.group(2)
            print(f"Detected Gmail assignment - Email: {gmail_email}, Password: {gmail_password}")

            # Extract the chat ID (recipient user)
            chat = await event.get_chat()
            target_user_id = chat.id
            print(f"Assigning Gmail {gmail_email} to user {target_user_id}.")

            # Assign the Gmail account to the user
            success = assign_account_to_user(gmail_email, gmail_password, target_user_id)
            if success:
                print(f"Successfully assigned Gmail {gmail_email} to user {target_user_id}.")
                # await event.respond(MESSAGES['assign_success'].format(email=gmail_email), parse_mode='markdown')
            else:
                print(f"Failed to assign Gmail {gmail_email} to user {target_user_id}.")
                # await event.respond(MESSAGES['assign_failure'].format(email=gmail_email), parse_mode='markdown')

        # Detect the "کد" command
        if message_text == "کد":
            print("Detected 'کد' command. Deleting the message...")
            await event.delete()  # Delete the admin's message

            # Extract the latest Gmail and send the appropriate code
            chat = await event.get_chat()
            target_user_id = chat.id
            await get_appropriate_code(target_user_id)

        if message_text == "اکانت":
            print("Detected 'اکانت' command. Deleting the message...")
            await event.delete()  # Delete the admin's message

            # Extract the latest Gmail and send the appropriate code
            chat = await event.get_chat()
            target_user_id = chat.id
            print(f"User {target_user_id} is requesting a free account.")
            account = get_available_account()
            if account:
                # Mark account as pending
                mark_account_pending(account['id'], target_user_id)
                account_details = f"ایمیل: `{account['email']}`\nرمز عبور: `{account['password']}`"
                await event.respond(f"{MESSAGES['account_sent']}\n\n{account_details}", parse_mode='markdown')
                print(f"Assigned account {account['email']} to user {target_user_id}.")
            else:
                await event.respond(MESSAGES['no_accounts'])
                print(f"No available accounts to assign to user {target_user_id}.")

    except Exception as e:
        print(f"Error handling outgoing message from admin {sender_id}: {e}")


# ------------------ Main Function ------------------

async def main():
    """Main function to start the Telegram client and Gmail monitoring."""
    print("Starting main function...")
    await client.start()

    # Start Gmail monitoring in the background
    asyncio.create_task(monitor_gmail())
    print("Gmail monitoring task started.")
    # Start the background task to reset pending accounts
    asyncio.create_task(background_reset_pending_accounts())
    print("Background reset pending accounts task started.")
    # Keep the script running until disconnected
    await client.run_until_disconnected()

if __name__ == '__main__':
    print("Launching the combined Telegram Bot and Gmail Monitoring script...")
    asyncio.get_event_loop().run_until_complete(main())
