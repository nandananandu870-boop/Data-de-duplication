from __future__ import print_function
import os.path
import base64
import hashlib
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# If modifying scopes, delete token.json file
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def get_gmail_service():
    """Authenticate and return Gmail service."""
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def get_email_hash(message):
    """Generate a hash for deduplication based on sender, subject, and snippet."""
    headers = message['payload'].get('headers', [])
    subject = sender = ''
    for h in headers:
        if h['name'] == 'Subject':
            subject = h['value']
        if h['name'] == 'From':
            sender = h['value']
    snippet = message.get('snippet', '')
    raw_string = sender + subject + snippet
    return hashlib.md5(raw_string.encode('utf-8')).hexdigest()

def deduplicate_emails(service, user_id='me'):
    """Find and delete duplicate emails."""
    seen_hashes = {}
    duplicates = []

    # Fetch messages
    results = service.users().messages().list(userId=user_id, maxResults=200).execute()
    messages = results.get('messages', [])

    for msg in messages:
        message = service.users().messages().get(userId=user_id, id=msg['id']).execute()
        email_hash = get_email_hash(message)

        if email_hash in seen_hashes:
            duplicates.append(msg['id'])
        else:
            seen_hashes[email_hash] = msg['id']

    # Delete duplicates
    if duplicates:
        service.users().messages().batchDelete(userId=user_id, body={'ids': duplicates}).execute()
        print(f"Deleted {len(duplicates)} duplicate emails.")
    else:
        print("No duplicates found.")

if __name__ == '__main__':
    service = get_gmail_service()
    deduplicate_emails(service)
