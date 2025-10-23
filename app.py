import os
import hashlib
from flask import Flask, session, redirect, url_for, request, render_template, flash
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# --- Configuration ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # allow http for local dev
APP_SECRET_KEY = "replace-with-a-random-secret"  # change before deploy
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
CLIENT_SECRETS_FILE = "client_secrets.json"
OAUTH2_CALLBACK = os.environ.get("OAUTH2_CALLBACK", "http://localhost:5000/oauth2callback")

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

# --- Helper functions ---
def creds_to_dict(creds: Credentials):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }

def creds_from_session():
    if "credentials" not in session:
        return None
    return Credentials(**session["credentials"])

def get_or_create_label(service, label_name="DUPLICATE"):
    """Return label ID, creating the label if it doesn't exist."""
    labels = service.users().labels().list(userId='me').execute().get('labels', [])
    for label in labels:
        if label['name'].lower() == label_name.lower():
            return label['id']
    new_label = service.users().labels().create(
        userId='me',
        body={
            "name": label_name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show"
        }
    ).execute()
    return new_label['id']

# --- Routes ---
@app.route("/")
def index():
    creds = creds_from_session()
    signed_in = creds is not None and creds.valid
    return render_template("index.html", signed_in=signed_in)

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=OAUTH2_CALLBACK,
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    session["state"] = state
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state", None)
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=OAUTH2_CALLBACK,
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    session["credentials"] = creds_to_dict(creds)
    return redirect(url_for("index"))

@app.route("/signout")
def signout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dedupe", methods=["POST"])
def dedupe():
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = build("gmail", "v1", credentials=creds)
    user_id = "me"
    label_id = get_or_create_label(service, "DUPLICATE")

    max_emails = int(request.form.get("max_emails", 500))  # Default: 500 emails
    seen = {}
    duplicates = []
    page_token = None
    fetched_emails = 0

    while fetched_emails < max_emails:
        resp = service.users().messages().list(
            userId=user_id,
            q="newer_than:90d",  # Only recent 90 days
            maxResults=min(100, max_emails - fetched_emails),
            pageToken=page_token
        ).execute()

        messages = resp.get("messages", [])
        if not messages:
            break

        for m in messages:
            try:
                msg = service.users().messages().get(
                    userId=user_id,
                    id=m["id"],
                    format="metadata",
                    metadataHeaders=["From", "Subject"]
                ).execute()
                headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
                sender = headers.get("From", "").strip().lower()
                subject = headers.get("Subject", "").strip().lower()

                key_source = f"{sender}|{subject}"
                key = hashlib.md5(key_source.encode("utf-8")).hexdigest()

                if key in seen:
                    duplicates.append(m["id"])
                    service.users().messages().modify(
                        userId=user_id,
                        id=m["id"],
                        body={"addLabelIds": [label_id]}
                    ).execute()
                else:
                    seen[key] = m["id"]

            except Exception as e:
                print("Error reading message:", e)
                continue

            fetched_emails += 1
            if fetched_emails >= max_emails:
                break

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    duplicate_details = []
    for msg_id in duplicates:
        msg = service.users().messages().get(
            userId=user_id, id=msg_id, format="metadata",
            metadataHeaders=["From", "Subject", "Date"]
        ).execute()
        headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
        duplicate_details.append({
            "id": msg_id,
            "from": headers.get("From", ""),
            "subject": headers.get("Subject", ""),
            "date": headers.get("Date", ""),
            "snippet": msg.get("snippet", "")
        })

    if duplicate_details:
        return render_template("results.html",
                               fetched=fetched_emails,
                               uniques=len(seen),
                               duplicates=duplicate_details)

    flash(f"Scan complete! Scanned {fetched_emails} emails. No duplicates found.")
    return redirect(url_for("index"))

@app.route("/delete", methods=["POST"])
def delete_duplicates():
    creds = creds_from_session()
    if not creds or not creds.valid:
        return redirect(url_for("index"))

    service = build("gmail", "v1", credentials=creds)
    ids = request.form.getlist("ids")

    for msg_id in ids:
        try:
            service.users().messages().trash(userId="me", id=msg_id).execute()
        except Exception as e:
            print("Error deleting message:", e)

    flash(f"Moved {len(ids)} duplicates to Trash successfully.")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
