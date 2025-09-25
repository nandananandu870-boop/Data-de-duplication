import os
import hashlib
import threading
from flask import Flask, session, redirect, url_for, request, render_template, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# --- Configuration ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
APP_SECRET_KEY = "replace-with-a-random-secret"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
CLIENT_SECRETS_FILE = "client_secrets.json"
OAUTH2_CALLBACK = os.environ.get("OAUTH2_CALLBACK", "http://localhost:5000/oauth2callback")

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

# --- Progress storage ---
dedupe_progress = {"scanned": 0, "duplicates": 0, "deleted": 0, "done": False}


# --- Helpers ---
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


# --- Dedupe Worker Function ---
def run_dedupe(creds):
    global dedupe_progress
    dedupe_progress = {"scanned": 0, "duplicates": 0, "deleted": 0, "done": False}

    service = build("gmail", "v1", credentials=creds)
    user_id = "me"
    seen = {}
    duplicates = []
    page_token = None

    while True:
        resp = service.users().messages().list(
            userId=user_id,
            maxResults=500,   # Fetch more per request (was 5)
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
                    metadataHeaders=["From", "Subject", "Message-Id", "Date"]
                ).execute()
            except:
                continue

            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            sender = headers.get("From", "").strip()
            subject = headers.get("Subject", "").strip()
            msg_id = headers.get("Message-Id", "").strip()
            snippet = msg.get("snippet", "").strip()

            # Use Message-Id if available, else fallback to hash
            if msg_id:
                key_source = msg_id.lower()
            else:
                key_source = (sender + "||" + subject + "||" + snippet).lower()

            key = hashlib.md5(key_source.encode("utf-8")).hexdigest()

            if key in seen:
                duplicates.append(m["id"])
                dedupe_progress["duplicates"] += 1
            else:
                seen[key] = m["id"]

            dedupe_progress["scanned"] += 1

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    # Delete duplicates
    if duplicates:
        for msg_id in duplicates:
            service.users().messages().trash(userId=user_id, id=msg_id).execute()
            dedupe_progress["deleted"] += 1

    dedupe_progress["done"] = True


@app.route("/dedupe", methods=["POST"])
def dedupe():
    creds = creds_from_session()
    if not creds or not creds.valid:
        return jsonify({"error": "Not authenticated"}), 401

    # Run dedupe in background thread
    threading.Thread(target=run_dedupe, args=(creds,)).start()

    return jsonify({"status": "started"})


@app.route("/dedupe/status", methods=["GET"])
def dedupe_status():
    return jsonify(dedupe_progress)


if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
