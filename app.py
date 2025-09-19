import os
import hashlib
from flask import Flask, session, redirect, url_for, request, render_template, jsonify
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


@app.route("/dedupe", methods=["POST"])
def dedupe():
    creds = creds_from_session()
    if not creds or not creds.valid:
        return jsonify({"error": "Not authenticated"}), 401

    service = build("gmail", "v1", credentials=creds)
    user_id = "me"

    seen = {}
    duplicates = []
    page_token = None

    # Fetch messages page by page
    while True:
        resp = service.users().messages().list(
            userId=user_id,
            maxResults=500,
            pageToken=page_token
        ).execute()
        messages = resp.get("messages", [])
        for m in messages:
            try:
                msg = service.users().messages().get(
                    userId=user_id,
                    id=m["id"],
                    format="metadata",
                    metadataHeaders=["From", "Subject"]
                ).execute()
            except:
                continue

            headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            sender = headers.get("From", "").strip()
            subject = headers.get("Subject", "").strip()
            snippet = msg.get("snippet", "").strip()

            key_source = (sender + "||" + subject + "||" + snippet).lower()
            key = hashlib.md5(key_source.encode("utf-8")).hexdigest()

            if key in seen:
                duplicates.append(m["id"])
            else:
                seen[key] = m["id"]

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    deleted_count = 0
    if duplicates:
        for msg_id in duplicates:
            service.users().messages().trash(
                userId=user_id,
                id=msg_id
            ).execute()
        deleted_count = len(duplicates)

    return jsonify({
        "deleted_count": deleted_count,
        "duplicates_found": len(duplicates),
        "unique_emails": len(seen)
    })


if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
