import requests
import time
import os
import json

environment = {
    "client_id":     "this_isnt_real",
    "client_secret": "this_REALLY_isnt_real",
    "grant_type":    "urn:ietf:params:oauth:grant-type:device_code"
}

TOKEN_FILE = ".token"

def get_token(env,
              client_id: str = None,
              client_secret: str = None,
              auth_url: str = None,
              token_url: str = None ) -> str:

    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            cache = json.load(f)
        expires_at = cache.get("expires_at", 0)
        now = time.time()
        remaining = expires_at - now
        # compute hours & minutes
        hours = int(remaining // 3600)
        minutes = int((remaining % 3600) // 60)
        print(f"Cached token expires in {hours}h {minutes}m")

        if remaining > 30:
            # still good
            return cache["access_token"]
        else:
            print("Token expired or expiring soon; requesting a new one...")

    # fall back to defaults
    client_id     = client_id     or environment["client_id"]
    client_secret = client_secret or environment["client_secret"]

    auth_url = auth_url or environment[env]["auth"]
    token_url = token_url or environment[env]["token"]

    # STEP 1: Request device & user codes
    dc_resp = requests.post(
        auth_url,
        data={
            "client_id":     client_id,
            "client_secret": client_secret
        }
    )
    dc_resp.raise_for_status()
    dc = dc_resp.json()

    device_code   = dc["device_code"]
    user_code     = dc["user_code"]
    verify_uri    = dc.get("verification_uri_complete") or dc["verification_uri"]
    poll_interval = dc.get("interval", 5)

    print(f"Please go to {verify_uri} and enter code {user_code}")

    # STEP 2: Poll for the token
    payload = {
        "grant_type":    environment["grant_type"],
        "device_code":   device_code,
        "client_id":     client_id,
        "client_secret": client_secret
    }

    while True:
        time.sleep(poll_interval)
        tok_resp = requests.post(token_url, data=payload)
        tok = tok_resp.json()

        if "access_token" in tok:
            expires_in = tok.get("expires_in", 0)
            expires_at = time.time() + expires_in
            with open(TOKEN_FILE, "w") as f:
                json.dump({
                    "access_token": tok["access_token"],
                    "expires_at":   expires_at
                }, f)
            print("🎉 Authorization successful! Token cached to .token")
            return tok["access_token"]

        # still waiting on the user to approve
        if tok.get("error") == "authorization_pending":
            continue

        # something else went wrong
        print("❌ Error fetching token:", tok.get("error_description") or tok.get("error"))
        tok_resp.raise_for_status()
        raise Exception("Unknown error in device‐flow token request")
