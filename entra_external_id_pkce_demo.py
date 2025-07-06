import os
import base64
import hashlib
import json
import urllib.parse
import requests
import jwt
from jwt.algorithms import RSAAlgorithm

# === Configuration via environment variables ===
TENANT_NAME   = os.getenv("TENANT_NAME", "<YOUR_TENANT_NAME>")      # e.g. demo-tenant
TENANT_GUID   = os.getenv("TENANT_GUID", "<YOUR_TENANT_GUID>")      # e.g. 00000000-0000-0000-0000-000000000000
CLIENT_ID     = os.getenv("CLIENT_ID", "<YOUR_CLIENT_ID>")          # e.g. 11111111-1111-1111-1111-111111111111
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "<YOUR_CLIENT_SECRET_VALUE>")                         # must be set in environment
REDIRECT_URI  = os.getenv("REDIRECT_URI", "https://jwt.ms")         # or your production redirect URI
NONCE         = os.getenv("NONCE", "demoNonce1234")                 # random string to mitigate replay

# Fail early if secret is missing
if not CLIENT_SECRET:
    raise SystemExit("Error: CLIENT_SECRET environment variable is not set")

def generate_pkce():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
    digest   = hashlib.sha256(verifier.encode()).digest()
    challenge= base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return verifier, challenge

def build_authorize_url(code_challenge):
    base = f"https://{TENANT_NAME}.ciamlogin.com/{TENANT_GUID}/oauth2/v2.0/authorize"
    params = {
        "client_id":               CLIENT_ID,
        "response_type":           "code",
        "redirect_uri":            REDIRECT_URI,
        "response_mode":           "query",
        "scope":                   "openid email offline_access",
        "code_challenge":          code_challenge,
        "code_challenge_method":   "S256",
        "nonce":                   NONCE
    }
    return f"{base}?{urllib.parse.urlencode(params)}"

def redeem_token(code, code_verifier):
    token_url = f"https://{TENANT_NAME}.ciamlogin.com/{TENANT_GUID}/oauth2/v2.0/token"
    payload = {
        "grant_type":    "authorization_code",
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code":          code,
        "redirect_uri":  REDIRECT_URI,
        "code_verifier": code_verifier
    }
    resp = requests.post(token_url,
                         data=payload,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
    if resp.status_code != 200:
        print(f"❌ Token endpoint returned HTTP {resp.status_code}")
        print("Response body:", resp.text)
        exit(1)
    return resp.json()

def validate_id_token(id_token):
    meta_url = f"https://{TENANT_NAME}.ciamlogin.com/{TENANT_GUID}/v2.0/.well-known/openid-configuration"
    metadata = requests.get(meta_url).json()
    jwks     = requests.get(metadata["jwks_uri"]).json()
    keys     = {jwk["kid"]: RSAAlgorithm.from_jwk(json.dumps(jwk)) for jwk in jwks["keys"]}
    kid      = jwt.get_unverified_header(id_token)["kid"]
    key      = keys.get(kid)
    if not key:
        raise Exception(f"No matching JWK for kid {kid}")
    return jwt.decode(
        id_token,
        key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=metadata["issuer"]
    )

def main():
    print("=== CIAM Auth Code + PKCE Demo ===\n")

    # Generate PKCE values
    code_verifier, code_challenge = generate_pkce()
    print(f"code_verifier: {code_verifier}")
    print(f"code_challenge: {code_challenge}\n")

    # Show authorize URL
    auth_url = build_authorize_url(code_challenge)
    print("1) Open this URL in a private browser:\n")
    print(auth_url + "\n")

    # Paste redirected URL
    print(f"2) After sign-in, you will be redirected to {REDIRECT_URI}?code=...&session_state=...")
    raw = input("3) Paste the full redirected URL here: ").strip()
    raw = raw.split('#', 1)[0]

    # Extract the code
    qs   = urllib.parse.urlparse(raw).query
    code = urllib.parse.parse_qs(qs).get("code", [None])[0]
    if not code:
        print("❌ No code found in URL, check your paste.")
        return

    # Redeem and validate
    tokens = redeem_token(code, code_verifier)
    print("\nTokens:")
    print(json.dumps(tokens, indent=2))

    if "id_token" in tokens:
        claims = validate_id_token(tokens["id_token"])
        print("\nDecoded ID token claims:")
        print(json.dumps(claims, indent=2))
    else:
        print("❌ ID token not found in response.")

if __name__ == "__main__":
    main()