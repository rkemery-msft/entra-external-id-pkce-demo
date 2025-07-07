# Entra External ID PKCE Demo

A Python sample demonstrating the OAuth 2.0 Authorization Code flow with PKCE against a Microsoft Entra External ID (CIAM) tenant. This shows how to securely:

1. Generate PKCE values  
2. Build and launch the `/authorize` URL for self-service sign-up/sign-in via email OTP  
3. Exchange the one-time code for tokens (including a refresh token) using your client secret  
4. Validate the returned ID token against your tenant’s JWKS  

⚠️ Warning:

This code is not production-ready. It lacks robust error handling, secure token storage, input validation, and other critical security features required for real-world applications.

Do not use this script as-is in production environments.

Always follow [Microsoft’s security best practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices) when implementing authentication flows in your applications.

---

## Prerequisites

- **Python 3.7+**  
- **pip**  
- An **Entra External ID** tenant (e.g. `yourtenant.onmicrosoft.com`) with:  
  - A Sign-up & Sign-in user flow configured  
  - An App Registration bound to that flow  
  - **Email One-Time Passcode** enabled  
- Your App Registration’s:  
  - **Application (client) ID**  
  - **Client secret**  
  - **Directory (tenant) ID**  
- A registered **Redirect URI** (e.g. `https://jwt.ms` for testing)

---

## Setup

1. **Clone the repo**  
   ```bash
   git clone https://github.com/your-org/entra-external-id-pkce-demo.git
   cd entra-external-id-pkce-demo
   ```

2. **Install dependencies**  
   ```bash
   pip3 install "PyJWT[crypto]"
   ```

3. **Configure environment variables**  
   ```bash
   export TENANT_NAME="<YOUR_TENANT_NAME>"       # e.g. demo-tenant (no .ciamlogin.com)
   export TENANT_GUID="<YOUR_TENANT_GUID>"
   export CLIENT_ID="<YOUR_CLIENT_ID>"
   export CLIENT_SECRET="<YOUR_CLIENT_SECRET>"
   export REDIRECT_URI="https://jwt.ms"
   export NONCE="randomString1234"
   ```

---

## Usage

Run the demo script and follow the prompts:

   ```bash
   python3 entra_external_id_pkce_demo.py
   ```

1. The script prints a **code_verifier** & **code_challenge**.  
2. It displays the `/authorize` URL—open it in a private/incognito browser.  
3. Sign up or sign in using your test email (e.g. `alice.test@gmail.com`), complete OTP.  
4. The browser redirects to `REDIRECT_URI?code=…&session_state=…`.  
5. **Copy** the full redirect URL and **paste** it back into the script.  
6. The script exchanges the code for tokens, validates the ID token, and prints decoded claims.

---

## How It Works

- **PKCE (Proof Key for Code Exchange)**  
  Prevents code interception by requiring a `code_verifier` at token exchange.  
- **Auth Code Flow**  
  Tokens are retrieved via a back-channel POST—never exposed in URL fragments.  
- **Token Validation**  
  The script fetches your tenant’s OpenID metadata and JWKS, then cryptographically verifies the ID token’s signature and standard claims (`aud`, `iss`, `nonce`, timestamps).

---

## Security Considerations

- **No Implicit Grant**: avoids tokens in the browser URL  
- **Proof-of-Possession**: PKCE binds the auth code to your client  
- **Refresh Tokens**: supports silent token renewal without re-authentication  
- **JWKS Validation**: dynamic key fetch guards against key rollover  
- **Environment Variables**: no secrets checked into source control

---

## References

- [OAuth 2.0 authorization code flow with PKCE (Microsoft identity platform)](https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow?tabs=python)  
- [Quickstart: Create an external tenant (Microsoft Entra External ID)](https://learn.microsoft.com/azure/active-directory/external-identities/quickstart-create-external-tenant)  
- [Overview: User flows in Entra External ID](https://learn.microsoft.com/azure/active-directory/external-identities/user-flow-overview)  
- [Quickstart: Sign in users in a Single-Page App (SPA)](https://learn.microsoft.com/azure/active-directory/develop/quickstart-v2-javascript)