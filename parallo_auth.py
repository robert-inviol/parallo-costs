#!/usr/bin/env python3
"""
Parallo Portal Authentication Flow

This script authenticates to the Parallo portal via Azure AD B2C federation
and obtains the tokens needed to query Power BI reports.

Authentication flow:
1. Navigate to portal.parallo.support/auth/login
2. B2C redirects to cpmportalprod.b2clogin.com
3. User authenticates via federated Azure AD
4. B2C returns id_token to portal
5. Portal sets session cookies
6. Session is used to get Power BI embed token
"""

import re
import json
import base64
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from html.parser import HTMLParser


class FormParser(HTMLParser):
    """Parse HTML forms to extract action URL and hidden inputs."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET'),
                'inputs': {}
            }
        elif tag == 'input' and self.current_form is not None:
            name = attrs_dict.get('name')
            value = attrs_dict.get('value', '')
            input_type = attrs_dict.get('type', 'text')
            if name:
                self.current_form['inputs'][name] = {
                    'value': value,
                    'type': input_type
                }

    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None


class ParalloAuth:
    """Handle authentication to Parallo portal."""

    # B2C Configuration
    B2C_TENANT = "cpmportalprod.onmicrosoft.com"
    B2C_POLICY = "B2C_1A_signup_signin"
    B2C_CLIENT_ID = "65015868-ad8c-44f8-902a-34baa7821e5b"

    # Azure AD (federated identity provider)
    AAD_CLIENT_ID = "ef8f4463-26a5-4961-8af5-721a428814ae"

    # Portal
    PORTAL_BASE = "https://portal.parallo.support"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.id_token = None
        self.access_token = None
        self.cookies = {}
        self.aad_base = "https://login.microsoftonline.com"  # Default, updated during auth

    def start_login_flow(self):
        """
        Start the login flow by hitting the portal login endpoint.
        Returns the B2C authorization URL.
        """
        print("[1] Starting login flow...")

        # Hit the login endpoint - this will redirect to B2C
        resp = self.session.get(
            f"{self.PORTAL_BASE}/auth/login",
            allow_redirects=False
        )

        if resp.status_code != 302:
            raise Exception(f"Expected redirect, got {resp.status_code}")

        b2c_url = resp.headers.get('Location')
        print(f"    Redirected to B2C: {b2c_url[:80]}...")

        return b2c_url

    def get_b2c_login_page(self, b2c_url):
        """
        Get the B2C login page and extract the CSRF token and state.
        """
        print("[2] Loading B2C login page...")

        resp = self.session.get(b2c_url)

        if resp.status_code != 200:
            raise Exception(f"Failed to load B2C page: {resp.status_code}")

        # Extract the CSRF token
        csrf_match = re.search(r'"csrf"\s*:\s*"([^"]+)"', resp.text)
        if not csrf_match:
            # Try alternative pattern
            csrf_match = re.search(r'csrf_token["\']?\s*[:=]\s*["\']([^"\']+)', resp.text)

        csrf_token = csrf_match.group(1) if csrf_match else None

        # Extract the transaction ID
        tx_match = re.search(r'"transId"\s*:\s*"([^"]+)"', resp.text)
        trans_id = tx_match.group(1) if tx_match else None

        # Extract state properties from the URL
        parsed = urlparse(b2c_url)
        params = parse_qs(parsed.query)

        print(f"    CSRF token: {csrf_token[:20] if csrf_token else 'Not found'}...")
        print(f"    Transaction ID: {trans_id if trans_id else 'Not found'}")

        return {
            'csrf_token': csrf_token,
            'trans_id': trans_id,
            'state': params.get('state', [''])[0],
            'nonce': params.get('nonce', [''])[0],
            'response': resp
        }

    def initiate_aad_federation(self, b2c_state):
        """
        Click the Azure AD login button (federated identity provider).
        This redirects to login.microsoftonline.com
        """
        print("[3] Initiating Azure AD federation...")

        # Build the URL to initiate Azure AD login
        # This is the "claims exchange" endpoint
        federation_url = (
            f"https://cpmportalprod.b2clogin.com/{self.B2C_TENANT}/"
            f"{self.B2C_POLICY}/api/CombinedSigninAndSignup/unified"
        )

        params = {
            'claimsexchange': 'AzureADCommonExchange',
            'csrf_token': b2c_state['csrf_token'],
            'tx': f"StateProperties={b2c_state['trans_id']}" if b2c_state['trans_id'] else '',
            'p': self.B2C_POLICY
        }

        resp = self.session.get(federation_url, params=params, allow_redirects=False)

        if resp.status_code == 302:
            aad_url = resp.headers.get('Location')
            print(f"    Redirected to AAD: {aad_url[:80]}...")
            return aad_url
        else:
            raise Exception(f"Expected redirect to AAD, got {resp.status_code}")

    def authenticate_with_aad(self, aad_url, username, password):
        """
        Authenticate with Azure AD using the provided credentials.
        This is the main authentication step.
        """
        print("[4] Authenticating with Azure AD...")

        # Load the Azure AD login page
        resp = self.session.get(aad_url)

        if resp.status_code != 200:
            raise Exception(f"Failed to load AAD login page: {resp.status_code}")

        # Check if already signed in (SSO) - look for auto-submit form
        code_match = re.search(r'name="code"\s+value="([^"]+)"', resp.text)
        if code_match:
            print("    SSO detected - already authenticated")
            state_match = re.search(r'name="state"\s+value="([^"]+)"', resp.text)
            return {
                'type': 'code',
                'code': code_match.group(1),
                'state': state_match.group(1) if state_match else None,
                'html': resp.text
            }

        # Extract the $Config object that contains all the login parameters
        config_text = resp.text

        # Extract flow token from script
        ft_match = re.search(r'"sFT"\s*:\s*"([^"]+)"', config_text)
        flow_token = ft_match.group(1) if ft_match else None

        # Extract context
        ctx_match = re.search(r'"sCtx"\s*:\s*"([^"]+)"', config_text)
        context = ctx_match.group(1) if ctx_match else None

        # Extract canary
        canary_match = re.search(r'"canary"\s*:\s*"([^"]+)"', config_text)
        canary = canary_match.group(1) if canary_match else None

        # Extract hpgid (page ID)
        hpgid_match = re.search(r'"hpgid"\s*:\s*(\d+)', config_text)
        hpgid = hpgid_match.group(1) if hpgid_match else "1002"

        print(f"    Flow token found: {bool(flow_token)}")
        print(f"    Context found: {bool(context)}")

        # Get the post URL - need to handle relative URLs
        parsed_aad = urlparse(aad_url)
        aad_base = f"https://{parsed_aad.netloc}"
        self.aad_base = aad_base  # Store for use in KMSI handler

        post_url_match = re.search(r'"urlPost"\s*:\s*"([^"]+)"', config_text)
        if post_url_match:
            post_url = post_url_match.group(1).replace('\\u0026', '&')
            # Handle relative URLs
            if post_url.startswith('/'):
                post_url = f"{aad_base}{post_url}"
        else:
            # Default post URL
            post_url = f"{aad_base}/common/login"

        # Step 1: Submit username first (AAD uses a 2-step login)
        print("    Submitting username...")
        username_data = {
            'login': username,
            'loginfmt': username,
            'type': '11',
            'LoginOptions': '3',
            'lrt': '',
            'lrtPartition': '',
            'hisRegion': '',
            'hisScaleUnit': '',
            'PPSX': '',
            'NewUser': '1',
            'FoundMSAs': '',
            'fspost': '0',
            'i21': '0',
            'CookieDisclosure': '0',
            'IsFidoSupported': '1',
            'isSignupPost': '0',
            'i19': str(len(username)),
            'canary': canary or '',
            'ctx': context or '',
            'hpgrequestid': '',
            'flowToken': flow_token or '',
            'PPFT': flow_token or '',
            'i13': '0',
            'ps': '2',
            'psRNGCDefaultType': '',
            'psRNGCEntropy': '',
            'psRNGCSLK': '',
            'i2': '1',
            'i17': '0',
            'i18': '',
            'i19': str(len(username)),
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://login.microsoftonline.com',
            'Referer': aad_url
        }

        resp = self.session.post(
            post_url.replace('\\', ''),
            data=username_data,
            headers=headers,
            allow_redirects=False
        )

        # Check response - might redirect or return password page
        if resp.status_code in [301, 302]:
            # Follow redirect
            resp = self.session.get(resp.headers['Location'])

        # Now extract new flow token for password submission
        ft_match = re.search(r'"sFT"\s*:\s*"([^"]+)"', resp.text)
        flow_token = ft_match.group(1) if ft_match else flow_token

        ctx_match = re.search(r'"sCtx"\s*:\s*"([^"]+)"', resp.text)
        context = ctx_match.group(1) if ctx_match else context

        canary_match = re.search(r'"canary"\s*:\s*"([^"]+)"', resp.text)
        canary = canary_match.group(1) if canary_match else canary

        post_url_match = re.search(r'"urlPost"\s*:\s*"([^"]+)"', resp.text)
        if post_url_match:
            new_post_url = post_url_match.group(1).replace('\\u0026', '&')
            # Handle relative URLs
            if new_post_url.startswith('/'):
                post_url = f"{aad_base}{new_post_url}"
            else:
                post_url = new_post_url

        # Step 2: Submit password
        print("    Submitting password...")
        password_data = {
            'login': username,
            'loginfmt': username,
            'passwd': password,
            'type': '11',
            'LoginOptions': '3',
            'lrt': '',
            'lrtPartition': '',
            'hisRegion': '',
            'hisScaleUnit': '',
            'PPSX': '',
            'NewUser': '1',
            'FoundMSAs': '',
            'fspost': '0',
            'i21': '0',
            'CookieDisclosure': '0',
            'IsFidoSupported': '1',
            'isSignupPost': '0',
            'canary': canary or '',
            'ctx': context or '',
            'flowToken': flow_token or '',
            'PPFT': flow_token or '',
            'i2': '1',
            'i17': '0',
            'i18': '',
            'i19': str(len(password)),
        }

        resp = self.session.post(
            post_url.replace('\\', ''),
            data=password_data,
            headers=headers,
            allow_redirects=False
        )

        print(f"    Login response: {resp.status_code}")

        # Handle the response - might need to follow redirects or parse form
        return self._handle_aad_response(resp)

    def _handle_aad_response(self, resp):
        """Handle the AAD response after credential submission."""

        # Check for immediate redirect
        if resp.status_code in [301, 302]:
            location = resp.headers.get('Location')
            print(f"    Redirect to: {location[:80]}...")

            # Follow redirects until we get a final response
            while resp.status_code in [301, 302]:
                location = resp.headers.get('Location')
                resp = self.session.get(location, allow_redirects=False)

            # Now process the final response
            return self._handle_aad_response(resp)

        # Check for form post (common in OIDC flows)
        if resp.status_code == 200:
            # Look for auto-submitting form with code
            code_match = re.search(r'name="code"\s+value="([^"]+)"', resp.text)
            state_match = re.search(r'name="state"\s+value="([^"]+)"', resp.text)

            if code_match:
                print("    Found authorization code in response")
                return {
                    'type': 'code',
                    'code': code_match.group(1),
                    'state': state_match.group(1) if state_match else None,
                    'html': resp.text
                }

            # Check for id_token (implicit flow)
            id_token_match = re.search(r'name="id_token"\s+value="([^"]+)"', resp.text)
            if id_token_match:
                print("    Found id_token in response")
                state_match = re.search(r'name="state"\s+value="([^"]+)"', resp.text)
                return {
                    'type': 'id_token',
                    'id_token': id_token_match.group(1),
                    'state': state_match.group(1) if state_match else None,
                    'html': resp.text
                }

            # Check for error
            error_match = re.search(r'"strServiceExceptionMessage"\s*:\s*"([^"]+)"', resp.text)
            if error_match:
                raise Exception(f"AAD Error: {error_match.group(1)}")

            # Check for error description
            error_desc_match = re.search(r'"sErrTxt"\s*:\s*"([^"]+)"', resp.text)
            if error_desc_match:
                raise Exception(f"AAD Error: {error_desc_match.group(1)}")

            # May need to handle 2FA or other steps
            if 'kmsi' in resp.text.lower() or 'stay signed in' in resp.text.lower():
                print("    KMSI (Keep me signed in) prompt detected")
                return self._handle_kmsi(resp)

            # Check for password page (may need to submit password separately)
            if 'passwd' in resp.text.lower() and '"sFT"' in resp.text:
                print("    Password page detected")
                return {'type': 'password_page', 'html': resp.text}

        return {'type': 'unknown', 'status': resp.status_code, 'html': resp.text[:2000]}

    def _handle_kmsi(self, resp):
        """Handle the 'Keep Me Signed In' prompt."""
        print("    Handling KMSI prompt (selecting 'No')...")

        # Extract necessary tokens
        ft_match = re.search(r'"sFT"\s*:\s*"([^"]+)"', resp.text)
        flow_token = ft_match.group(1) if ft_match else None

        ctx_match = re.search(r'"sCtx"\s*:\s*"([^"]+)"', resp.text)
        context = ctx_match.group(1) if ctx_match else None

        canary_match = re.search(r'"canary"\s*:\s*"([^"]+)"', resp.text)
        canary = canary_match.group(1) if canary_match else None

        # Get the KMSI post URL
        post_url_match = re.search(r'"urlPost"\s*:\s*"([^"]+)"', resp.text)
        if not post_url_match:
            raise Exception("Could not find KMSI post URL")

        post_url = post_url_match.group(1).replace('\\u0026', '&')
        # Handle relative URLs
        if post_url.startswith('/'):
            post_url = f"{self.aad_base}{post_url}"

        # Submit KMSI response (LoginOptions=1 = Don't stay signed in)
        kmsi_data = {
            'LoginOptions': '1',
            'type': '28',
            'ctx': context or '',
            'hpgrequestid': '',
            'flowToken': flow_token or '',
            'canary': canary or '',
            'i19': '2326',
        }

        resp = self.session.post(
            post_url,
            data=kmsi_data,
            allow_redirects=False
        )

        return self._handle_aad_response(resp)

    def complete_b2c_flow(self, aad_result):
        """
        Complete the B2C flow by submitting the AAD response back to B2C,
        which then redirects to the portal with the id_token.
        """
        print("[5] Completing B2C flow...")

        if aad_result['type'] == 'code':
            # Post the code to B2C's oauth2/authresp endpoint
            b2c_authresp_url = (
                f"https://cpmportalprod.b2clogin.com/{self.B2C_TENANT}/oauth2/authresp"
            )

            data = {
                'code': aad_result['code'],
                'state': aad_result.get('state', '')
            }

            resp = self.session.post(
                b2c_authresp_url,
                data=data,
                allow_redirects=False
            )

            print(f"    B2C authresp response: {resp.status_code}")

            # This might return another form with id_token to POST to portal
            if resp.status_code == 200:
                # Look for id_token form - try multiple patterns
                id_token_match = re.search(r'name="id_token"\s+value="([^"]+)"', resp.text)
                if not id_token_match:
                    id_token_match = re.search(r'name=.id_token.\s+value=.([^"\']+)', resp.text)
                if not id_token_match:
                    # Try looking for it in a different format
                    id_token_match = re.search(r'"id_token"[^>]*value="([^"]+)"', resp.text)

                state_match = re.search(r'name="state"\s+value="([^"]+)"', resp.text)
                if not state_match:
                    state_match = re.search(r'name=.state.\s+value=.([^"\']+)', resp.text)

                if id_token_match:
                    print("    Found id_token, posting to portal...")
                    return self._post_to_portal_signin(
                        id_token_match.group(1),
                        state_match.group(1) if state_match else ''
                    )
                else:
                    # Debug: print what we got
                    print(f"    No id_token found in B2C response")
                    print(f"    Response contains 'id_token': {'id_token' in resp.text}")
                    print(f"    Response contains 'form': {'<form' in resp.text.lower()}")
                    # Save response for debugging
                    with open('b2c_response.html', 'w') as f:
                        f.write(resp.text)
                    print("    Saved response to b2c_response.html for debugging")

            # This should redirect to portal with id_token
            if resp.status_code in [301, 302]:
                return self._follow_portal_redirect(resp.headers.get('Location'))

            # If we got here with a 200, we might need to handle the response differently
            # The B2C page might be an auto-submit form - return so we can debug
            return resp

        elif aad_result['type'] == 'id_token':
            # Direct id_token - post to portal
            return self._post_to_portal_signin(
                aad_result['id_token'],
                aad_result.get('state', '')
            )

        elif aad_result['type'] == 'redirect':
            # Follow the redirect chain
            return self._follow_redirects(aad_result['location'])

        raise Exception(f"Unexpected AAD result type: {aad_result['type']}")

    def _post_to_portal_signin(self, id_token, state):
        """Post the id_token to the portal's signin-oidc endpoint."""
        print("    Posting id_token to portal signin-oidc...")

        data = {
            'id_token': id_token,
            'state': state
        }

        resp = self.session.post(
            f"{self.PORTAL_BASE}/signin-oidc",
            data=data,
            allow_redirects=False
        )

        print(f"    Portal signin response: {resp.status_code}")

        if resp.status_code in [301, 302]:
            location = resp.headers.get('Location')
            if not location.startswith('http'):
                location = f"{self.PORTAL_BASE}{location}"
            print(f"    Redirected to: {location}")

            # Follow redirect to home page
            resp = self.session.get(location)

        self.id_token = id_token
        return resp

    def _follow_portal_redirect(self, url):
        """Follow redirects back to the portal."""
        print(f"    Following redirect: {url[:80]}...")

        resp = self.session.get(url, allow_redirects=False)

        while resp.status_code in [301, 302]:
            url = resp.headers.get('Location')
            if not url.startswith('http'):
                url = f"{self.PORTAL_BASE}{url}"
            print(f"    -> {url[:60]}...")
            resp = self.session.get(url, allow_redirects=False)

        return resp

    def _follow_redirects(self, url, max_redirects=10):
        """Follow a chain of redirects."""
        for _ in range(max_redirects):
            resp = self.session.get(url, allow_redirects=False)

            if resp.status_code not in [301, 302]:
                return resp

            url = resp.headers.get('Location')
            if not url.startswith('http'):
                # Relative URL - need to determine base
                parsed = urlparse(resp.url if hasattr(resp, 'url') else url)
                url = f"{parsed.scheme}://{parsed.netloc}{url}"

            print(f"    -> {url[:60]}...")

        raise Exception("Too many redirects")

    def get_powerbi_embed_token(self):
        """
        After authentication, get the Power BI embed token.
        The portal renders a page with the embed configuration.
        """
        print("[6] Getting Power BI embed token...")

        # Navigate to a page that shows Power BI reports
        # This might be the main dashboard or a specific reports page
        resp = self.session.get(f"{self.PORTAL_BASE}/")

        # Look for Power BI configuration in the response
        # The portal uses Blazor and calls a JavaScript function with the token

        # Look for the embed URL pattern
        embed_match = re.search(
            r'embedUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            resp.text
        )
        token_match = re.search(
            r'accessToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            resp.text
        )

        if token_match:
            self.access_token = token_match.group(1)
            print(f"    Found access token: {self.access_token[:50]}...")

        return {
            'embed_url': embed_match.group(1) if embed_match else None,
            'access_token': self.access_token,
            'cookies': dict(self.session.cookies)
        }

    def login(self, username, password):
        """
        Complete login flow.

        Args:
            username: Azure AD email address
            password: Azure AD password

        Returns:
            dict with tokens and session info
        """
        try:
            # Step 1: Start login flow
            b2c_url = self.start_login_flow()

            # Step 2: Get B2C login page
            b2c_state = self.get_b2c_login_page(b2c_url)

            # Step 3: Initiate Azure AD federation
            aad_url = self.initiate_aad_federation(b2c_state)

            # Step 4: Authenticate with Azure AD
            aad_result = self.authenticate_with_aad(aad_url, username, password)

            # Step 5: Complete B2C flow
            self.complete_b2c_flow(aad_result)

            # Step 6: Get Power BI token
            embed_info = self.get_powerbi_embed_token()

            print("\n[SUCCESS] Authentication complete!")
            return embed_info

        except Exception as e:
            print(f"\n[ERROR] Authentication failed: {e}")
            raise


    def save_session(self, filepath='session.json'):
        """Save session cookies and tokens to a file."""
        data = {
            'cookies': dict(self.session.cookies),
            'id_token': self.id_token,
            'access_token': self.access_token,
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Session saved to {filepath}")

    def load_session(self, filepath='session.json'):
        """Load session cookies and tokens from a file."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            for name, value in data.get('cookies', {}).items():
                self.session.cookies.set(name, value)
            self.id_token = data.get('id_token')
            self.access_token = data.get('access_token')
            print(f"Session loaded from {filepath}")
            return True
        except FileNotFoundError:
            return False

    def is_authenticated(self):
        """Check if the session is still valid."""
        resp = self.session.get(f"{self.PORTAL_BASE}/", allow_redirects=False)
        # If we get redirected to login, session is invalid
        return resp.status_code == 200


def main():
    """Main entry point."""
    import os
    import sys
    import getpass

    print("=" * 60)
    print("Parallo Portal Authentication")
    print("=" * 60)
    print()

    auth = ParalloAuth()

    # Try to load existing session
    if auth.load_session() and auth.is_authenticated():
        print("Using existing session")
        result = auth.get_powerbi_embed_token()
    else:
        # Get credentials
        username = os.environ.get('PARALLO_USERNAME')
        password = os.environ.get('PARALLO_PASSWORD')

        if not username:
            username = input("Azure AD Email: ")
        if not password:
            password = getpass.getpass("Password: ")

        print()

        # Authenticate
        result = auth.login(username, password)

        # Save session for future use
        auth.save_session()

    print()
    print("=" * 60)
    print("Result:")
    print(json.dumps({
        'embed_url': result.get('embed_url'),
        'access_token': result.get('access_token', '')[:50] + '...' if result.get('access_token') else None,
        'cookies': list(result.get('cookies', {}).keys())
    }, indent=2))

    # Return exit code based on success
    sys.exit(0 if result.get('access_token') or result.get('cookies') else 1)


if __name__ == '__main__':
    main()
