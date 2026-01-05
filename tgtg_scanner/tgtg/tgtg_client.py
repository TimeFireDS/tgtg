# Copied and modified from https://github.com/ahivert/tgtg-python
# Enhanced TGTG Client with retry plugin behavior

import json
import logging
import re
import time
import uuid
from datetime import datetime
from http import HTTPStatus
from typing import Optional
from urllib.parse import urljoin, urlsplit, quote
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from tgtg_scanner.errors import (
    TgtgAPIError as _TgtgAPIError,
    TGTGConfigurationError,
    TgtgLoginError,
    TgtgPollingError,
)

# Enhanced TgtgAPIError with proper attributes
class TgtgAPIError(_TgtgAPIError):
    def __init__(self, status_code=None, message=""):
        self.status_code = status_code
        self.message = str(message)
        super().__init__(f"({status_code}, {self.message})")

log = logging.getLogger("tgtg")
# Using the correct base URL
BASE_URL = "https://api.toogoodtogo.com/api/"
API_ITEM_ENDPOINT = "item/v8/"
FAVORITE_ITEM_ENDPOINT = "user/favorite/v1/{}/update"
AUTH_BY_EMAIL_ENDPOINT = "auth/v5/authByEmail"
AUTH_POLLING_ENDPOINT = "auth/v5/authByRequestPollingId"
AUTH_BY_PIN_ENDPOINT = "auth/v5/authByRequestPin"
SIGNUP_BY_EMAIL_ENDPOINT = "auth/v5/signUpByEmail"
REFRESH_ENDPOINT = "token/v1/refresh"
ACTIVE_ORDER_ENDPOINT = "order/v8/active"
INACTIVE_ORDER_ENDPOINT = "order/v8/inactive"
CREATE_ORDER_ENDPOINT = "order/v8/create/"
ABORT_ORDER_ENDPOINT = "order/v8/{}/abort"
ORDER_STATUS_ENDPOINT = "order/v8/{}/status"
API_BUCKET_ENDPOINT = "discover/v1/bucket"
MANUFACTURERITEM_ENDPOINT = "manufactureritem/v2/"
DATADOME_SDK_ENDPOINT = "https://api-sdk.datadome.co/sdk/"

USER_AGENTS = [
    "TGTG/{} Dalvik/2.1.0 (Linux; U; Android 14; Pixel 7 Pro Build/UQ1A.240105.004)",
]
DEFAULT_ACCESS_TOKEN_LIFETIME = 3600 * 4  # 4 hours
DEFAULT_MAX_POLLING_TRIES = 24
DEFAULT_POLLING_WAIT_TIME = 5
DEFAULT_APK_VERSION = "24.11.0"

APK_RE_SCRIPT = re.compile(r"AF_initDataCallback\({key:\s*'ds:5'.*?data:([\s\S]*?), sideChannel:.+<\/script")


@dataclass
class DataDomeConfig:
    """Configuration for DataDome cookie generation"""
    device_model: str = "Pixel 7 Pro"
    device_product: str = "Pixel 7 Pro"
    manufacturer: str = "Google"
    device: str = "cheetah"
    hardware: str = "GS201"
    fingerprint: str = "google/cheetah/cheetah:14/UQ1A.240105.004/10814564:user/release-keys"
    os_version: str = "14"
    os_release: str = "34"
    screen_x: str = "1440"
    screen_y: str = "3120"
    screen_density: str = "3.5"
    camera_info: str = '{"auth":"true", "info":"{\\"front\\":\\"2000x1500\\",\\"back\\":\\"5472x3648\\"}"}'
    os_name: str = "UPSIDE_DOWN_CAKE"
    tags: str = "release-keys"


class DataDomeCookieManager:
    """Manages DataDome cookie generation"""
    
    def __init__(self, base_url: str, timeout: int = 30, proxies: dict = None, apk_version: str = None):
        self.base_url = base_url
        self.timeout = timeout
        self.proxies = proxies
        self.config = DataDomeConfig()
        self.apk_version = apk_version or DEFAULT_APK_VERSION
    
    def generate_datadome_cookie(self, original_request_path: str) -> Optional[str]:
        """
        Generates DataDome cookie.
        Returns the cookie string (name=value) or None.
        """
        try:
            # Generate unique IDs
            cid = uuid.uuid4().hex[:64]
            d_ifv = uuid.uuid4().hex
            
            # Encode the request URL
            request_url = quote(f"{self.base_url}{original_request_path}", safe='')
            
            # Build user agent matching main requests
            user_agent = USER_AGENTS[0].format(self.apk_version)
            
            # Current timestamp
            timestamp = int(time.time() * 1000)
            
            # Events JSON
            events = f'[%7B%22id%22:1,%22message%22:%22response%20validation%22,%22source%22:%22sdk%22,%22date%22:{timestamp}%7D]'
            
            # Build form data
            form_data = {
                'cid': cid,
                'ddk': '1D42C2CA6131C526E09F294FE96F94',
                'request': request_url,
                'ua': user_agent,
                'events': events,
                'inte': 'android-java-okhttp',
                'ddv': '3.0.4',
                'ddvc': self.apk_version,
                'os': 'Android',
                'osr': self.config.os_version,
                'osn': self.config.os_name,
                'osv': self.config.os_release,
                'screen_x': self.config.screen_x,
                'screen_y': self.config.screen_y,
                'screen_d': self.config.screen_density,
                'camera': self.config.camera_info,
                'mdl': self.config.device_model,
                'prd': self.config.device_product,
                'mnf': self.config.manufacturer,
                'dev': self.config.device,
                'hrd': self.config.hardware,
                'fgp': self.config.fingerprint,
                'tgs': self.config.tags,
                'd_ifv': d_ifv,
            }
            
            headers = {
                'User-Agent': 'okhttp/5.1.0',
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            
            log.info(f"Requesting DataDome cookie for: {original_request_path}")
            log.debug(f"APK version: {self.apk_version}")
            log.debug(f"CID: {cid[:32]}...")
            log.debug(f"API User-Agent: {user_agent}")
            
            response = requests.post(
                DATADOME_SDK_ENDPOINT,
                data=form_data,
                headers=headers,
                timeout=self.timeout,
                proxies=self.proxies
            )
            
            log.info(f"DataDome SDK response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                log.debug(f"DataDome response keys: {list(data.keys())}")
                
                cookie_full = data.get('cookie', '')
                # Extract just the cookie value before the first semicolon
                cookie = cookie_full.split(';')[0] if cookie_full else None
                
                if cookie:
                    log.info(f"✓ DataDome cookie generated successfully")
                    log.debug(f"Cookie value: {cookie[:60]}...")
                    return cookie
                else:
                    log.warning("✗ No 'cookie' field in DataDome response")
                    log.debug(f"Full response: {data}")
            else:
                log.warning(f"✗ DataDome SDK returned {response.status_code}")
                log.debug(f"Response body: {response.text[:500]}")
                
        except Exception as e:
            log.error(f"✗ DataDome cookie generation exception: {e}", exc_info=True)
        
        return None


class TgtgSession(requests.Session):
    """Enhanced session with retry behavior"""
    
    def __init__(
        self,
        user_agent: str | None = None,
        language: str = "en-UK",
        timeout: int | None = None,
        proxies: dict | None = None,
        datadome_cookie: str | None = None,
        base_url: str = BASE_URL,
        correlation_id: str | None = None,
        enable_auto_retry: bool = False,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        
        # Configure retry strategy
        if enable_auto_retry:
            retry_strategy = Retry(
                total=2,  # maxRetries = 2
                status_forcelist=[403, 500, 502, 503, 504],  # Retry 403
                allowed_methods=["POST"],  # retries POST
                backoff_factor=0.5,
                raise_on_status=False,  # Don't raise, let us handle it
            )
        else:
            retry_strategy = Retry(
                total=5,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET", "POST"],
                backoff_factor=1,
            )
        
        http_adapter = HTTPAdapter(max_retries=retry_strategy)
        self.mount("https://", http_adapter)
        self.mount("http://", http_adapter)
        
        self.correlation_id = correlation_id or str(uuid.uuid4())
        
        self.headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "accept-language": language,
            "accept-encoding": "gzip, deflate",
            "user-agent": user_agent or "",
            "x-correlation-id": self.correlation_id,
        }
        self.timeout = timeout
        if proxies:
            self.proxies = proxies
            
        # Set DataDome cookie if provided
        if datadome_cookie:
            # Parse cookie string (format: "datadome=VALUE" or just "VALUE")
            cookie_name = "datadome"
            cookie_value = datadome_cookie
            
            if "=" in datadome_cookie:
                parts = datadome_cookie.split("=", 1)
                cookie_name = parts[0].strip()
                cookie_value = parts[1].strip()
            
            domain = urlsplit(base_url).hostname
            # Don't add leading dot for localhost, do add it for real domains
            if domain and domain != "localhost":
                domain = f".{domain}"
            
            log.debug(f"Setting cookie '{cookie_name}' on domain '{domain}'")
            log.debug(f"Cookie value: {cookie_value[:50]}...")
            
            # Clear any existing datadome cookies first to prevent duplicates
            cookies_to_remove = [c for c in self.cookies if c.name == cookie_name]
            for cookie in cookies_to_remove:
                self.cookies.clear(domain=cookie.domain, path=cookie.path, name=cookie.name)
                log.debug(f"Cleared old cookie on domain {cookie.domain}")
            
            self.cookies.set(
                name=cookie_name,
                value=cookie_value,
                domain=domain,
                path="/",
                secure=True
            )

    def post(self, *args, access_token: str | None = None, **kwargs) -> requests.Response:
        if "headers" not in kwargs:
            kwargs["headers"] = self.headers.copy()
        if access_token:
            kwargs["headers"]["authorization"] = f"Bearer {access_token}"
        return super().post(*args, **kwargs)

    def send(self, request, **kwargs):
        for key in ["timeout", "proxies"]:
            val = kwargs.get(key)
            if val is None and hasattr(self, key):
                kwargs[key] = getattr(self, key)
        return super().send(request, **kwargs)


class TgtgClient:
    def __init__(
        self,
        base_url=BASE_URL,
        email=None,
        access_token=None,
        refresh_token=None,
        datadome_cookie=None,
        apk_version=None,
        user_agent=None,
        language="en-GB",
        proxies=None,
        timeout=None,
        access_token_lifetime=DEFAULT_ACCESS_TOKEN_LIFETIME,
        max_polling_tries=DEFAULT_MAX_POLLING_TRIES,
        polling_wait_time=DEFAULT_POLLING_WAIT_TIME,
        device_type="ANDROID",
        use_retry_plugin=True,
        pin_callback=None,
    ):
        if base_url != BASE_URL:
            log.warning("Using custom tgtg base url: %s", base_url)

        self.base_url = base_url
        self.email = email
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.datadome_cookie = datadome_cookie

        self.last_time_token_refreshed = None
        self.access_token_lifetime = access_token_lifetime
        self.max_polling_tries = max_polling_tries
        self.polling_wait_time = polling_wait_time

        self.device_type = device_type
        self.apk_version = apk_version or DEFAULT_APK_VERSION
        self.fixed_user_agent = user_agent
        self.user_agent = user_agent
        self.language = language
        self.proxies = proxies
        self.timeout = timeout
        self.session = None
        self.correlation_id = str(uuid.uuid4())
        
        # Enable retry plugin behavior
        self.use_retry_plugin = use_retry_plugin
        
        # Initialize DataDome manager
        self.datadome_manager = DataDomeCookieManager(
            base_url, 
            timeout or 30, 
            proxies,
            self.apk_version
        )

        self.pin_callback = pin_callback

    def __del__(self) -> None:
        if self.session:
            self.session.close()

    def _get_url(self, path) -> str:
        return urljoin(self.base_url, path)

    def _create_session(self, enable_auto_retry: bool = False) -> TgtgSession:
        """Create session with optional retry behavior"""
        if not self.user_agent:
            self.user_agent = self._get_user_agent()
        
        session = TgtgSession(
            self.user_agent,
            self.language,
            self.timeout,
            self.proxies,
            self.datadome_cookie,
            self.base_url,
            self.correlation_id,
            enable_auto_retry=enable_auto_retry,
        )
        
        log.debug(f"Session created - Correlation ID: {self.correlation_id[:16]}...")
        log.debug(f"Auto-retry enabled: {enable_auto_retry}")
        
        if self.datadome_cookie:
            log.debug(f"DataDome cookie set: {self.datadome_cookie[:50]}...")
            # Verify cookie was actually set in session
            try:
                # Check for any datadome cookies
                datadome_cookies = [c for c in session.cookies if c.name == "datadome"]
                if datadome_cookies:
                    log.debug(f"✓ Found {len(datadome_cookies)} datadome cookie(s) in session")
                    for cookie in datadome_cookies:
                        log.debug(f"  Domain: {cookie.domain}, Value: {cookie.value[:50]}...")
                else:
                    log.warning("✗ Cookie NOT found in session after setting!")
            except Exception as e:
                log.debug(f"Error checking cookies: {e}")
        else:
            log.debug("No DataDome cookie to set")
        
        return session

    def regenerate_correlation_id(self) -> None:
        """Regenerate correlation ID for fresh auth flows"""
        self.correlation_id = str(uuid.uuid4())
        if self.session:
            self.session.correlation_id = self.correlation_id
            self.session.headers["x-correlation-id"] = self.correlation_id
        log.debug(f"New correlation ID: {self.correlation_id[:16]}...")

    def get_credentials(self) -> dict:
        """Returns current tgtg api credentials"""
        self.login()
        return {
            "email": self.email,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "datadome_cookie": self.datadome_cookie,
            "correlation_id": self.correlation_id,
        }

    def _post_with_retry(self, path, **kwargs) -> requests.Response:
        """
        Mimics HttpRequestRetry plugin:
        - Retries on 403 (for cookie acquisition)
        - Retries on server errors (500+)
        - Maximum 2 retries
        """
        if not self.session:
            self.session = self._create_session(enable_auto_retry=True)
        
        max_retries = 2
        attempt = 0
        last_response = None
        
        while attempt <= max_retries:
            if attempt > 0:
                log.info(f"Retry attempt {attempt}/{max_retries} for {path}")
            
            log.debug(f"POST {self._get_url(path)} (attempt {attempt + 1})")
            
            # Log cookies being sent
            try:
                cookies_to_send = [c for c in self.session.cookies]
                if cookies_to_send:
                    log.debug(f"Session has {len(cookies_to_send)} cookie(s)")
                    for cookie in cookies_to_send:
                        log.debug(f"  {cookie.name} (domain: {cookie.domain}): {cookie.value[:50]}...")
                else:
                    log.debug("No cookies in session")
            except Exception as e:
                log.debug(f"Error listing cookies: {e}")
            
            response = self.session.post(
                self._get_url(path),
                access_token=self.access_token,
                **kwargs,
            )
            
            log.debug(f"Response: {response.status_code}")
            last_response = response  # Always save the response
            
            # Update DataDome cookie from response if present
            # Handle multiple cookies by getting all and using the most recent
            try:
                # Get all datadome cookies
                datadome_cookies = [c for c in self.session.cookies if c.name == "datadome"]
                if datadome_cookies:
                    # Use the most recently set cookie (last in list)
                    new_cookie = datadome_cookies[-1].value
                    if new_cookie and new_cookie != self.datadome_cookie:
                        self.datadome_cookie = new_cookie
                        log.debug(f"Cookie updated from response")
            except Exception as e:
                log.debug(f"Could not extract cookie from response: {e}")
            
            # Success
            if response.status_code in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
                return response
            
            # Handle 403 - try to get DataDome cookie
            if response.status_code == 403 and attempt < max_retries:
                log.warning(f"Got 403 on attempt {attempt + 1}")
                
                # Log the 403 response content for debugging
                try:
                    error_data = response.json()
                    log.debug(f"403 response body: {error_data}")
                    if "url" in error_data and "captcha" in str(error_data.get("url", "")).lower():
                        log.warning(f"Response contains CAPTCHA URL: {error_data.get('url')}")
                except Exception as e:
                    log.debug(f"Could not parse 403 response as JSON: {e}")
                    log.debug(f"Raw content (first 500 chars): {response.content[:500]}")
                
                # Try to generate new cookie FIRST
                log.info("Attempting DataDome cookie generation...")
                new_cookie = self.datadome_manager.generate_datadome_cookie(path)
                
                if new_cookie:
                    log.info("New cookie generated, recreating session...")
                    self.datadome_cookie = new_cookie
                    
                    # Recreate session with new cookie
                    if self.session:
                        self.session.close()
                    self.session = self._create_session(enable_auto_retry=True)
                    
                    attempt += 1
                    time.sleep(0.5)  # Small delay before retry
                    continue
                else:
                    log.error("Failed to generate DataDome cookie")
                    break
            
            # Retry on server errors
            if response.status_code >= 500 and attempt < max_retries:
                log.warning(f"Server error {response.status_code}, will retry...")
                attempt += 1
                time.sleep(1)
                continue
            
            # No more retries
            break
        
        # All retries exhausted or non-retryable error
        if last_response is not None:
            # Log final CAPTCHA info if present
            try:
                error_data = last_response.json()
                if "url" in error_data and "captcha" in str(error_data.get("url", "")).lower():
                    log.error(f"Final response contains CAPTCHA: {error_data.get('url')}")
            except:
                pass
            
            raise TgtgAPIError(last_response.status_code, last_response.content)
        else:
            raise TgtgAPIError(None, "Request failed without response")

    def _post(self, path, **kwargs) -> requests.Response:
        """
        Main POST method - delegates to retry or simple POST
        """
        if self.use_retry_plugin:
            return self._post_with_retry(path, **kwargs)
        else:
            # Simple mode without retry plugin
            if not self.session:
                self.session = self._create_session(enable_auto_retry=False)
            
            response = self.session.post(
                self._get_url(path),
                access_token=self.access_token,
                **kwargs,
            )
            
            # Update cookie
            new_cookie = self.session.cookies.get("datadome")
            if new_cookie:
                self.datadome_cookie = new_cookie
            
            if response.status_code in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
                return response
            
            raise TgtgAPIError(response.status_code, response.content)

    def _get_user_agent(self) -> str:
        if self.fixed_user_agent:
            return self.fixed_user_agent
        log.debug(f"Using APK version: {self.apk_version}")
        return USER_AGENTS[0].format(self.apk_version)

    @staticmethod
    def get_latest_apk_version() -> str:
        """Returns latest APK version from Google Play Store"""
        response = requests.get(
            "https://play.google.com/store/apps/details?id=com.app.tgtg&hl=en&gl=US",
            timeout=30,
        )
        match = APK_RE_SCRIPT.search(response.text)
        if not match:
            raise TgtgAPIError("Failed to get latest APK version from Google Play Store.")
        data = json.loads(match.group(1))
        return data[1][2][140][0][0][0]

    @property
    def _already_logged(self) -> bool:
        return bool(self.access_token and self.refresh_token)

    def _refresh_token(self) -> None:
        if (
            self.last_time_token_refreshed
            and (datetime.now() - self.last_time_token_refreshed).seconds <= self.access_token_lifetime
        ):
            return
        response = self._post(REFRESH_ENDPOINT, json={"refresh_token": self.refresh_token})
        self.access_token = response.json().get("access_token")
        self.refresh_token = response.json().get("refresh_token")
        self.last_time_token_refreshed = datetime.now()

    def ensure_datadome_cookie(self) -> None:
        """
        Ensures a DataDome cookie exists before making requests.
        Generates one if missing to avoid initial 403 errors.
        """
        if not self.datadome_cookie:
            log.info("No DataDome cookie found, generating preemptively...")
            # Generate for the auth endpoint since that's typically first
            cookie = self.datadome_manager.generate_datadome_cookie("auth/v5/authByEmail")
            if cookie:
                self.datadome_cookie = cookie
                log.info("✓ Preemptive cookie generated successfully")
                # Recreate session with the new cookie if it exists
                if self.session:
                    self.session.close()
                    self.session = None
            else:
                log.warning("⚠ Failed to generate preemptive cookie, will retry on 403")

    def login(self) -> None:
        if not (self.email or self.access_token and self.refresh_token):
            raise TGTGConfigurationError("You must provide at least email or access_token and refresh_token")
        
        if self._already_logged:
            self._refresh_token()
        else:
            # Fresh login - regenerate correlation ID
            self.regenerate_correlation_id()
            
            # Ensure we have a cookie BEFORE the first request
            self.ensure_datadome_cookie()

            log.info("Starting login process...")
            log.debug(f"User-Agent: {self._get_user_agent()}")
            log.debug(f"Correlation ID: {self.correlation_id[:16]}...")
            
            try:
                response = self._post(
                    AUTH_BY_EMAIL_ENDPOINT,
                    json={
                        "device_type": self.device_type,
                        "email": self.email,
                    },
                )
                
                log.debug(f"Auth response status: {response.status_code}")
                
                first_login_response = response.json()
                log.debug(f"Auth response: {first_login_response}")
                
                # Check for CAPTCHA challenge
                if "url" in first_login_response and "captcha" in str(first_login_response.get("url", "")).lower():
                    log.error("Received CAPTCHA challenge")
                    log.error(f"CAPTCHA URL: {first_login_response.get('url')}")
                    raise TgtgLoginError(
                        response.status_code,
                        "DataDome CAPTCHA challenge - bot protection is blocking the request"
                    )
                
                # Check for expected state
                if "state" not in first_login_response:
                    log.error(f"Unexpected response: {first_login_response}")
                    raise TgtgLoginError(
                        response.status_code,
                        f"Missing 'state' field: {first_login_response}"
                    )
                
                state = first_login_response["state"]
                
                if state == "TERMS":
                    raise TgtgPollingError(
                        f"Email {self.email} not linked to TGTG account. Please sign up first."
                    )
                elif state == "WAIT":
                    polling_id = first_login_response.get("polling_id")
                    if not polling_id:
                        raise TgtgLoginError(response.status_code, "No polling_id in response")
                    self.start_polling(polling_id)
                else:
                    raise TgtgLoginError(response.status_code, f"Unexpected state: {state}")
                    
            except TgtgAPIError as e:
                log.error(f"Login failed with API error: {e}")
                # TgtgAPIError has status_code and message attributes
                status = getattr(e, 'status_code', None)
                message = getattr(e, 'message', str(e))
                raise TgtgLoginError(status, message)
            except Exception as e:
                log.error(f"Login failed: {e}", exc_info=True)
                raise

    def start_polling(self, polling_id) -> None:
        """Authenticate using PIN code from email"""
        # If there's a configured callback (e.g., Telegram), use it
        if self.pin_callback:
            log.info("Requesting PIN via callback...")
            try:
                pin = self.pin_callback()
            except Exception as exc:
                log.error("PIN callback error: %s. Falling back to manual input.", exc)
                log.warning("Check your mailbox and insert the code to continue")
                pin = input("Code: ").strip()
        else:
            # Fallback: request from terminal
            log.warning("Check your mailbox and insert the code to continue")
            pin = input("Code: ").strip()
        
        if not pin:
            raise TgtgLoginError("PIN code cannot be empty")
        
        try:
            response = self._post(
                AUTH_BY_PIN_ENDPOINT,
                json={
                    "device_type": self.device_type,
                    "email": self.email,
                    "request_pin": pin,
                    "request_polling_id": polling_id,
                },
            )
            
            if response.status_code == HTTPStatus.OK:
                log.info("Successfully authenticated with PIN!")
                login_response = response.json()
                self.access_token = login_response.get("access_token")
                self.refresh_token = login_response.get("refresh_token")
                self.last_time_token_refreshed = datetime.now()
            else:
                raise TgtgLoginError(
                    response.status_code,
                    f"PIN authentication failed: {response.content}"
                )
                
        except TgtgLoginError:
            raise
        except Exception as e:
            raise TgtgLoginError(None, f"PIN authentication error: {e}")

    def get_items(
        self,
        *,
        latitude=0.0,
        longitude=0.0,
        radius=21,
        page_size=20,
        page=1,
        discover=False,
        favorites_only=True,
        item_categories=None,
        diet_categories=None,
        pickup_earliest=None,
        pickup_latest=None,
        search_phrase=None,
        with_stock_only=False,
        hidden_only=False,
        we_care_only=False,
    ) -> list[dict]:
        self.login()
        
        data = {
            "origin": {"latitude": latitude, "longitude": longitude},
            "radius": radius,
            "page_size": page_size,
            "page": page,
            "discover": discover,
            "favorites_only": favorites_only,
            "item_categories": item_categories if item_categories else [],
            "diet_categories": diet_categories if diet_categories else [],
            "pickup_earliest": pickup_earliest,
            "pickup_latest": pickup_latest,
            "search_phrase": search_phrase if search_phrase else None,
            "with_stock_only": with_stock_only,
            "hidden_only": hidden_only,
            "we_care_only": we_care_only,
        }
        response = self._post(API_ITEM_ENDPOINT, json=data)
        return response.json().get("items", [])

    def get_item(self, item_id: str) -> dict:
        self.login()
        response = self._post(
            f"{API_ITEM_ENDPOINT}/{item_id}",
            json={"origin": None},
        )
        return response.json()

    def get_favorites(self) -> list[dict]:
        """Returns favorites of current account"""
        items = []
        page = 1
        page_size = 100
        while True:
            new_items = self.get_items(favorites_only=True, page_size=page_size, page=page)
            items += new_items
            if len(new_items) < page_size:
                break
            page += 1
        return items

    def set_favorite(self, item_id: str, is_favorite: bool) -> None:
        self.login()
        self._post(
            FAVORITE_ITEM_ENDPOINT.format(item_id),
            json={"is_favorite": is_favorite},
        )

    def create_order(self, item_id: str, item_count: int) -> dict[str, str]:
        self.login()
        response = self._post(f"{CREATE_ORDER_ENDPOINT}/{item_id}", json={"item_count": item_count})
        if response.json().get("state") != "SUCCESS":
            raise TgtgAPIError(response.status_code, response.content)
        return response.json().get("order", {})

    def get_order_status(self, order_id: str) -> dict[str, str]:
        self.login()
        response = self._post(ORDER_STATUS_ENDPOINT.format(order_id))
        return response.json()

    def abort_order(self, order_id: str) -> None:
        """Abort unpaid order"""
        self.login()
        response = self._post(ABORT_ORDER_ENDPOINT.format(order_id), json={"cancel_reason_id": 1})
        if response.json().get("state") != "SUCCESS":
            raise TgtgAPIError(response.status_code, response.content)

    def get_manufactureritems(self) -> dict:
        self.login()
        response = self._post(
            MANUFACTURERITEM_ENDPOINT,
            json={
                "action_types_accepted": ["QUERY"],
                "display_types_accepted": ["LIST", "FILL"],
                "element_types_accepted": [
                    "ITEM",
                    "HIGHLIGHTED_ITEM",
                    "MANUFACTURER_STORY_CARD",
                    "DUO_ITEMS",
                    "DUO_ITEMS_V2",
                    "TEXT",
                    "PARCEL_TEXT",
                    "NPS",
                    "SMALL_CARDS_CAROUSEL",
                    "ITEM_CARDS_CAROUSEL",
                ],
            },
        )
        return response.json()
