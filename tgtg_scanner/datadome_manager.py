"""
DataDome Cookie Manager for TGTG API
Based on Cereal-Automation's Kotlin implementation
SDK Version: 3.0.4 (Nov 2025)
"""

import requests
import json
import time
import uuid
import re
import configparser
from typing import Optional, Dict
from urllib.parse import urlencode
from pathlib import Path


class DataDomeCookieManager:
    """Manages DataDome cookie acquisition and refresh for TGTG API"""
    
    DATADOME_SDK_URL = "https://api-sdk.datadome.co/sdk/"
    DATADOME_SDK_VERSION = "3.0.4"
    TGTG_APP_VERSION_DEFAULT = "23.11.2"  # Fallback version
    TGTG_PACKAGE_NAME = "com.app.tgtg"
    VERSION_CHECK_INTERVAL_HOURS = 24  # Check for updates every 24 hours
    
    # DDK Key extracted from TGTG Android app
    DDK_KEY = "1D42C2CA6131C526E09F294FE96F94"
    
    def __init__(self, config_file: str = "config.ini"):
        self.cookie: Optional[str] = None
        self.cookie_expiry: Optional[float] = None
        self.session = requests.Session()
        self.config_file = config_file
        # Persistent client ID for device
        self.client_id = self._generate_client_id()
        # Load version check interval from config (default: 24 hours)
        self.version_check_interval = self._get_version_check_interval()
        # Get TGTG app version
        self.tgtg_app_version = self._get_tgtg_version()
        
    def _get_version_check_interval(self) -> int:
        """
        Reads version check interval from config.ini
        
        Returns:
            Hours between version checks (default: 24)
        """
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                config = configparser.ConfigParser()
                config.read(config_path)
                
                if config.has_section("DataDome") and config.has_option("DataDome", "version_check_interval"):
                    interval = config.getint("DataDome", "version_check_interval")
                    if interval >= 0:  # 0 means disabled
                        return interval
        except Exception as e:
            print(f"Error reading version check interval from config: {e}")
        
        return self.VERSION_CHECK_INTERVAL_HOURS
        
    def _generate_client_id(self) -> str:
        """Generates a unique Client ID for the device"""
        return str(uuid.uuid4()).replace("-", "") + str(uuid.uuid4()).replace("-", "")
    
    def _get_tgtg_version(self) -> str:
        """
        Gets TGTG app version from environment variable, config.ini, or Play Store
        
        Priority:
        1. Environment variable TGTG_APK_VERSION
        2. config.ini [TGTG] section, APKVersion key (with periodic update check)
        3. Play Store scraping
        4. Default fallback version
        
        Returns:
            TGTG app version string (e.g., "23.11.2")
        """
        # Priority 1: Environment variable (always takes precedence, no updates)
        env_version = os.getenv('TGTG_APK_VERSION')
        if env_version and self._validate_version(env_version):
            print(f"Using TGTG version from environment: {env_version}")
            return env_version
        
        # Priority 2: config.ini (with update check)
        config_version, last_update = self._read_version_from_config()
        if config_version:
            # Check if version needs updating
            if self._should_check_for_updates(last_update):
                print(f"Checking for TGTG version updates (last check: {last_update or 'never'})...")
                playstore_version = self._fetch_version_from_playstore()
                
                if playstore_version and playstore_version != config_version:
                    print(f"New TGTG version available: {config_version} -> {playstore_version}")
                    self._save_version_to_config(playstore_version)
                    return playstore_version
                elif playstore_version:
                    print(f"TGTG version is up to date: {config_version}")
                    # Update timestamp even if version unchanged
                    self._update_check_timestamp()
                else:
                    print(f"Could not check for updates, using current version: {config_version}")
            else:
                print(f"Using TGTG version from config.ini: {config_version}")
            
            return config_version
        
        # Priority 3: Play Store (first time setup)
        playstore_version = self._fetch_version_from_playstore()
        if playstore_version:
            print(f"Fetched TGTG version from Play Store: {playstore_version}")
            self._save_version_to_config(playstore_version)
            return playstore_version
        
        # Priority 4: Default fallback
        print(f"Using default TGTG version: {self.TGTG_APP_VERSION_DEFAULT}")
        return self.TGTG_APP_VERSION_DEFAULT
    
    def _read_version_from_config(self) -> tuple[Optional[str], Optional[str]]:
        """
        Reads TGTG app version and last update timestamp from config.ini
        
        Returns:
            Tuple of (version, last_update_timestamp)
        """
        try:
            config_path = Path(self.config_file)
            if not config_path.exists():
                return None, None
            
            config = configparser.ConfigParser()
            config.read(config_path)
            
            # Read APKVersion from TGTG section
            if config.has_section("TGTG") and config.has_option("TGTG", "APKVersion"):
                version = config.get("TGTG", "APKVersion").strip()
                last_update = None
                
                if config.has_option("TGTG", "APKVersion_Updated"):
                    last_update = config.get("TGTG", "APKVersion_Updated").strip()
                
                if version and self._validate_version(version):
                    return version, last_update
                    
        except Exception as e:
            print(f"Error reading config.ini: {e}")
        
        return None, None
    
    def _should_check_for_updates(self, last_update: Optional[str]) -> bool:
        """
        Checks if enough time has passed since last version check
        
        Args:
            last_update: Timestamp string from config (YYYY-MM-DD HH:MM:SS)
            
        Returns:
            True if should check for updates, False otherwise
        """
        # If interval is 0, automatic checks are disabled
        if self.version_check_interval == 0:
            return False
        
        if not last_update:
            return True  # Never checked before
        
        try:
            last_update_time = time.strptime(last_update, "%Y-%m-%d %H:%M:%S")
            last_update_timestamp = time.mktime(last_update_time)
            current_timestamp = time.time()
            
            hours_since_update = (current_timestamp - last_update_timestamp) / 3600
            
            return hours_since_update >= self.version_check_interval
            
        except Exception as e:
            print(f"Error parsing last update time: {e}")
            return True  # Check on error
    
    def _update_check_timestamp(self) -> None:
        """Updates only the timestamp in config without changing version"""
        try:
            config_path = Path(self.config_file)
            if not config_path.exists():
                return
            
            config = configparser.ConfigParser()
            config.read(config_path)
            
            if config.has_section("TGTG"):
                config.set("TGTG", "APKVersion_Updated", 
                          time.strftime("%Y-%m-%d %H:%M:%S"))
                
                with open(config_path, 'w') as f:
                    config.write(f)
                    
        except Exception as e:
            print(f"Error updating timestamp: {e}")
    
    def _save_version_to_config(self, version: str) -> None:
        """Saves TGTG app version to config.ini using APKVersion key"""
        try:
            config_path = Path(self.config_file)
            config = configparser.ConfigParser()
            
            # Read existing config
            if config_path.exists():
                config.read(config_path)
            
            # Add or update TGTG section
            if not config.has_section("TGTG"):
                config.add_section("TGTG")
            
            # Use APKVersion key (existing convention)
            config.set("TGTG", "APKVersion", version)
            config.set("TGTG", "APKVersion_Updated", 
                      time.strftime("%Y-%m-%d %H:%M:%S"))
            
            # Write back to file
            with open(config_path, 'w') as f:
                config.write(f)
            
            print(f"Saved TGTG version {version} to {self.config_file}")
        except Exception as e:
            print(f"Error saving to config.ini: {e}")
    
    def _fetch_version_from_playstore(self) -> Optional[str]:
        """
        Fetches current TGTG app version from Google Play Store
        
        Returns:
            Version string or None if failed
        """
        try:
            url = f"https://play.google.com/store/apps/details?id={self.TGTG_PACKAGE_NAME}&hl=en&gl=US"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                print(f"Play Store request failed: {response.status_code}")
                return None
            
            # Parse version from HTML
            # Play Store usually has version in format: "Version X.Y.Z"
            version_patterns = [
                r'Current Version[<>\w\s="]+>([0-9]+\.[0-9]+\.[0-9]+)',
                r'Version[<>\w\s="]+>([0-9]+\.[0-9]+\.[0-9]+)',
                r'"softwareVersion"[:\s]+"([0-9]+\.[0-9]+\.[0-9]+)"',
                r'versionName["\s:]+([0-9]+\.[0-9]+\.[0-9]+)'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    if self._validate_version(version):
                        return version
            
            print("Could not find version in Play Store HTML")
            return None
            
        except Exception as e:
            print(f"Error fetching from Play Store: {e}")
            return None
    
    def _validate_version(self, version: str) -> bool:
        """
        Validates version string format
        
        Args:
            version: Version string to validate
            
        Returns:
            True if valid (e.g., "23.11.2"), False otherwise
        """
        pattern = r'^[0-9]+\.[0-9]+\.[0-9]+
    
    def _get_device_fingerprint(self, target_url: str) -> Dict[str, str]:
        """
        Generates device fingerprint emulating a real Android device
        These parameters must match the TGTG Android app
        """
        timestamp = int(time.time() * 1000)
        
        return {
            "cid": self.client_id,
            "ddk": self.DDK_KEY,
            "request": target_url,
            "ua": f"TGTG/{self.tgtg_app_version} Dalvik/2.1.0 (Linux; U; Android 14; Pixel 7 Pro Build/UQ1A.240105.004)",
            "events": json.dumps([{
                "id": 1,
                "message": "response validation",
                "source": "sdk",
                "date": timestamp
            }]),
            "inte": "android-java-okhttp",
            "ddv": self.DATADOME_SDK_VERSION,
            "ddvc": self.tgtg_app_version,
            "os": "Android",
            "osr": "14",
            "osn": "UPSIDE_DOWN_CAKE",
            "osv": "34",
            "screen_x": "1440",
            "screen_y": "3120",
            "screen_d": "3.5",
            "camera": json.dumps({
                "auth": "true",
                "info": json.dumps({
                    "front": "2000x1500",
                    "back": "4032x3024"
                })
            }),
            "manufacturer": "Google",
            "model": "Pixel 7 Pro",
            "brand": "google",
            "device": "cheetah",
            "product": "cheetah",
            "hardware": "cheetah",
            "display": "UQ1A.240105.004",
            "fingerprint": "google/cheetah/cheetah:14/UQ1A.240105.004/11206848:user/release-keys",
            "abi": "arm64-v8a",
            "locale": "en_US",
            "timezone": "UTC",
            "network_type": "WIFI",
            "battery_level": "85",
            "battery_charging": "false",
        }
    
    def fetch_cookie(self, target_url: str) -> Optional[str]:
        """
        Requests a new DataDome cookie from the SDK endpoint
        
        Args:
            target_url: URL of the TGTG request that generated 403
            
        Returns:
            DataDome cookie or None if failed
        """
        try:
            fingerprint = self._get_device_fingerprint(target_url)
            
            headers = {
                "User-Agent": "okhttp/5.1.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
            }
            
            response = self.session.post(
                self.DATADOME_SDK_URL,
                data=fingerprint,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                # Extract cookie from response
                cookies = response.cookies.get_dict()
                if "datadome" in cookies:
                    self.cookie = cookies["datadome"]
                    # DataDome cookies typically last 30 minutes
                    self.cookie_expiry = time.time() + 1800
                    return self.cookie
            
            print(f"DataDome SDK error: {response.status_code}")
            return None
            
        except Exception as e:
            print(f"Failed to fetch DataDome cookie: {e}")
            return None
    
    def get_cookie(self, target_url: str) -> Optional[str]:
        """
        Gets a valid cookie, requesting a new one if necessary
        
        Args:
            target_url: Target URL for the request
            
        Returns:
            Valid DataDome cookie
        """
        # Check if cookie is still valid
        if self.cookie and self.cookie_expiry and time.time() < self.cookie_expiry:
            return self.cookie
        
        # Request a new cookie
        return self.fetch_cookie(target_url)
    
    def is_valid(self) -> bool:
        """Checks if current cookie is still valid"""
        return (
            self.cookie is not None 
            and self.cookie_expiry is not None 
            and time.time() < self.cookie_expiry
        )


class TGTGApiClient:
    """TGTG client with automatic DataDome handling"""
    
    TGTG_API_BASE = "https://api.toogoodtogo.com"
    
    def __init__(self):
        self.session = requests.Session()
        self.datadome_manager = DataDomeCookieManager()
        
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """
        Makes a request with automatic 403 handling
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: Relative API endpoint
            **kwargs: Additional parameters for requests
            
        Returns:
            Response object
        """
        url = f"{self.TGTG_API_BASE}{endpoint}"
        headers = kwargs.get("headers", {})
        
        # Add DataDome cookie if available
        cookie = self.datadome_manager.get_cookie(url)
        if cookie:
            headers["Cookie"] = f"datadome={cookie}"
        
        kwargs["headers"] = headers
        
        # First request
        response = self.session.request(method, url, **kwargs)
        
        # If 403, get new cookie and retry
        if response.status_code == 403:
            print("Got 403, fetching new DataDome cookie...")
            cookie = self.datadome_manager.fetch_cookie(url)
            
            if cookie:
                headers["Cookie"] = f"datadome={cookie}"
                kwargs["headers"] = headers
                response = self.session.request(method, url, **kwargs)
            else:
                print("Failed to get DataDome cookie!")
        
        return response
    
    def auth_by_email(self, email: str) -> Dict:
        """
        Example: TGTG authentication request
        
        Args:
            email: TGTG account email
            
        Returns:
            Response JSON
        """
        endpoint = "/api/auth/v5/authByEmail"
        payload = {
            "device_type": "ANDROID",
            "email": email
        }
        
        response = self._make_request(
            "POST",
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        return response.json() if response.status_code == 200 else {}


# Usage example
if __name__ == "__main__":
    # Initialize client
    client = TGTGApiClient()
    
    # Test authentication
    result = client.auth_by_email("[email protected]")
    print(f"Auth result: {result}")
    
    # DataDome cookie is handled automatically:
    # 1. First request without cookie -> 403
    # 2. Automatic DataDome cookie fetch
    # 3. Request retry with valid cookie
    # 4. Cookie is reused for subsequent requests

        return bool(re.match(pattern, version))
    
    def _get_device_fingerprint(self, target_url: str) -> Dict[str, str]:
        """
        Generates device fingerprint emulating a real Android device
        These parameters must match the TGTG Android app
        """
        timestamp = int(time.time() * 1000)
        
        return {
            "cid": self.client_id,
            "ddk": self.DDK_KEY,
            "request": target_url,
            "ua": f"TGTG/{self.TGTG_APP_VERSION} Dalvik/2.1.0 (Linux; U; Android 14; Pixel 7 Pro Build/UQ1A.240105.004)",
            "events": json.dumps([{
                "id": 1,
                "message": "response validation",
                "source": "sdk",
                "date": timestamp
            }]),
            "inte": "android-java-okhttp",
            "ddv": self.DATADOME_SDK_VERSION,
            "ddvc": self.TGTG_APP_VERSION,
            "os": "Android",
            "osr": "14",
            "osn": "UPSIDE_DOWN_CAKE",
            "osv": "34",
            "screen_x": "1440",
            "screen_y": "3120",
            "screen_d": "3.5",
            "camera": json.dumps({
                "auth": "true",
                "info": json.dumps({
                    "front": "2000x1500",
                    "back": "4032x3024"
                })
            }),
            "manufacturer": "Google",
            "model": "Pixel 7 Pro",
            "brand": "google",
            "device": "cheetah",
            "product": "cheetah",
            "hardware": "cheetah",
            "display": "UQ1A.240105.004",
            "fingerprint": "google/cheetah/cheetah:14/UQ1A.240105.004/11206848:user/release-keys",
            "abi": "arm64-v8a",
            "locale": "en_US",
            "timezone": "UTC",
            "network_type": "WIFI",
            "battery_level": "85",
            "battery_charging": "false",
        }
    
    def fetch_cookie(self, target_url: str) -> Optional[str]:
        """
        Requests a new DataDome cookie from the SDK endpoint
        
        Args:
            target_url: URL of the TGTG request that generated 403
            
        Returns:
            DataDome cookie or None if failed
        """
        try:
            fingerprint = self._get_device_fingerprint(target_url)
            
            headers = {
                "User-Agent": "okhttp/5.1.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
            }
            
            response = self.session.post(
                self.DATADOME_SDK_URL,
                data=fingerprint,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                # Extract cookie from response
                cookies = response.cookies.get_dict()
                if "datadome" in cookies:
                    self.cookie = cookies["datadome"]
                    # DataDome cookies typically last 30 minutes
                    self.cookie_expiry = time.time() + 1800
                    return self.cookie
            
            print(f"DataDome SDK error: {response.status_code}")
            return None
            
        except Exception as e:
            print(f"Failed to fetch DataDome cookie: {e}")
            return None
    
    def get_cookie(self, target_url: str) -> Optional[str]:
        """
        Gets a valid cookie, requesting a new one if necessary
        
        Args:
            target_url: Target URL for the request
            
        Returns:
            Valid DataDome cookie
        """
        # Check if cookie is still valid
        if self.cookie and self.cookie_expiry and time.time() < self.cookie_expiry:
            return self.cookie
        
        # Request a new cookie
        return self.fetch_cookie(target_url)
    
    def is_valid(self) -> bool:
        """Checks if current cookie is still valid"""
        return (
            self.cookie is not None 
            and self.cookie_expiry is not None 
            and time.time() < self.cookie_expiry
        )


class TGTGApiClient:
    """TGTG client with automatic DataDome handling"""
    
    TGTG_API_BASE = "https://api.toogoodtogo.com"
    
    def __init__(self):
        self.session = requests.Session()
        self.datadome_manager = DataDomeCookieManager()
        
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """
        Makes a request with automatic 403 handling
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: Relative API endpoint
            **kwargs: Additional parameters for requests
            
        Returns:
            Response object
        """
        url = f"{self.TGTG_API_BASE}{endpoint}"
        headers = kwargs.get("headers", {})
        
        # Add DataDome cookie if available
        cookie = self.datadome_manager.get_cookie(url)
        if cookie:
            headers["Cookie"] = f"datadome={cookie}"
        
        kwargs["headers"] = headers
        
        # First request
        response = self.session.request(method, url, **kwargs)
        
        # If 403, get new cookie and retry
        if response.status_code == 403:
            print("Got 403, fetching new DataDome cookie...")
            cookie = self.datadome_manager.fetch_cookie(url)
            
            if cookie:
                headers["Cookie"] = f"datadome={cookie}"
                kwargs["headers"] = headers
                response = self.session.request(method, url, **kwargs)
            else:
                print("Failed to get DataDome cookie!")
        
        return response
    
    def auth_by_email(self, email: str) -> Dict:
        """
        Example: TGTG authentication request
        
        Args:
            email: TGTG account email
            
        Returns:
            Response JSON
        """
        endpoint = "/api/auth/v5/authByEmail"
        payload = {
            "device_type": "ANDROID",
            "email": email
        }
        
        response = self._make_request(
            "POST",
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        return response.json() if response.status_code == 200 else {}


# Usage example
if __name__ == "__main__":
    # Initialize client
    client = TGTGApiClient()
    
    # Test authentication
    result = client.auth_by_email("[email protected]")
    print(f"Auth result: {result}")
    
    # DataDome cookie is handled automatically:
    # 1. First request without cookie -> 403
    # 2. Automatic DataDome cookie fetch
    # 3. Request retry with valid cookie
    # 4. Cookie is reused for subsequent requests
