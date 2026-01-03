"""
Datadome Cookie Manager for TGTG Scanner
Handles retrieval of Datadome cookies and APK version management
"""

import os
import re
import requests
import secrets
import configparser
from datetime import datetime
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)


class APKVersionManager:
    """Manages TGTG APK version retrieval and storage"""

    PLAY_STORE_URL = "https://play.google.com/store/apps/details?id=com.app.tgtg"

    def __init__(self, config_path: str = "config.ini"):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self.config.read(config_path)

    def get_version(self) -> str:
        """
        Get APK version from environment, config file, or Play Store (in that order)
        Updates config.ini if Play Store version differs from stored version

        Returns:
            str: APK version string (e.g., "25.12.0")
        """
        # 1. Check environment variable
        env_version = os.getenv("TGTG_APK_VERSION")
        if env_version:
            logger.info(f"Using APK version from environment: {env_version}")
            return env_version

        # 2. Check config.ini
        try:
            config_version = self.config.get("TGTG", "APKVersion")
            if config_version:
                logger.info(f"Using APK version from config: {config_version}")
                # Still check Play Store and update if needed
                self._check_and_update_version(config_version)
                return config_version
        except (configparser.NoSectionError, configparser.NoOptionError):
            logger.warning("APKVersion not found in config.ini")

        # 3. Fetch from Play Store
        logger.info("Fetching APK version from Play Store...")
        play_store_version = self._fetch_play_store_version()
        if play_store_version:
            self._save_version_to_config(play_store_version)
            return play_store_version

        # Fallback to a reasonable default
        logger.error("Could not determine APK version, using fallback")
        return "25.12.0"

    def _fetch_play_store_version(self) -> Optional[str]:
        """
        Fetch current APK version from Google Play Store

        Returns:
            Optional[str]: Version string if found, None otherwise
        """
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response = requests.get(self.PLAY_STORE_URL, headers=headers, timeout=10)
            response.raise_for_status()

            # Pattern to match version in Play Store HTML
            # Looking for patterns like [[["25.12.0"]]]
            pattern = r'\[\[\["(\d+\.\d+\.\d+)"\]\]\]'
            match = re.search(pattern, response.text)

            if match:
                version = match.group(1)
                logger.info(f"Found Play Store version: {version}")
                return version

            logger.warning("Could not parse version from Play Store HTML")
            return None

        except Exception as e:
            logger.error(f"Error fetching Play Store version: {e}")
            return None

    def _check_and_update_version(self, current_version: str) -> None:
        """
        Check Play Store for new version and update config if changed

        Args:
            current_version: Currently stored version
        """
        play_store_version = self._fetch_play_store_version()

        if play_store_version and play_store_version != current_version:
            logger.info(f"New version detected: {play_store_version} (was {current_version})")
            self._save_version_to_config(play_store_version)

    def _save_version_to_config(self, version: str) -> None:
        """
        Save version to config.ini with timestamp

        Args:
            version: Version string to save
        """
        try:
            if not self.config.has_section("TGTG"):
                self.config.add_section("TGTG")

            self.config.set("TGTG", "APKVersion", version)
            self.config.set("TGTG", "APKVersion_LastUpdated", 
                          datetime.utcnow().isoformat() + "Z")

            with open(self.config_path, "w") as f:
                self.config.write(f)

            logger.info(f"Saved APK version {version} to config.ini")

        except Exception as e:
            logger.error(f"Error saving version to config: {e}")


class DatadomeManager:
    """Manages Datadome cookie retrieval for TGTG API"""

    DATADOME_ENDPOINT = "https://api-sdk.datadome.co/sdk/"
    DATADOME_KEY = "1D42C2CA6131C526E09F294FE96F94"  # From TGTG Android app
    DATADOME_SDK_VERSION = "3.0.4"

    def __init__(self, apk_version: str):
        self.apk_version = apk_version
        self.cookie: Optional[str] = None

    def get_cookie(self, failed_request_url: str) -> Optional[str]:
        """
        Obtain Datadome cookie for TGTG API requests

        Args:
            failed_request_url: The TGTG API URL that returned 403

        Returns:
            Optional[str]: Datadome cookie string or None if failed
        """
        if self.cookie:
            return self.cookie

        try:
            payload = self._build_payload(failed_request_url)
            headers = {
                "User-Agent": f"TGTG/{self.apk_version} Dalvik/2.1.0 (Linux; U; Android 9; SM-G973F)",
                "Content-Type": "application/x-www-form-urlencoded"
            }

            response = requests.post(
                self.DATADOME_ENDPOINT,
                data=payload,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()

            result = response.json()

            if result.get("status") == 0 and "cookie" in result:
                self.cookie = result["cookie"]
                logger.info("Successfully obtained Datadome cookie")
                return self.cookie

            logger.error(f"Datadome API returned unexpected status: {result}")
            return None

        except Exception as e:
            logger.error(f"Error obtaining Datadome cookie: {e}")
            return None

    def _build_payload(self, request_url: str) -> Dict[str, str]:
        """
        Build Datadome SDK request payload with device fingerprinting

        Args:
            request_url: Original TGTG API URL

        Returns:
            Dict[str, str]: Payload dictionary
        """
        # Generate random identifiers
        cid = secrets.token_hex(32)  # 64 hex chars
        d_ifv = secrets.token_hex(16)  # 32 hex chars

        return {
            "cid": cid,
            "ddk": self.DATADOME_KEY,
            "Referer": request_url,
            "request": request_url,
            "responsePage": "origin",
            "ddv": self.DATADOME_SDK_VERSION,
            "ua": f"TGTG/{self.apk_version} Dalvik/2.1.0 (Linux; U; Android 9; SM-G973F)",
            "jsType": "android",
            "d_ifv": d_ifv,
            "ddvc": self.apk_version,
        }

    def clear_cookie(self) -> None:
        """Clear cached cookie to force refresh on next request"""
        self.cookie = None


class TGTGAPIClient:
    """Enhanced TGTG API client with Datadome protection handling"""

    def __init__(self, config_path: str = "config.ini"):
        self.version_manager = APKVersionManager(config_path)
        self.apk_version = self.version_manager.get_version()
        self.datadome_manager = DatadomeManager(self.apk_version)
        self.session = requests.Session()

    def make_request(self, url: str, method: str = "GET", **kwargs) -> requests.Response:
        """
        Make API request with automatic Datadome cookie handling

        Args:
            url: API endpoint URL
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional arguments for requests

        Returns:
            requests.Response: API response

        Raises:
            requests.HTTPError: If request fails after retry
        """
        # Add Datadome cookie if available
        headers = kwargs.get("headers", {})
        if self.datadome_manager.cookie:
            headers["Cookie"] = self.datadome_manager.cookie
        kwargs["headers"] = headers

        # Make initial request
        response = self.session.request(method, url, **kwargs)

        # Handle 403 by obtaining new Datadome cookie
        if response.status_code == 403:
            logger.warning("Received 403, attempting to obtain Datadome cookie...")

            cookie = self.datadome_manager.get_cookie(url)
            if cookie:
                headers["Cookie"] = cookie
                kwargs["headers"] = headers

                # Retry request with new cookie
                response = self.session.request(method, url, **kwargs)

                if response.status_code == 403:
                    logger.error("Still receiving 403 after Datadome cookie refresh")
            else:
                logger.error("Failed to obtain Datadome cookie")

        response.raise_for_status()
        return response


# Usage example
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Initialize client
    client = TGTGAPIClient()

    # The client will automatically:
    # 1. Get APK version from env -> config -> Play Store
    # 2. Handle 403 errors by obtaining Datadome cookies
    # 3. Update config.ini with new versions

    print(f"Using TGTG APK version: {client.apk_version}")
