"""DNS Authenticator for DNScale."""

import logging
from typing import Optional

import requests

from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "https://api.dnscale.eu"


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DNScale.

    This Authenticator uses the DNScale API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using DNScale for DNS)."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._client = None

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=60):
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="DNScale credentials INI file.")

    def more_info(self):
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using the DNScale API."

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "DNScale credentials INI file",
            required_variables={
                "api_token": "API token for DNScale (create at dnscale.eu with records:read and records:write scopes)",
            },
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_client().add_txt_record(validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_client().del_txt_record(validation_name, validation)

    def _get_client(self) -> "_DNScaleClient":
        if self._client is None:
            self._client = _DNScaleClient(
                api_token=self.credentials.conf("api_token"),
                api_url=self.credentials.conf("api_url") or DEFAULT_API_URL,
            )
        return self._client


class _DNScaleClient:
    """Wrapper around the DNScale API for DNS-01 challenge operations."""

    def __init__(self, api_token: str, api_url: str = DEFAULT_API_URL):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def add_txt_record(self, record_name: str, record_content: str) -> None:
        """Create a TXT record for the dns-01 challenge."""
        zone_id, zone_name = self._find_zone(record_name)

        logger.debug("Creating TXT record for %s in zone %s", record_name, zone_name)

        data = {
            "name": record_name,
            "type": "TXT",
            "content": record_content,
            "ttl": 120,
        }

        resp = self.session.post(f"{self.api_url}/v1/zones/{zone_id}/records", json=data)

        if resp.status_code not in (200, 201):
            raise errors.PluginError(
                f"Failed to create TXT record: {resp.status_code} {resp.text}"
            )

        logger.debug("Successfully created TXT record for %s", record_name)

    def del_txt_record(self, record_name: str, record_content: str) -> None:
        """Delete a TXT record after dns-01 challenge validation."""
        try:
            zone_id, zone_name = self._find_zone(record_name)
        except errors.PluginError:
            logger.warning("Could not find zone for %s during cleanup, skipping", record_name)
            return

        logger.debug("Deleting TXT record for %s in zone %s", record_name, zone_name)

        resp = self.session.delete(
            f"{self.api_url}/v1/zones/{zone_id}/records/by-name/{record_name}/TXT",
            params={"content": record_content},
        )

        if resp.status_code not in (200, 204):
            logger.warning("Failed to delete TXT record: %s %s", resp.status_code, resp.text)
            return

        logger.debug("Successfully deleted TXT record for %s", record_name)

    def _find_zone(self, record_name: str) -> tuple:
        """Find the zone managing the given record name.

        Returns a tuple of (zone_id, zone_name).
        """
        zones = self._list_zones()

        # Strip trailing dot if present.
        name = record_name.rstrip(".")

        # Walk up the domain labels to find the zone.
        while name:
            for zone in zones:
                zone_name = zone["name"].rstrip(".")
                if name.lower() == zone_name.lower():
                    return zone["id"], zone["name"]

            # Remove the leftmost label.
            dot = name.find(".")
            if dot < 0:
                break
            name = name[dot + 1 :]

        raise errors.PluginError(f"Could not find a DNScale zone for {record_name}")

    def _list_zones(self) -> list:
        """Fetch all zones from the DNScale API."""
        all_zones = []
        offset = 0
        limit = 100

        while True:
            resp = self.session.get(
                f"{self.api_url}/v1/zones",
                params={"offset": offset, "limit": limit},
            )

            if resp.status_code != 200:
                raise errors.PluginError(
                    f"Failed to list zones: {resp.status_code} {resp.text}"
                )

            data = resp.json()
            zones = data.get("zones", [])
            all_zones.extend(zones)

            if len(zones) < limit:
                break
            offset += limit

        return all_zones
