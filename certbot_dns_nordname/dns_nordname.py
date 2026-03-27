"""DNS Authenticator for Nordname."""

from dataclasses import dataclass
import logging
from typing import Any
from typing import Callable
from typing import Optional

import requests

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "https://api.nordname.fi/api/v3"


@dataclass(frozen=True, slots=True)
class _DnsRecord:
    """Typed view of a DNS record returned by the Nordname API."""

    record_id: Optional[str]
    record_type: str
    name: str
    content: str

    @classmethod
    def from_api(cls, payload: Any) -> Optional["_DnsRecord"]:
        """Create a _DnsRecord from a Nordname API response item."""
        if not isinstance(payload, dict):
            return None

        raw_id = payload.get("id")
        return cls(
            record_id=None if raw_id is None else str(raw_id),
            record_type=str(payload.get("type", "")).upper(),
            name=str(payload.get("name", "")),
            # Nordname stores TXT content with surrounding double-quotes.
            content=str(payload.get("content", "")).strip('"'),
        )


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Nordname.

    This Authenticator uses the Nordname API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record for Nordname DNS."
    ttl = 3600 # required minimum TTL for Nordname API

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None
        self._client: Optional[_NordnameClient] = None

    @classmethod
    def add_parser_arguments(
        cls,
        add: Callable[..., None],
        default_propagation_seconds: int = 30,
    ) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="Nordname credentials INI file.")
        add(
            "endpoint",
            default=DEFAULT_ENDPOINT,
            help="Nordname API base URL.",
        )

    def more_info(self) -> str:
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge "
            "using the Nordname API."
        )

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "Nordname credentials INI file",
            {"api-token": "API token for Nordname account"},
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_client().del_txt_record(domain, validation_name, validation)

    def _get_client(self) -> "_NordnameClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")

        if self._client is None:
            token = self.credentials.conf("api-token")
            endpoint = self.conf("endpoint")
            self._client = _NordnameClient(token=token, endpoint=endpoint)

        return self._client


class _NordnameClient:
    """Encapsulates communication with the Nordname API."""

    def __init__(self, token: Optional[str], endpoint: str, timeout: int = 30) -> None:
        if not token:
            raise errors.PluginError("Missing Nordname API token in credentials file.")
        self._token = token
        self._endpoint = endpoint.rstrip("/")
        self._timeout = timeout
        self._zone_cache: dict[str, str] = {}

    def _relative_record_name(self, record_name: str, zone: str) -> str:
        """Return the record name relative to the zone (strip zone suffix)."""
        suffix = "." + zone
        if record_name.endswith(suffix):
            return record_name[: -len(suffix)]
        return record_name

    def add_txt_record(self, domain: str, record_name: str, record_content: str, ttl: int) -> None:
        """Add a TXT record to Nordname."""
        zone = self._find_zone(domain)
        relative_name = self._relative_record_name(record_name, zone)
        self._request(
            "POST",
            f"/domain/{zone}/add_dns_record",
            params={
                "type": "TXT",
                "name": relative_name,
                "content": record_content,
                "ttl": ttl,
            },
        )

    def del_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """Delete the specified TXT record."""
        zone = self._find_zone(domain)
        relative_name = self._relative_record_name(record_name, zone)
        record_id = self._find_txt_record_id(zone, relative_name, record_content)

        if not record_id:
            logger.warning("TXT record not found for cleanup: %s %s", record_name, record_content)
            return

        self._request(
            "DELETE",
            f"/domain/{zone}/delete_dns_record",
            params={"id": record_id},
        )

    def _find_zone(self, domain: str) -> str:
        """Discover the zone name for a given domain.
        
        Tries progressively shorter domain names until one resolves successfully.
        Caches results to avoid repeated API calls.
        """
        if domain in self._zone_cache:
            return self._zone_cache[domain]

        for candidate in dns_common.base_domain_name_guesses(domain):
            try:
                self._request("GET", f"/domain/{candidate}/get_dns_zone")
                logger.debug("Found zone for %s: %s", domain, candidate)
                self._zone_cache[domain] = candidate
                return candidate
            except errors.PluginError as e:
                if "404" not in str(e) and "Zone not found" not in str(e):
                    raise
                logger.debug("Zone %s not found, trying next candidate", candidate)
                continue

        raise errors.PluginError(
            f"Could not find a DNS zone for domain {domain} in your Nordname account. "
        )

    def _find_txt_record_id(
        self,
        zone: str,
        record_name: str,
        record_content: str,
    ) -> Optional[str]:
        try:
            payload = self._request("GET", f"/domain/{zone}/get_dns_zone")
            for record in self._extract_records(payload):
                if self._record_matches(record, record_name, record_content):
                    if record.record_id is not None:
                        return record.record_id
        except errors.PluginError as e:
            if "404" in str(e) or "Zone not found" in str(e):
                logger.debug("Zone not found for %s during cleanup", zone)
                return None
            raise

        return None

    def _record_matches(self, record: _DnsRecord, name: str, content: str) -> bool:
        return record.record_type == "TXT" and record.name == name and record.content == content

    def _extract_records(self, payload: Any) -> list[_DnsRecord]:
        if not isinstance(payload, list):
            return []

        records: list[_DnsRecord] = []
        for item in payload:
            record = _DnsRecord.from_api(item)
            if record is not None:
                records.append(record)
        return records

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
    ) -> Any:
        url = f"{self._endpoint}{path}"
        headers = {
            "Authorization": f"token {self._token}",
            "Accept": "application/json",
        }
        if json is not None:
            headers["Content-Type"] = "application/json"

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json,
                params=params,
                timeout=self._timeout,
            )
        except requests.RequestException as err:
            raise errors.PluginError(f"Error communicating with Nordname API: {err}") from err

        if response.status_code >= 400:
            body = response.text.strip()
            raise errors.PluginError(
                f"Nordname API request failed ({response.status_code}) for {method} {path}: {body}"
            )

        if not response.text:
            return {}

        try:
            return response.json()
        except ValueError:
            return {}
