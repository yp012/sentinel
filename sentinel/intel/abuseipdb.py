"""AbuseIPDB reputation lookups with a deterministic offline mock.

Live mode needs ``ABUSEIPDB_API_KEY``. Any live failure degrades to the mock so
enrichment never blocks the response chain. The API key is never logged.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import threading
import time
from dataclasses import asdict, dataclass, replace
from typing import Any, Callable, Literal, Optional

import requests

from sentinel import config
from sentinel.config import Settings
from sentinel.detection.window import LRUDict
from sentinel.net import is_private_or_special, parse_ip

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_MAX_ENTRIES = 10_000

# RFC 5737 documentation ranges the simulator uses as known-bad attackers.
KNOWN_BAD_NETWORKS = (
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
)
_MOCK_COUNTRIES = ("US", "DE", "NL", "CN", "RU", "BR", "IN", "FR", "GB", "SG")

IntelSource = Literal["live", "mock", "cache"]


@dataclass(frozen=True)
class IntelResult:
    ip: str
    score: int
    country: Optional[str]
    isp: Optional[str]
    reports: int
    source: IntelSource

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def mock_score(ip: str) -> IntelResult:
    """Deterministic offline reputation.

    Private/loopback -> 0. Documentation ranges 203.0.113.0/24 and 198.51.100.0/24
    -> 85-100. Any other address gets 0-60 from a hash of the IP, so only the
    designated known-bad ranges cross the default block score of 75.
    """
    addr = parse_ip(ip)
    digest = int.from_bytes(hashlib.sha256(str(addr).encode()).digest()[:8], "big")
    if is_private_or_special(addr):
        return IntelResult(str(addr), 0, None, "Private network", 0, "mock")
    if any(addr in net for net in KNOWN_BAD_NETWORKS if net.version == addr.version):
        score = 85 + digest % 16
    else:
        score = digest % 61
    country = _MOCK_COUNTRIES[(digest >> 8) % len(_MOCK_COUNTRIES)]
    return IntelResult(str(addr), score, country, "MockNet ISP", score // 4, "mock")


class AbuseIPDBClient:
    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        api_key: Optional[str] = None,
        session: Optional[requests.Session] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings or config.settings
        self._api_key = self.settings.abuseipdb_api_key if api_key is None else api_key
        self._session = session
        self._clock = clock
        self._cache: LRUDict = LRUDict(CACHE_MAX_ENTRIES)  # ip -> (expires_at, IntelResult)
        self._lock = threading.Lock()

    def __repr__(self) -> str:  # never expose the key
        return f"AbuseIPDBClient(mode={self.mode!r})"

    @property
    def mode(self) -> Literal["live", "mock"]:
        return "live" if self._api_key else "mock"

    def score(self, ip: str) -> IntelResult:
        """Reputation for ``ip``. Raises ValueError only if ``ip`` is not an IP address."""
        addr = str(parse_ip(ip))
        if self.mode == "mock":
            return mock_score(addr)

        now = self._clock()
        with self._lock:
            cached = self._cache.get(addr)
            if cached is not None and cached[0] > now:
                return replace(cached[1], source="cache")

        result = self._fetch(addr)
        if result is None:
            return mock_score(addr)
        with self._lock:
            self._cache[addr] = (now + self.settings.abuseipdb_cache_ttl_s, result)
        return result

    def _fetch(self, ip: str) -> Optional[IntelResult]:
        http: Any = self._session if self._session is not None else requests
        attempts = 1 + max(0, self.settings.abuseipdb_retries)
        for attempt in range(1, attempts + 1):
            try:
                resp = http.get(
                    API_URL,
                    headers={"Key": self._api_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": self.settings.abuseipdb_max_age_days},
                    timeout=self.settings.abuseipdb_timeout_s,
                )
                if resp.status_code != 200:
                    raise ValueError(f"HTTP {resp.status_code}")
                return self._parse(ip, resp.json())
            except Exception as exc:  # network, HTTP or schema error: all degrade
                # Only the exception type: messages from HTTP libraries can echo requests.
                logger.warning("AbuseIPDB lookup for %s failed (attempt %d/%d): %s",
                               ip, attempt, attempts, type(exc).__name__)
        return None

    @staticmethod
    def _parse(ip: str, body: Any) -> IntelResult:
        data = body["data"]
        score = max(0, min(100, int(data["abuseConfidenceScore"])))
        return IntelResult(
            ip=ip,
            score=score,
            country=data.get("countryCode"),
            isp=data.get("isp"),
            reports=int(data.get("totalReports") or 0),
            source="live",
        )
