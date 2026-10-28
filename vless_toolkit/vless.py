"""Parsing and validation for VLESS share links.

A VLESS link has the following shape::

    vless://<uuid>@<host>:<port>?<query>#<display-name>

The UUID is the user identity, while transport and TLS settings live in the
query string.  Query parameter names are case-sensitive and are kept as-is so
that callers can pass through settings this library does not interpret yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit
from uuid import UUID

from .errors import LinkParseError, LinkValidationError

DEFAULT_ENCRYPTION = "none"


def _validate_uuid(value: str) -> str:
    """Return the canonical lower-case form of ``value`` if it is a UUID."""
    try:
        return str(UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise LinkValidationError(f"VLESS user id must be a UUID, got {value!r}") from exc


def _validate_host(value: str) -> str:
    """Validate and return a hostname without IPv6 brackets."""
    if not isinstance(value, str):
        raise LinkValidationError("VLESS host must be a string")
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise LinkValidationError("VLESS host must not be empty")
    if any(char in host for char in "/?#@ \t\r\n"):
        raise LinkValidationError(f"invalid VLESS host: {value!r}")
    return host


def _validate_port(value: int) -> int:
    """Validate a TCP/UDP port number."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise LinkValidationError("VLESS port must be an integer")
    if not 1 <= value <= 65535:
        raise LinkValidationError(f"VLESS port must be between 1 and 65535, got {value}")
    return value


def _validate_params(params: dict[str, str]) -> dict[str, str]:
    """Copy and validate VLESS query parameters."""
    if not isinstance(params, dict):
        raise LinkValidationError("VLESS params must be a dictionary")
    cleaned: dict[str, str] = {}
    for key, value in params.items():
        if not isinstance(key, str) or not key:
            raise LinkValidationError("VLESS query parameter names must be non-empty strings")
        if not isinstance(value, str):
            raise LinkValidationError(f"VLESS query parameter {key!r} must be a string")
        cleaned[key] = value
    encryption = cleaned.get("encryption", DEFAULT_ENCRYPTION)
    if encryption != DEFAULT_ENCRYPTION:
        raise LinkValidationError(
            f"unsupported VLESS encryption {encryption!r}; only 'none' is valid"
        )
    return cleaned


@dataclass(frozen=True)
class VLESS:
    """A validated VLESS share link.

    Attributes:
        uuid: Canonical lower-case UUID identifying the user.
        host: Server hostname or IP address, without IPv6 brackets.
        port: Server port in the range 1-65535.
        params: Query parameters such as ``security``, ``sni`` or ``type``.
        name: Optional display name from the URL fragment.
    """

    uuid: str
    host: str
    port: int
    params: dict[str, str] = field(default_factory=dict)
    name: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "uuid", _validate_uuid(self.uuid))
        object.__setattr__(self, "host", _validate_host(self.host))
        object.__setattr__(self, "port", _validate_port(self.port))
        object.__setattr__(self, "params", _validate_params(self.params))
        if not isinstance(self.name, str):
            raise LinkValidationError("VLESS display name must be a string")

    @property
    def encryption(self) -> str:
        """The effective VLESS encryption method (always ``"none"``)."""
        return self.params.get("encryption", DEFAULT_ENCRYPTION)

    @property
    def security(self) -> str:
        """Transport security from the query, defaulting to ``"none"``."""
        return self.params.get("security", "none")


def _query_pairs(query: str) -> list[tuple[str, str]]:
    """Split a query string, rejecting duplicate names."""
    pairs = parse_qsl(query, keep_blank_values=True)
    seen = set()
    for key, _ in pairs:
        if not key:
            raise LinkParseError("VLESS query contains an empty parameter name")
        if key in seen:
            raise LinkParseError(f"VLESS query contains duplicate parameter {key!r}")
        seen.add(key)
    return pairs


def parse_vless(link: str) -> VLESS:
    """Parse a ``vless://`` share link into a :class:`VLESS` object.

    Args:
        link: The share link, optionally surrounded by whitespace.

    Returns:
        A validated, immutable VLESS record.

    Raises:
        LinkParseError: If the input is not a well-formed VLESS link.
        LinkValidationError: If parsed values fail field validation.
    """
    if not isinstance(link, str):
        raise LinkParseError("VLESS link must be a string")
    candidate = link.strip()
    if not candidate:
        raise LinkParseError("empty VLESS link")
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise LinkParseError(f"malformed VLESS link: {exc}") from exc

    if parsed.scheme.lower() != "vless":
        raise LinkParseError(f"expected a vless:// link, got {parsed.scheme or 'no scheme'!r}")
    if parsed.password is not None:
        raise LinkParseError("VLESS link must not contain a password")
    if parsed.username is None or not parsed.username:
        raise LinkParseError("VLESS link is missing the user UUID")
    if parsed.path not in ("", "/"):
        raise LinkParseError(f"unexpected path in VLESS link: {parsed.path!r}")
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise LinkParseError(f"invalid VLESS authority: {exc}") from exc
    if host is None:
        raise LinkParseError("VLESS link is missing a host")
    if port is None:
        raise LinkParseError("VLESS link is missing a port")

    params = dict(_query_pairs(parsed.query))
    try:
        return VLESS(
            uuid=unquote(parsed.username),
            host=host,
            port=port,
            params=params,
            name=unquote(parsed.fragment),
        )
    except LinkValidationError as exc:
        raise LinkParseError(str(exc)) from exc
