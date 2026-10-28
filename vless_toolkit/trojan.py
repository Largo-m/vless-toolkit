"""Parsing and building for Trojan share links.

Trojan links use the password as the URL user-info component::

    trojan://<password>@<host>:<port>?<query>#<display-name>

Transport parameters are kept as a case-sensitive query dictionary. Passwords
are excluded from ``repr`` to reduce accidental credential exposure in logs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from .errors import LinkParseError, LinkValidationError


def _validate_host(value: str) -> str:
    """Validate and return a hostname without IPv6 brackets."""
    if not isinstance(value, str):
        raise LinkValidationError("Trojan host must be a string")
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise LinkValidationError("Trojan host must not be empty")
    if any(char in host for char in "/?#@ \t\r\n"):
        raise LinkValidationError(f"invalid Trojan host: {value!r}")
    return host


def _validate_port(value: int) -> int:
    """Validate a port number."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise LinkValidationError("Trojan port must be an integer")
    if not 1 <= value <= 65535:
        raise LinkValidationError(f"Trojan port must be between 1 and 65535, got {value}")
    return value


def _validate_password(value: str) -> str:
    """Validate a Trojan password without altering its contents."""
    if not isinstance(value, str):
        raise LinkValidationError("Trojan password must be a string")
    if not value:
        raise LinkValidationError("Trojan password must not be empty")
    if any(char in value for char in "\r\n\x00"):
        raise LinkValidationError("Trojan password contains a control character")
    return value


def _validate_params(params: dict[str, str]) -> dict[str, str]:
    """Copy and validate Trojan query parameters."""
    if not isinstance(params, dict):
        raise LinkValidationError("Trojan params must be a dictionary")
    cleaned: dict[str, str] = {}
    for key, value in params.items():
        if not isinstance(key, str) or not key:
            raise LinkValidationError("Trojan query parameter names must be non-empty strings")
        if not isinstance(value, str):
            raise LinkValidationError(f"Trojan query parameter {key!r} must be a string")
        cleaned[key] = value
    return cleaned


@dataclass(frozen=True)
class Trojan:
    """A validated Trojan share link.

    Attributes:
        password: Authentication password.
        host: Server hostname or IP address, without IPv6 brackets.
        port: Server port in the range 1-65535.
        params: Query parameters such as ``security``, ``sni`` or ``type``.
        name: Optional display name from the URL fragment.
    """

    password: str = field(repr=False)
    host: str
    port: int = 443
    params: dict[str, str] = field(default_factory=dict)
    name: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "password", _validate_password(self.password))
        object.__setattr__(self, "host", _validate_host(self.host))
        object.__setattr__(self, "port", _validate_port(self.port))
        object.__setattr__(self, "params", _validate_params(self.params))
        if not isinstance(self.name, str):
            raise LinkValidationError("Trojan display name must be a string")

    @property
    def security(self) -> str:
        """Transport security from the query, defaulting to ``"tls"``."""
        return self.params.get("security", "tls")

    def __str__(self) -> str:
        """Serialize this record back to a ``trojan://`` share link."""
        return serialize_trojan(self)


def _query_pairs(query: str) -> list[tuple[str, str]]:
    """Split a query string, rejecting duplicate names."""
    pairs = parse_qsl(query, keep_blank_values=True)
    seen = set()
    for key, _ in pairs:
        if not key:
            raise LinkParseError("Trojan query contains an empty parameter name")
        if key in seen:
            raise LinkParseError(f"Trojan query contains duplicate parameter {key!r}")
        seen.add(key)
    return pairs


def parse_trojan(link: str) -> Trojan:
    """Parse a ``trojan://`` share link into a :class:`Trojan` record.

    Raw colons in the user-info are accepted and treated as part of the
    password. Percent-encoded credentials are decoded exactly once.

    Raises:
        LinkParseError: If the link is not a valid Trojan link.
    """
    if not isinstance(link, str):
        raise LinkParseError("Trojan link must be a string")
    candidate = link.strip()
    if not candidate:
        raise LinkParseError("empty Trojan link")
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise LinkParseError(f"malformed Trojan link: {exc}") from exc

    if parsed.scheme.lower() != "trojan":
        raise LinkParseError(f"expected a trojan:// link, got {parsed.scheme or 'no scheme'!r}")
    if parsed.username is None or not parsed.username:
        raise LinkParseError("Trojan link is missing the password")
    if parsed.path not in ("", "/"):
        raise LinkParseError(f"unexpected path in Trojan link: {parsed.path!r}")
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise LinkParseError(f"invalid Trojan authority: {exc}") from exc
    if host is None:
        raise LinkParseError("Trojan link is missing a host")
    if port is None:
        raise LinkParseError("Trojan link is missing a port")

    password = unquote(parsed.username)
    if parsed.password is not None:
        password = f"{password}:{unquote(parsed.password)}"
    params = dict(_query_pairs(parsed.query))
    try:
        return Trojan(
            password=password,
            host=host,
            port=port,
            params=params,
            name=unquote(parsed.fragment),
        )
    except LinkValidationError as exc:
        raise LinkParseError(str(exc)) from exc


def serialize_trojan(link: Trojan) -> str:
    """Serialize a :class:`Trojan` record to a share link.

    The password is fully percent-encoded, IPv6 hosts are bracketed, and the
    display-name fragment is omitted when empty.

    Raises:
        LinkValidationError: If ``link`` is not a :class:`Trojan` instance.
    """
    if not isinstance(link, Trojan):
        raise LinkValidationError("serialize_trojan expects a Trojan instance")

    host = f"[{link.host}]" if ":" in link.host else link.host
    password = quote(link.password, safe="")
    link_text = f"trojan://{password}@{host}:{link.port}"
    if link.params:
        query = urlencode(list(link.params.items()), quote_via=quote, safe="")
        link_text += f"?{query}"
    if link.name:
        link_text += f"#{quote(link.name, safe='')}"
    return link_text
