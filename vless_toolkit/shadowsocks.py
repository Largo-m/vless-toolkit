"""Parsing and building for Shadowsocks SIP002 links.

Supported link forms::

    ss://base64url(method:password)@host:port/?plugin=... # name
    ss://method:password@host:port#name
    ss://base64(method:password@host:port)#name        (legacy)

New links are emitted in SIP002 form with URL-safe, unpadded base64 user-info.
Passwords are excluded from ``repr``.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from .errors import LinkParseError, LinkValidationError


def _validate_text(value: str, label: str) -> str:
    """Validate a non-empty string field."""
    if not isinstance(value, str):
        raise LinkValidationError(f"Shadowsocks {label} must be a string")
    if not value:
        raise LinkValidationError(f"Shadowsocks {label} must not be empty")
    return value


def _validate_host(value: str) -> str:
    """Validate and return a hostname without IPv6 brackets."""
    if not isinstance(value, str):
        raise LinkValidationError("Shadowsocks host must be a string")
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise LinkValidationError("Shadowsocks host must not be empty")
    if any(char in host for char in "/?#@ \t\r\n"):
        raise LinkValidationError(f"invalid Shadowsocks host: {value!r}")
    return host


def _validate_port(value: int) -> int:
    """Validate a port number."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise LinkValidationError("Shadowsocks port must be an integer")
    if not 1 <= value <= 65535:
        raise LinkValidationError(f"Shadowsocks port must be between 1 and 65535, got {value}")
    return value


def _validate_params(params: dict[str, str]) -> dict[str, str]:
    """Copy and validate Shadowsocks query parameters."""
    if not isinstance(params, dict):
        raise LinkValidationError("Shadowsocks params must be a dictionary")
    cleaned: dict[str, str] = {}
    for key, value in params.items():
        if not isinstance(key, str) or not key:
            raise LinkValidationError(
                "Shadowsocks query parameter names must be non-empty strings"
            )
        if not isinstance(value, str):
            raise LinkValidationError(f"Shadowsocks query parameter {key!r} must be a string")
        cleaned[key] = value
    return cleaned


def _decode_base64_text(token: str, label: str) -> str:
    """Decode standard or URL-safe base64 with optional padding."""
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LinkParseError(f"invalid base64 in Shadowsocks {label}: {exc}") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LinkParseError(f"Shadowsocks {label} is not valid UTF-8") from exc


def _split_credentials(value: str) -> tuple[str, str]:
    """Split a ``method:password`` string without truncating colons."""
    method, separator, password = value.partition(":")
    if not separator:
        raise LinkParseError("Shadowsocks credentials are missing the method separator")
    try:
        return _validate_text(method, "method"), _validate_text(password, "password")
    except LinkValidationError as exc:
        raise LinkParseError(str(exc)) from exc


def _credentials_from_userinfo(userinfo: str) -> tuple[str, str]:
    """Decode either base64 user-info or a plain ``method:password`` pair."""
    for candidate in dict.fromkeys((userinfo, unquote(userinfo))):
        if ":" in candidate:
            return _split_credentials(unquote(candidate))
    for candidate in dict.fromkeys((userinfo, unquote(userinfo))):
        try:
            decoded = _decode_base64_text(candidate, "user-info")
        except LinkParseError:
            continue
        if ":" in decoded:
            return _split_credentials(decoded)
    raise LinkParseError("Shadowsocks user-info is neither base64 nor method:password")


def _parse_host_port(text: str) -> tuple[str, int]:
    """Parse a ``host:port`` suffix, including bracketed IPv6."""
    try:
        parsed = urlsplit(f"//{text}")
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise LinkParseError(f"invalid Shadowsocks authority: {exc}") from exc
    if host is None:
        raise LinkParseError("Shadowsocks link is missing a host")
    if port is None:
        raise LinkParseError("Shadowsocks link is missing a port")
    try:
        return _validate_host(host), _validate_port(port)
    except LinkValidationError as exc:
        raise LinkParseError(str(exc)) from exc


def _query_pairs(query: str) -> list[tuple[str, str]]:
    """Split a query string, rejecting duplicate names."""
    pairs = parse_qsl(query, keep_blank_values=True)
    seen = set()
    for key, _ in pairs:
        if not key:
            raise LinkParseError("Shadowsocks query contains an empty parameter name")
        if key in seen:
            raise LinkParseError(f"Shadowsocks query contains duplicate parameter {key!r}")
        seen.add(key)
    return pairs


@dataclass(frozen=True)
class Shadowsocks:
    """A validated Shadowsocks configuration.

    Attributes:
        method: Cipher name, for example ``"aes-256-gcm"``.
        password: Cipher password.
        host: Server hostname or IP address, without IPv6 brackets.
        port: Server port in the range 1-65535.
        params: Query parameters, most notably ``plugin``.
        name: Optional display name from the URL fragment.
    """

    method: str
    password: str = field(repr=False)
    host: str = ""
    port: int = 8388
    params: dict[str, str] = field(default_factory=dict)
    name: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", _validate_text(self.method, "method"))
        object.__setattr__(self, "password", _validate_text(self.password, "password"))
        object.__setattr__(self, "host", _validate_host(self.host))
        object.__setattr__(self, "port", _validate_port(self.port))
        object.__setattr__(self, "params", _validate_params(self.params))
        if not isinstance(self.name, str):
            raise LinkValidationError("Shadowsocks display name must be a string")

    @property
    def plugin(self) -> str:
        """The configured SIP003 plugin, or an empty string."""
        return self.params.get("plugin", "")

    def __str__(self) -> str:
        """Serialize this record back to a SIP002 ``ss://`` link."""
        return serialize_shadowsocks(self)


def _parse_legacy(authority: str) -> tuple[str, str, str, int]:
    """Decode a legacy all-in-one base64 authority."""
    decoded = _decode_base64_text(authority, "legacy authority")
    if "@" not in decoded:
        raise LinkParseError("legacy Shadowsocks payload is missing '@'")
    credentials, host_port = decoded.rsplit("@", 1)
    method, password = _split_credentials(credentials)
    host, port = _parse_host_port(host_port)
    return method, password, host, port


def parse_shadowsocks(link: str) -> Shadowsocks:
    """Parse an ``ss://`` link into a :class:`Shadowsocks` record.

    Both SIP002 and legacy all-in-one base64 links are accepted, along with
    plain percent-encoded user-info used by some clients.

    Raises:
        LinkParseError: If the link is not a valid Shadowsocks link.
    """
    if not isinstance(link, str):
        raise LinkParseError("Shadowsocks link must be a string")
    candidate = link.strip()
    if not candidate:
        raise LinkParseError("empty Shadowsocks link")
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise LinkParseError(f"malformed Shadowsocks link: {exc}") from exc

    if parsed.scheme.lower() != "ss":
        raise LinkParseError(
            f"expected an ss:// link, got {parsed.scheme or 'no scheme'!r}"
        )
    if parsed.path not in ("", "/"):
        raise LinkParseError(f"unexpected path in Shadowsocks link: {parsed.path!r}")

    if "@" in parsed.netloc:
        userinfo, host_port = parsed.netloc.rsplit("@", 1)
        method, password = _credentials_from_userinfo(userinfo)
        host, port = _parse_host_port(host_port)
    else:
        method, password, host, port = _parse_legacy(parsed.netloc)

    params = dict(_query_pairs(parsed.query))
    try:
        return Shadowsocks(
            method=method,
            password=password,
            host=host,
            port=port,
            params=params,
            name=unquote(parsed.fragment),
        )
    except LinkValidationError as exc:
        raise LinkParseError(str(exc)) from exc


def serialize_shadowsocks(link: Shadowsocks) -> str:
    """Serialize a :class:`Shadowsocks` record to a SIP002 link.

    The ``method:password`` pair is encoded as unpadded URL-safe base64. IPv6
    hosts are bracketed and the display-name fragment is omitted when empty.

    Raises:
        LinkValidationError: If ``link`` is not a :class:`Shadowsocks` instance.
    """
    if not isinstance(link, Shadowsocks):
        raise LinkValidationError("serialize_shadowsocks expects a Shadowsocks instance")

    credentials = f"{link.method}:{link.password}".encode()
    userinfo = base64.urlsafe_b64encode(credentials).decode("ascii").rstrip("=")
    host = f"[{link.host}]" if ":" in link.host else link.host
    link_text = f"ss://{userinfo}@{host}:{link.port}"
    if link.params:
        query = urlencode(list(link.params.items()), quote_via=quote, safe="")
        link_text += f"?{query}"
    if link.name:
        link_text += f"#{quote(link.name, safe='')}"
    return link_text
