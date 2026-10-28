"""Parsing and building for VMess share links.

VMess links encode a JSON document in URL-safe base64::

    vmess://<base64-json>

The JSON carries both credentials and transport settings.  Common fields are
exposed as attributes; unknown fields are preserved in :attr:`VMess.extra` so
newer client extensions survive a parse/build round trip.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from .errors import LinkParseError, LinkValidationError

_KNOWN_KEYS = {
    "v",
    "ps",
    "add",
    "port",
    "id",
    "aid",
    "scy",
    "net",
    "type",
    "host",
    "path",
    "tls",
    "sni",
    "alpn",
    "fp",
}


def _as_text(mapping: dict[str, Any], key: str, default: str = "") -> str:
    """Read an optional string field."""
    value = mapping.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise LinkValidationError(f"VMess field {key!r} must be a string")
    return value


def _as_port(value: Any) -> int:
    """Parse a port supplied as a JSON integer or numeric string."""
    if isinstance(value, bool):
        raise LinkValidationError("VMess port must be an integer")
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        raise LinkValidationError(f"invalid VMess port: {value!r}")
    if not 1 <= port <= 65535:
        raise LinkValidationError(f"VMess port must be between 1 and 65535, got {port}")
    return port


def _as_alter_id(value: Any) -> int:
    """Parse the legacy alterId field, which clients encode as int or string."""
    if isinstance(value, bool):
        raise LinkValidationError("VMess alterId must be a non-negative integer")
    if isinstance(value, int):
        alter_id = value
    elif isinstance(value, str) and value.strip().isdigit():
        alter_id = int(value.strip())
    else:
        raise LinkValidationError(f"invalid VMess alterId: {value!r}")
    if alter_id < 0:
        raise LinkValidationError("VMess alterId must be non-negative")
    return alter_id


def _validate_host(value: str) -> str:
    """Validate a VMess server address."""
    if not isinstance(value, str):
        raise LinkValidationError("VMess host must be a string")
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise LinkValidationError("VMess host must not be empty")
    if any(char in host for char in "/?#@ \t\r\n"):
        raise LinkValidationError(f"invalid VMess host: {value!r}")
    return host


def _validate_uuid(value: str) -> str:
    """Validate and canonicalize a VMess user id."""
    try:
        return str(UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise LinkValidationError(f"VMess user id must be a UUID, got {value!r}") from exc


class _DuplicateKeyError(ValueError):
    """Internal signal for duplicate JSON keys."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


@dataclass(frozen=True)
class VMess:
    """A validated VMess configuration.

    Attributes:
        uuid: User UUID.
        host: Server hostname or IP address, without IPv6 brackets.
        port: Server port.
        name: Display name (the VMess ``ps`` field).
        alter_id: Legacy alterId value.
        security: Cipher name (``scy``), usually ``"auto"``.
        network: Transport network (``net``), usually ``"tcp"`` or ``"ws"``.
        header_type: Header obfuscation type, usually ``"none"``.
        tls: TLS mode, empty for plaintext.
        sni: TLS server name.
        host_header: HTTP host header.
        path: HTTP/WebSocket path.
        alpn: ALPN list as a comma-separated string.
        fingerprint: TLS fingerprint preset.
        version: VMess JSON schema version (always ``"2"``).
        extra: Unknown JSON fields preserved for round trips.
    """

    uuid: str
    host: str
    port: int
    name: str = ""
    alter_id: int = 0
    security: str = "auto"
    network: str = "tcp"
    header_type: str = "none"
    tls: str = ""
    sni: str = ""
    host_header: str = ""
    path: str = ""
    alpn: str = ""
    fingerprint: str = ""
    version: str = "2"
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "uuid", _validate_uuid(self.uuid))
        object.__setattr__(self, "host", _validate_host(self.host))
        object.__setattr__(self, "port", _as_port(self.port))
        object.__setattr__(self, "alter_id", _as_alter_id(self.alter_id))
        if self.version != "2":
            raise LinkValidationError(f"unsupported VMess version: {self.version!r}")
        for field_name in (
            "name",
            "security",
            "network",
            "header_type",
            "tls",
            "sni",
            "host_header",
            "path",
            "alpn",
            "fingerprint",
        ):
            if not isinstance(getattr(self, field_name), str):
                raise LinkValidationError(f"VMess field {field_name!r} must be a string")
        if not isinstance(self.extra, dict):
            raise LinkValidationError("VMess extra fields must be a dictionary")
        collisions = _KNOWN_KEYS.intersection(self.extra)
        if collisions:
            names = ", ".join(sorted(collisions))
            raise LinkValidationError(f"VMess extra fields shadow known keys: {names}")
        object.__setattr__(self, "extra", dict(self.extra))

    def to_dict(self) -> dict[str, Any]:
        """Return the VMess JSON representation as a mutable dictionary."""
        payload: dict[str, Any] = {
            "v": self.version,
            "ps": self.name,
            "add": self.host,
            "port": str(self.port),
            "id": self.uuid,
            "aid": str(self.alter_id),
            "scy": self.security,
            "net": self.network,
            "type": self.header_type,
            "host": self.host_header,
            "path": self.path,
            "tls": self.tls,
            "sni": self.sni,
            "alpn": self.alpn,
            "fp": self.fingerprint,
        }
        payload.update(self.extra)
        return payload

    def __str__(self) -> str:
        """Serialize this configuration back to a ``vmess://`` link."""
        return serialize_vmess(self)


def _decode_payload(link: str) -> dict[str, Any]:
    """Decode the base64 JSON payload of a VMess link."""
    payload = link.strip()[len("vmess://") :]
    if not payload:
        raise LinkParseError("VMess link is missing its base64 payload")
    padded = payload + "=" * (-len(payload) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LinkParseError(f"invalid base64 in VMess link: {exc}") from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise LinkParseError("VMess payload is not valid UTF-8") from exc
    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
    except _DuplicateKeyError as exc:
        raise LinkParseError(f"VMess JSON contains duplicate key {exc.args[0]!r}") from exc
    except json.JSONDecodeError as exc:
        raise LinkParseError(f"invalid JSON in VMess link: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise LinkParseError("VMess payload must be a JSON object")
    return data


def parse_vmess(link: str) -> VMess:
    """Parse a ``vmess://`` link into a :class:`VMess` record.

    Both standard and URL-safe base64 alphabets are accepted, with or without
    padding. Unknown JSON fields are retained.

    Raises:
        LinkParseError: If the link is not a valid VMess link.
    """
    if not isinstance(link, str):
        raise LinkParseError("VMess link must be a string")
    if link.strip()[:8].lower() != "vmess://":
        raise LinkParseError("expected a vmess:// link")
    data = _decode_payload(link)

    version = data.get("v", "2")
    if isinstance(version, int) and not isinstance(version, bool):
        version = str(version)
    if not isinstance(version, str) or version != "2":
        raise LinkParseError(f"unsupported VMess version: {version!r}")
    if "add" not in data:
        raise LinkParseError("VMess payload is missing the 'add' server address")
    if "port" not in data:
        raise LinkParseError("VMess payload is missing the 'port' field")
    if "id" not in data:
        raise LinkParseError("VMess payload is missing the 'id' user UUID")
    if not isinstance(data["add"], str):
        raise LinkParseError("VMess 'add' field must be a string")
    if not isinstance(data["id"], str):
        raise LinkParseError("VMess 'id' field must be a string")

    try:
        return VMess(
            uuid=data["id"],
            host=data["add"],
            port=_as_port(data["port"]),
            name=_as_text(data, "ps"),
            alter_id=_as_alter_id(data.get("aid", 0)),
            security=_as_text(data, "scy", "auto"),
            network=_as_text(data, "net", "tcp"),
            header_type=_as_text(data, "type", "none"),
            tls=_as_text(data, "tls"),
            sni=_as_text(data, "sni"),
            host_header=_as_text(data, "host"),
            path=_as_text(data, "path"),
            alpn=_as_text(data, "alpn"),
            fingerprint=_as_text(data, "fp"),
            version=version,
            extra={key: value for key, value in data.items() if key not in _KNOWN_KEYS},
        )
    except LinkValidationError as exc:
        raise LinkParseError(str(exc)) from exc


def serialize_vmess(link: VMess) -> str:
    """Serialize a :class:`VMess` record to a ``vmess://`` link.

    JSON is emitted compactly with UTF-8 text and URL-safe base64 without
    padding, matching common client output.

    Raises:
        LinkValidationError: If ``link`` is not a :class:`VMess` instance.
    """
    if not isinstance(link, VMess):
        raise LinkValidationError("serialize_vmess expects a VMess instance")
    try:
        text = json.dumps(link.to_dict(), ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise LinkValidationError(f"VMess extra fields must be JSON serializable: {exc}") from exc
    encoded = base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
    return f"vmess://{encoded}"
