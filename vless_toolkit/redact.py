"""Helpers for safely displaying or logging credential-bearing links.

Redaction replaces all authentication material with fixed placeholders and can
optionally hide server addresses. Redacted links remain syntactically valid so
they can still be passed through parsers during diagnostics.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from .errors import LinkError, LinkValidationError
from .parser import Link, parse_link, serialize_link
from .shadowsocks import Shadowsocks
from .trojan import Trojan
from .vless import VLESS
from .vmess import VMess

REDACTED = "[REDACTED]"
REDACTED_UUID = "00000000-0000-0000-0000-000000000000"
REDACTED_HOST = "redacted.invalid"

_SENSITIVE_KEYS = {
    "apikey",
    "api_key",
    "auth",
    "key",
    "passwd",
    "password",
    "secret",
    "token",
}
_LINK_PATTERN = re.compile(r"(?i)\b(?:vless|vmess|trojan|ss)://[^\s<>'\"]+")


def redact_secret(value: str, *, show_last: int = 0) -> str:
    """Redact a secret, optionally revealing a short suffix for correlation.

    Args:
        value: Secret text.
        show_last: Number of trailing characters to reveal. Zero redacts all.

    Raises:
        LinkValidationError: If the value or suffix length is invalid.
    """
    if not isinstance(value, str):
        raise LinkValidationError("secret must be a string")
    if isinstance(show_last, bool) or not isinstance(show_last, int) or show_last < 0:
        raise LinkValidationError("show_last must be a non-negative integer")
    if not value:
        return ""
    if show_last == 0 or show_last >= len(value):
        return REDACTED
    return "*" * (len(value) - show_last) + value[-show_last:]


def _redact_params(params: dict[str, str]) -> dict[str, str]:
    """Mask values of query parameters whose names imply a secret."""
    return {
        key: REDACTED if key.lower() in _SENSITIVE_KEYS else value
        for key, value in params.items()
    }


def _redact_extra(value: Any) -> Any:
    """Recursively mask sensitive keys in VMess extension dictionaries."""
    if isinstance(value, dict):
        return {
            key: REDACTED
            if isinstance(key, str) and key.lower() in _SENSITIVE_KEYS
            else _redact_extra(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redact_extra(child) for child in value]
    return value


def redact_record(record: Link, *, keep_host: bool = True) -> Link:
    """Return a copy of a record with credentials replaced by placeholders.

    Args:
        record: Parsed protocol record.
        keep_host: Keep the server hostname. Set false to replace it with
            ``redacted.invalid`` as well.

    Raises:
        LinkValidationError: If ``record`` is not a supported record type.
    """
    if not isinstance(record, (VLESS, VMess, Trojan, Shadowsocks)):
        raise LinkValidationError(f"cannot redact record type: {type(record).__name__}")
    host = record.host if keep_host else REDACTED_HOST
    if isinstance(record, VLESS):
        return replace(
            record,
            uuid=REDACTED_UUID,
            host=host,
            params=_redact_params(record.params),
        )
    if isinstance(record, VMess):
        return replace(
            record,
            uuid=REDACTED_UUID,
            host=host,
            extra=_redact_extra(record.extra),
        )
    if isinstance(record, Trojan):
        return replace(
            record,
            password=REDACTED,
            host=host,
            params=_redact_params(record.params),
        )
    if isinstance(record, Shadowsocks):
        return replace(
            record,
            password=REDACTED,
            host=host,
            params=_redact_params(record.params),
        )
    raise LinkValidationError(f"cannot redact record type: {type(record).__name__}")


def redact_link(link: str, *, keep_host: bool = True) -> str:
    """Parse a share link and return a redacted, serializable equivalent."""
    return serialize_link(redact_record(parse_link(link), keep_host=keep_host))


def redact_text(text: str, *, keep_host: bool = True) -> str:
    """Redact every recognizable share link embedded in free-form text.

    Invalid links that match the scheme pattern are replaced wholesale rather
    than echoed, preventing malformed credentials from leaking into logs.
    """
    if not isinstance(text, str):
        raise LinkValidationError("text must be a string")

    def replace_match(match: re.Match[str]) -> str:
        try:
            return redact_link(match.group(0), keep_host=keep_host)
        except LinkError:
            return "<redacted-invalid-link>"

    return _LINK_PATTERN.sub(replace_match, text)


def redact_records(records: list[Link], *, keep_host: bool = True) -> list[Link]:
    """Redact a list of protocol records."""
    return [redact_record(record, keep_host=keep_host) for record in records]
