"""Base64 subscription payload decoding and encoding.

A subscription is normally a base64-encoded, newline-separated list of share
links. Real-world providers also serve plain text and both standard and
URL-safe base64, sometimes without padding, so decoding is deliberately
forgiving while every decoded link is strictly validated.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable

from .errors import LinkParseError, LinkValidationError
from .parser import Link, parse_link, serialize_link

_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")


def _decode_base64_payload(payload: str) -> str:
    """Decode a subscription body using either base64 alphabet."""
    compact = "".join(payload.split())
    if not compact:
        raise LinkParseError("subscription payload is empty")
    padded = compact + "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LinkParseError(f"subscription is not valid base64: {exc}") from exc
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise LinkParseError("decoded subscription is not valid UTF-8") from exc


def decode_subscription(payload: str) -> list[str]:
    """Decode a subscription payload into a list of share-link strings.

    Plain-text payloads are returned as-is. Base64 payloads, with either
    alphabet and optional padding or line wrapping, are decoded first. Blank
    lines are discarded and link order is preserved.

    Raises:
        LinkParseError: If the payload is empty, invalid base64, or decodes to
            no links.
    """
    if not isinstance(payload, str):
        raise LinkParseError("subscription payload must be a string")
    text = payload.strip()
    if not text:
        raise LinkParseError("subscription payload is empty")

    lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    if not any(line.lower().startswith(_SCHEMES) for line in lines):
        text = _decode_base64_payload(text)
        lines = [
            line.strip()
            for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        ]

    links = [line for line in lines if line]
    if not links:
        raise LinkParseError("subscription contains no share links")
    if not any(line.lower().startswith(_SCHEMES) for line in links):
        raise LinkParseError("subscription does not contain any supported share links")
    return links


def parse_subscription(payload: str) -> list[Link]:
    """Decode and parse every link in a subscription payload.

    Raises:
        LinkParseError: If the payload cannot be decoded or any link is invalid.
            The error identifies the offending line number.
    """
    records: list[Link] = []
    for number, link in enumerate(decode_subscription(payload), start=1):
        try:
            records.append(parse_link(link))
        except LinkParseError as exc:
            raise LinkParseError(f"subscription line {number}: {exc}") from exc
    return records


def encode_subscription(
    links: Iterable[Link | str],
    *,
    urlsafe: bool = False,
    padding: bool = True,
) -> str:
    """Encode share links or records as a base64 subscription payload.

    Args:
        links: Share-link strings or protocol records.
        urlsafe: Use the URL-safe base64 alphabet.
        padding: Keep ``=`` padding (the conventional subscription form).

    Raises:
        LinkValidationError: If a value is not a supported record/link.
    """
    lines: list[str] = []
    for item in links:
        if isinstance(item, str):
            candidate = item.strip()
            if not candidate:
                raise LinkValidationError("cannot encode an empty share link")
            try:
                parse_link(candidate)
            except LinkParseError as exc:
                raise LinkValidationError(f"cannot encode invalid share link: {exc}") from exc
            lines.append(candidate)
        else:
            try:
                lines.append(serialize_link(item))
            except LinkValidationError:
                raise
            except Exception as exc:  # pragma: no cover - defensive guard
                raise LinkValidationError(f"cannot encode {type(item).__name__}") from exc
    if not lines:
        raise LinkValidationError("cannot encode an empty subscription")
    raw = "\n".join(lines).encode()
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    encoded = encoder(raw).decode("ascii")
    return encoded if padding else encoded.rstrip("=")
