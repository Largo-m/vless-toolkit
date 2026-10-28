"""Unified parsing and serialization across supported protocols."""

from __future__ import annotations

from typing import Union

from .errors import LinkParseError, LinkValidationError
from .shadowsocks import Shadowsocks, parse_shadowsocks, serialize_shadowsocks
from .trojan import Trojan, parse_trojan, serialize_trojan
from .vless import VLESS, parse_vless, serialize_vless
from .vmess import VMess, parse_vmess, serialize_vmess

Link = Union[VLESS, VMess, Trojan, Shadowsocks]

SUPPORTED_SCHEMES = ("vless", "vmess", "trojan", "ss")

_PROTOCOL_NAMES = {
    VLESS: "vless",
    VMess: "vmess",
    Trojan: "trojan",
    Shadowsocks: "shadowsocks",
}


def protocol_name(record: Link) -> str:
    """Return the friendly protocol name for a record.

    Raises:
        LinkValidationError: If ``record`` is not a supported record type.
    """
    name = _PROTOCOL_NAMES.get(type(record))
    if name is None:
        raise LinkValidationError(f"unsupported record type: {type(record).__name__}")
    return name


def parse_link(link: str) -> Link:
    """Parse any supported share link by dispatching on its scheme.

    Args:
        link: A ``vless://``, ``vmess://``, ``trojan://`` or ``ss://`` link.

    Returns:
        The matching protocol record.

    Raises:
        LinkParseError: If the link is malformed or its scheme is unsupported.
    """
    if not isinstance(link, str):
        raise LinkParseError("share link must be a string")
    candidate = link.strip()
    scheme, separator, _ = candidate.partition("://")
    if not separator or not scheme:
        raise LinkParseError("share link is missing a scheme")
    scheme = scheme.lower()
    parsers = {
        "vless": parse_vless,
        "vmess": parse_vmess,
        "trojan": parse_trojan,
        "ss": parse_shadowsocks,
    }
    parser = parsers.get(scheme)
    if parser is None:
        supported = ", ".join(f"{name}://" for name in SUPPORTED_SCHEMES)
        raise LinkParseError(f"unsupported scheme {scheme!r}; expected one of {supported}")
    return parser(candidate)


def serialize_link(record: Link) -> str:
    """Serialize any supported protocol record back to a share link.

    Raises:
        LinkValidationError: If ``record`` is not a supported record type.
    """
    serializers = {
        VLESS: serialize_vless,
        VMess: serialize_vmess,
        Trojan: serialize_trojan,
        Shadowsocks: serialize_shadowsocks,
    }
    serializer = serializers.get(type(record))
    if serializer is None:
        raise LinkValidationError(f"unsupported record type: {type(record).__name__}")
    return serializer(record)
