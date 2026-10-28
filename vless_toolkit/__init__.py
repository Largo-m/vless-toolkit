"""Dependency-free tools for VLESS, VMess, Trojan and Shadowsocks links."""

from .errors import LinkError, LinkParseError, LinkValidationError
from .parser import SUPPORTED_SCHEMES, parse_link, serialize_link
from .shadowsocks import Shadowsocks, parse_shadowsocks, serialize_shadowsocks
from .subscription import decode_subscription, encode_subscription, parse_subscription
from .trojan import Trojan, parse_trojan, serialize_trojan
from .vless import VLESS, parse_vless, serialize_vless
from .vmess import VMess, parse_vmess, serialize_vmess

__version__ = "0.1.0"

__all__ = [
    "SUPPORTED_SCHEMES",
    "VLESS",
    "LinkError",
    "LinkParseError",
    "LinkValidationError",
    "Shadowsocks",
    "Trojan",
    "VMess",
    "__version__",
    "decode_subscription",
    "encode_subscription",
    "parse_link",
    "parse_shadowsocks",
    "parse_subscription",
    "parse_trojan",
    "parse_vless",
    "parse_vmess",
    "serialize_link",
    "serialize_shadowsocks",
    "serialize_trojan",
    "serialize_vless",
    "serialize_vmess",
]
