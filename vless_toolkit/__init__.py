"""Dependency-free tools for VLESS, VMess, Trojan and Shadowsocks links."""

from .errors import LinkError, LinkParseError, LinkValidationError
from .shadowsocks import Shadowsocks, parse_shadowsocks, serialize_shadowsocks
from .trojan import Trojan, parse_trojan, serialize_trojan
from .vless import VLESS, parse_vless, serialize_vless
from .vmess import VMess, parse_vmess, serialize_vmess

__version__ = "0.1.0"

__all__ = [
    "VLESS",
    "LinkError",
    "LinkParseError",
    "LinkValidationError",
    "Shadowsocks",
    "Trojan",
    "VMess",
    "__version__",
    "parse_shadowsocks",
    "parse_trojan",
    "parse_vless",
    "parse_vmess",
    "serialize_shadowsocks",
    "serialize_trojan",
    "serialize_vless",
    "serialize_vmess",
]
