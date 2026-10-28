"""Dependency-free tools for VLESS, VMess, Trojan and Shadowsocks links."""

from .errors import LinkError, LinkParseError, LinkValidationError
from .trojan import Trojan, parse_trojan, serialize_trojan
from .vless import VLESS, parse_vless, serialize_vless
from .vmess import VMess, parse_vmess, serialize_vmess

__version__ = "0.1.0"

__all__ = [
    "VLESS",
    "LinkError",
    "LinkParseError",
    "LinkValidationError",
    "Trojan",
    "VMess",
    "__version__",
    "parse_trojan",
    "parse_vless",
    "parse_vmess",
    "serialize_trojan",
    "serialize_vless",
    "serialize_vmess",
]
