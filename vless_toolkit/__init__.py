"""Dependency-free tools for VLESS, VMess, Trojan and Shadowsocks links."""

from .errors import LinkError, LinkParseError, LinkValidationError
from .vless import VLESS, parse_vless

__version__ = "0.1.0"

__all__ = [
    "VLESS",
    "LinkError",
    "LinkParseError",
    "LinkValidationError",
    "__version__",
    "parse_vless",
]
