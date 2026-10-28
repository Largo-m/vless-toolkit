"""Dependency-free tools for VLESS, VMess, Trojan and Shadowsocks links."""

from .errors import LinkError, LinkParseError, LinkValidationError
from .export import record_to_dict, records_to_json, records_to_yaml
from .parser import SUPPORTED_SCHEMES, parse_link, serialize_link
from .qr import QRCode, encode_qr, link_to_ascii_qr, qr_to_ascii
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
    "QRCode",
    "Shadowsocks",
    "Trojan",
    "VMess",
    "__version__",
    "decode_subscription",
    "encode_qr",
    "encode_subscription",
    "link_to_ascii_qr",
    "parse_link",
    "parse_shadowsocks",
    "parse_subscription",
    "parse_trojan",
    "parse_vless",
    "parse_vmess",
    "qr_to_ascii",
    "record_to_dict",
    "records_to_json",
    "records_to_yaml",
    "serialize_link",
    "serialize_shadowsocks",
    "serialize_trojan",
    "serialize_vless",
    "serialize_vmess",
]
