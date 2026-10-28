"""Dependency-free tools for VLESS, VMess, Trojan and Shadowsocks links."""

from .errors import LinkError, LinkParseError, LinkValidationError
from .export import record_to_dict, records_to_json, records_to_yaml
from .normalize import (
    dedupe_links,
    dedupe_records,
    normalize_link,
    normalize_record,
    record_fingerprint,
)
from .parser import SUPPORTED_SCHEMES, parse_link, protocol_name, serialize_link
from .qr import QRCode, encode_qr, link_to_ascii_qr, qr_to_ascii
from .redact import (
    redact_link,
    redact_record,
    redact_records,
    redact_secret,
    redact_text,
)
from .shadowsocks import Shadowsocks, parse_shadowsocks, serialize_shadowsocks
from .stats import (
    UNKNOWN_COUNTRY,
    SummaryStats,
    country_for_record,
    infer_country,
    summarize_records,
)
from .subscription import decode_subscription, encode_subscription, parse_subscription
from .table import color_enabled, display_width, render_records_table, render_table
from .trojan import Trojan, parse_trojan, serialize_trojan
from .vless import VLESS, parse_vless, serialize_vless
from .vmess import VMess, parse_vmess, serialize_vmess

__version__ = "1.0.0"

__all__ = [
    "SUPPORTED_SCHEMES",
    "UNKNOWN_COUNTRY",
    "VLESS",
    "LinkError",
    "LinkParseError",
    "LinkValidationError",
    "QRCode",
    "Shadowsocks",
    "SummaryStats",
    "Trojan",
    "VMess",
    "__version__",
    "color_enabled",
    "country_for_record",
    "decode_subscription",
    "dedupe_links",
    "dedupe_records",
    "display_width",
    "encode_qr",
    "encode_subscription",
    "infer_country",
    "link_to_ascii_qr",
    "normalize_link",
    "normalize_record",
    "parse_link",
    "parse_shadowsocks",
    "parse_subscription",
    "parse_trojan",
    "parse_vless",
    "parse_vmess",
    "protocol_name",
    "qr_to_ascii",
    "record_fingerprint",
    "record_to_dict",
    "records_to_json",
    "records_to_yaml",
    "redact_link",
    "redact_record",
    "redact_records",
    "redact_secret",
    "redact_text",
    "render_records_table",
    "render_table",
    "serialize_link",
    "serialize_shadowsocks",
    "serialize_trojan",
    "serialize_vless",
    "serialize_vmess",
    "summarize_records",
]
