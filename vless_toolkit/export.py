"""Structured JSON and dependency-free YAML export for proxy records.

The YAML writer intentionally implements only the small, unambiguous subset
needed by this project: mappings, sequences and scalar values. Strings are
quoted whenever plain YAML could change their meaning.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from typing import Any

from .errors import LinkValidationError
from .parser import Link
from .shadowsocks import Shadowsocks
from .trojan import Trojan
from .vless import VLESS
from .vmess import VMess

_SAFE_PLAIN = re.compile(r"^[A-Za-z_][A-Za-z0-9._/@+-]*$")
_RESERVED = {"null", "true", "false", "yes", "no", "on", "off", "~"}


def record_to_dict(record: Link) -> dict[str, Any]:
    """Convert a protocol record to an export-friendly dictionary.

    Secrets are included because exports are intended for local migration. Use
    the redaction helpers before sharing or logging exported data.

    Raises:
        LinkValidationError: If ``record`` is not a supported record type.
    """
    if isinstance(record, VLESS):
        return {
            "protocol": "vless",
            "name": record.name,
            "host": record.host,
            "port": record.port,
            "uuid": record.uuid,
            "params": dict(record.params),
        }
    if isinstance(record, VMess):
        result: dict[str, Any] = {
            "protocol": "vmess",
            "name": record.name,
            "host": record.host,
            "port": record.port,
            "uuid": record.uuid,
            "alter_id": record.alter_id,
            "security": record.security,
            "network": record.network,
            "header_type": record.header_type,
            "tls": record.tls,
            "sni": record.sni,
            "host_header": record.host_header,
            "path": record.path,
            "alpn": record.alpn,
            "fingerprint": record.fingerprint,
            "version": record.version,
        }
        if record.extra:
            result["extra"] = record.extra
        return result
    if isinstance(record, Trojan):
        return {
            "protocol": "trojan",
            "name": record.name,
            "host": record.host,
            "port": record.port,
            "password": record.password,
            "params": dict(record.params),
        }
    if isinstance(record, Shadowsocks):
        return {
            "protocol": "shadowsocks",
            "name": record.name,
            "host": record.host,
            "port": record.port,
            "method": record.method,
            "password": record.password,
            "plugin": record.plugin,
            "params": dict(record.params),
        }
    raise LinkValidationError(f"cannot export record type: {type(record).__name__}")


def records_to_json(records: Iterable[Link], *, indent: int = 2) -> str:
    """Serialize records as a JSON array.

    Raises:
        LinkValidationError: If a record or one of its extra fields cannot be
            represented as JSON.
    """
    payload = [record_to_dict(record) for record in records]
    try:
        return json.dumps(payload, ensure_ascii=False, indent=indent, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise LinkValidationError(f"cannot serialize records as JSON: {exc}") from exc


def _yaml_scalar(value: Any) -> str:
    """Render a scalar as a valid, unambiguous YAML 1.2 scalar."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise LinkValidationError("YAML output does not support NaN or infinity")
        return repr(value)
    if isinstance(value, str):
        if (
            value
            and value.lower() not in _RESERVED
            and _SAFE_PLAIN.fullmatch(value)
            and not value.endswith(":")
        ):
            return value
        return json.dumps(value, ensure_ascii=False)
    raise LinkValidationError(f"unsupported YAML value type: {type(value).__name__}")


def _is_collection(value: Any) -> bool:
    """Return whether a value is a mapping or sequence."""
    return isinstance(value, (dict, list, tuple))


def _yaml_lines(value: Any, indent: int = 0) -> list[str]:
    """Recursively render a value as indented YAML lines."""
    prefix = " " * indent
    if isinstance(value, dict):
        if not value:
            return [f"{prefix}{{}}"]
        lines: list[str] = []
        for key, child in value.items():
            rendered_key = _yaml_scalar(key)
            if _is_collection(child):
                if not child:
                    empty = "{}" if isinstance(child, dict) else "[]"
                    lines.append(f"{prefix}{rendered_key}: {empty}")
                else:
                    lines.append(f"{prefix}{rendered_key}:")
                    lines.extend(_yaml_lines(child, indent + 2))
            else:
                lines.append(f"{prefix}{rendered_key}: {_yaml_scalar(child)}")
        return lines
    if isinstance(value, (list, tuple)):
        if not value:
            return [f"{prefix}[]"]
        lines = []
        for child in value:
            if not _is_collection(child):
                lines.append(f"{prefix}- {_yaml_scalar(child)}")
            elif not child:
                empty = "{}" if isinstance(child, dict) else "[]"
                lines.append(f"{prefix}- {empty}")
            else:
                nested = _yaml_lines(child, indent + 2)
                lines.append(f"{prefix}- {nested[0][indent + 2 :]}")
                lines.extend(nested[1:])
        return lines
    return [f"{prefix}{_yaml_scalar(value)}"]


def records_to_yaml(records: Iterable[Link]) -> str:
    """Serialize records as a YAML sequence without third-party libraries."""
    payload = [record_to_dict(record) for record in records]
    return "\n".join(_yaml_lines(payload, 0)) + "\n"
