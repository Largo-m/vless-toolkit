"""Canonicalization and semantic deduplication for proxy links.

Two links often describe the same server while differing in display name,
query-parameter order or explicit default values. Normalization produces a
stable representation, and fingerprints allow deduplication without exposing
credentials.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from hashlib import sha256
from typing import Any

from .errors import LinkValidationError
from .parser import Link, parse_link, serialize_link
from .shadowsocks import Shadowsocks
from .trojan import Trojan
from .vless import VLESS
from .vmess import VMess

_LOWERCASE_QUERY_KEYS = {"encryption", "security", "type"}


def _normalize_params(
    params: dict[str, str], defaults: set[tuple[str, str]]
) -> dict[str, str]:
    """Lower-case known enum values, drop defaults and sort keys."""
    normalized: dict[str, str] = {}
    for key, value in params.items():
        normalized_value = value.lower() if key in _LOWERCASE_QUERY_KEYS else value
        if (key, normalized_value) in defaults:
            continue
        normalized[key] = normalized_value
    return dict(sorted(normalized.items()))


def _normalize_extra(value: Any) -> Any:
    """Recursively sort JSON extension dictionaries for stable output."""
    if isinstance(value, dict):
        return {key: _normalize_extra(child) for key, child in sorted(value.items())}
    if isinstance(value, list):
        return [_normalize_extra(child) for child in value]
    return value


def normalize_record(record: Link, *, keep_name: bool = True) -> Link:
    """Return a canonical copy of a protocol record.

    Host names, cipher and transport enum values are lower-cased, query
    parameters are sorted, known explicit defaults are dropped, and VMess
    extension dictionaries are sorted recursively. The display name is kept
    unless ``keep_name`` is false.

    Raises:
        LinkValidationError: If ``record`` is not a supported record type.
    """
    if not isinstance(record, (VLESS, VMess, Trojan, Shadowsocks)):
        raise LinkValidationError(f"cannot normalize record type: {type(record).__name__}")
    name = record.name if keep_name else ""
    if isinstance(record, VLESS):
        params = _normalize_params(
            record.params,
            defaults={("encryption", "none"), ("security", "none")},
        )
        return replace(record, host=record.host.lower(), params=params, name=name)
    if isinstance(record, VMess):
        return replace(
            record,
            host=record.host.lower(),
            security=record.security.lower(),
            network=record.network.lower(),
            header_type=record.header_type.lower(),
            tls=record.tls.lower(),
            extra=_normalize_extra(record.extra),
            name=name,
        )
    if isinstance(record, Trojan):
        params = _normalize_params(record.params, defaults={("security", "tls")})
        return replace(record, host=record.host.lower(), params=params, name=name)
    if isinstance(record, Shadowsocks):
        params = _normalize_params(record.params, defaults=set())
        return replace(
            record,
            method=record.method.lower(),
            host=record.host.lower(),
            params=params,
            name=name,
        )
    raise LinkValidationError(f"cannot normalize record type: {type(record).__name__}")


def normalize_link(link: str, *, keep_name: bool = True) -> str:
    """Parse a link and return its canonical serialization."""
    return serialize_link(normalize_record(parse_link(link), keep_name=keep_name))


def record_fingerprint(record: Link, *, include_name: bool = False) -> str:
    """Return a SHA-256 fingerprint of a record's canonical form.

    Names are ignored by default because providers commonly vary cosmetic
    labels for the same endpoint. Credentials are hashed rather than exposed.
    """
    canonical = serialize_link(normalize_record(record, keep_name=include_name))
    return sha256(canonical.encode("utf-8")).hexdigest()


def dedupe_records(records: Iterable[Link], *, include_names: bool = False) -> list[Link]:
    """Remove semantically duplicate records, preserving first occurrences.

    Returned records are normalized. By default display names are ignored when
    deciding whether two records are duplicates.
    """
    seen: set[str] = set()
    unique: list[Link] = []
    for record in records:
        normalized = normalize_record(record, keep_name=True)
        fingerprint = record_fingerprint(normalized, include_name=include_names)
        if fingerprint not in seen:
            seen.add(fingerprint)
            unique.append(normalized)
    return unique


def dedupe_links(links: Iterable[str], *, include_names: bool = False) -> list[Link]:
    """Parse and semantically deduplicate an iterable of share-link strings."""
    records: list[Link] = []
    for link in links:
        if not isinstance(link, str):
            raise LinkValidationError("dedupe_links expects share-link strings")
        records.append(parse_link(link))
    return dedupe_records(records, include_names=include_names)
