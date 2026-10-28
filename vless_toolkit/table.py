"""Dependency-free table rendering for terminal output.

Tables are plain ASCII by default. Color is applied only when the caller asks
for it, so redirected output stays machine-friendly. Width calculation is
Unicode-aware: wide East Asian characters count as two columns and combining
marks as zero.
"""

from __future__ import annotations

import os
import sys
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from typing import IO, Any

from .errors import LinkValidationError
from .parser import Link, protocol_name
from .shadowsocks import Shadowsocks
from .stats import country_for_record
from .vmess import VMess

ANSI_RESET = "\x1b[0m"
ANSI_HEADER = "\x1b[1;36m"

Align = str


def _char_width(character: str) -> int:
    if unicodedata.combining(character):
        return 0
    if unicodedata.east_asian_width(character) in ("W", "F"):
        return 2
    return 1


def display_width(value: str) -> int:
    """Return the terminal column width of ``value``."""
    return sum(_char_width(character) for character in value)


def _clean(value: Any) -> str:
    text = str(value)
    return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def _pad(value: str, width: int, align: Align) -> str:
    missing = width - display_width(value)
    if missing <= 0:
        return value
    if align == "r":
        return " " * missing + value
    if align == "c":
        left = missing // 2
        return " " * left + value + " " * (missing - left)
    return value + " " * missing


def render_table(
    headers: Sequence[Any],
    rows: Iterable[Sequence[Any]],
    *,
    aligns: Sequence[Align] | None = None,
    color: bool = False,
) -> str:
    """Render an ASCII table with optional ANSI-colored headers.

    Args:
        headers: Column labels.
        rows: Row values, each with the same length as ``headers``.
        aligns: Per-column ``"l"``, ``"r"`` or ``"c"`` alignment.
        color: Wrap the header in ANSI bold/cyan.

    Raises:
        LinkValidationError: If headers or rows are malformed.
    """
    labels = [_clean(header) for header in headers]
    if not labels:
        raise LinkValidationError("table requires at least one column")
    column_count = len(labels)
    alignment = list(aligns) if aligns is not None else ["l"] * column_count
    if len(alignment) != column_count:
        raise LinkValidationError("alignment count must match the number of columns")
    if any(value not in {"l", "r", "c"} for value in alignment):
        raise LinkValidationError("table alignment must be 'l', 'r' or 'c'")

    rendered_rows: list[list[str]] = []
    for row in rows:
        cells = [_clean(cell) for cell in row]
        if len(cells) != column_count:
            raise LinkValidationError(
                f"table row has {len(cells)} cells, expected {column_count}"
            )
        rendered_rows.append(cells)

    widths = [display_width(label) for label in labels]
    for cells in rendered_rows:
        for index, cell in enumerate(cells):
            widths[index] = max(widths[index], display_width(cell))

    def render_row(cells: Sequence[str]) -> str:
        return " | ".join(
            _pad(cell, widths[index], alignment[index]) for index, cell in enumerate(cells)
        )

    header = render_row(labels)
    if color:
        header = f"{ANSI_HEADER}{header}{ANSI_RESET}"
    separator = "-+-".join("-" * width for width in widths)
    return "\n".join([header, separator, *(render_row(cells) for cells in rendered_rows)])


def _transport(record: Link) -> str:
    if isinstance(record, VMess):
        return record.network or "tcp"
    if isinstance(record, Shadowsocks):
        return record.method
    return record.params.get("type") or "tcp"


def _security(record: Link) -> str:
    if isinstance(record, VMess):
        return record.tls or "none"
    if isinstance(record, Shadowsocks):
        return "-"
    return record.params.get("security") or "none"


def render_records_table(records: Iterable[Link], *, color: bool = False) -> str:
    """Render a credential-free overview table for parsed records.

    UUIDs and passwords are never included, making this format suitable for
    screenshots, issue reports and CI logs.
    """
    materialized = list(records)
    rows = [
        (
            index,
            protocol_name(record),
            country_for_record(record),
            record.name or "-",
            record.host,
            record.port,
            _transport(record),
            _security(record),
        )
        for index, record in enumerate(materialized, start=1)
    ]
    return render_table(
        ("#", "Protocol", "Country", "Name", "Host", "Port", "Transport", "Security"),
        rows,
        aligns=("r", "l", "l", "l", "l", "r", "l", "l"),
        color=color,
    )


def color_enabled(
    stream: IO[str] | None = None,
    *,
    no_color: bool = False,
    force_color: bool = False,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Decide whether ANSI color should be emitted.

    ``--no-color`` always wins; otherwise ``--color`` overrides the standard
    ``NO_COLOR`` environment variable. Without an explicit choice, color is
    enabled only for an interactive TTY.
    """
    if no_color:
        return False
    if force_color:
        return True
    environment = os.environ if environ is None else environ
    if environment.get("NO_COLOR"):
        return False
    target = sys.stdout if stream is None else stream
    isatty = getattr(target, "isatty", None)
    return bool(isatty and isatty())
