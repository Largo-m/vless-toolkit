"""Command-line interface for :mod:`vless_toolkit`.

Sources may be literal share links, paths to UTF-8 text/subscription files, or
``-`` to read standard input. The CLI never makes network requests, so links
and credentials stay local.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .errors import LinkError, LinkParseError, LinkValidationError
from .export import records_to_json, records_to_yaml
from .normalize import dedupe_records, normalize_record
from .parser import Link, parse_link, protocol_name, serialize_link
from .qr import link_to_ascii_qr
from .redact import redact_records
from .shadowsocks import Shadowsocks
from .stats import summarize_records
from .subscription import decode_subscription, encode_subscription
from .table import color_enabled, render_records_table, render_table
from .trojan import Trojan
from .vless import VLESS
from .vmess import VMess

_SCHEME_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://")

_VMESS_OPTIONS = {
    "network": "network",
    "security": "security",
    "tls": "tls",
    "sni": "sni",
    "path": "path",
    "host": "host_header",
    "alpn": "alpn",
    "fp": "fingerprint",
}

_VMESS_INT_OPTIONS = {"alter-id": "alter_id"}


class CliError(Exception):
    """A user-facing command-line error (exit status 2)."""


def _port(value: str) -> int:
    """argparse type for a valid TCP/UDP port."""
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _parse_sets(values: Sequence[str]) -> dict[str, str]:
    """Parse repeated ``KEY=VALUE`` options, rejecting duplicates."""
    result: dict[str, str] = {}
    for item in values:
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise CliError(f"invalid --set value {item!r}; expected KEY=VALUE")
        if key in result:
            raise CliError(f"duplicate --set key: {key!r}")
        result[key] = value
    return result


def _read_source(source: str) -> tuple[str, str]:
    """Read one source and return ``(text, display-label)``."""
    if source == "-":
        try:
            return sys.stdin.read(), "stdin"
        except UnicodeError as exc:
            raise CliError(f"could not read stdin as UTF-8: {exc}") from exc
    if source.lower().startswith(_SCHEME_PREFIXES):
        return source, "link"
    path = Path(source)
    if not path.is_file():
        raise CliError(f"source not found: {source}")
    try:
        return path.read_text(encoding="utf-8-sig"), str(path)
    except (OSError, UnicodeError) as exc:
        raise CliError(f"could not read {source}: {exc}") from exc


def _load_links(sources: Sequence[str]) -> list[str]:
    """Load link strings from direct links, files and/or stdin."""
    links: list[str] = []
    for source in sources:
        text, label = _read_source(source)
        if label == "link":
            links.append(text.strip())
            continue
        try:
            links.extend(decode_subscription(text))
        except LinkParseError as exc:
            raise CliError(f"{label}: {exc}") from exc
    if not links:
        raise CliError("no share links found in the provided sources")
    return links


def _parse_records(sources: Sequence[str]) -> list[Link]:
    """Load and parse every link, reporting the source index on failure."""
    records: list[Link] = []
    for index, link in enumerate(_load_links(sources), start=1):
        try:
            records.append(parse_link(link))
        except LinkParseError as exc:
            raise CliError(f"link {index}: {exc}") from exc
    return records


def _record_lines(record: Link) -> list[str]:
    """Render a record as stable human-readable key/value lines."""
    lines = [
        f"protocol: {protocol_name(record)}",
        f"name: {record.name}",
        f"host: {record.host}",
        f"port: {record.port}",
    ]
    if isinstance(record, VLESS):
        lines.append(f"uuid: {record.uuid}")
    elif isinstance(record, VMess):
        lines.extend(
            [
                f"uuid: {record.uuid}",
                f"network: {record.network}",
                f"tls: {record.tls}",
            ]
        )
    elif isinstance(record, Trojan):
        lines.append(f"password: {record.password}")
    elif isinstance(record, Shadowsocks):
        lines.extend([f"method: {record.method}", f"password: {record.password}"])
    if getattr(record, "params", None):
        lines.append("params:")
        lines.extend(f"  {key}: {value}" for key, value in record.params.items())
    return lines


def _color_enabled(args: argparse.Namespace) -> bool:
    """Apply CLI and environment color preferences for stdout."""
    return color_enabled(
        sys.stdout,
        no_color=args.no_color,
        force_color=args.force_color,
    )


def _cmd_parse(args: argparse.Namespace) -> int:
    records = _parse_records(args.sources)
    if args.redact or args.hide_hosts:
        records = redact_records(records, keep_host=not args.hide_hosts)
    if args.format == "table":
        print(render_records_table(records, color=_color_enabled(args)))
        return 0
    if args.format == "json":
        print(records_to_json(records))
        return 0
    if args.format == "yaml":
        print(records_to_yaml(records), end="")
        return 0
    for index, record in enumerate(records):
        if index:
            print()
        print("\n".join(_record_lines(record)))
    return 0


def _build_record(args: argparse.Namespace) -> Link:
    """Construct a protocol record from ``build`` options."""
    params = _parse_sets(args.set)
    if args.protocol == "vless":
        if not args.uuid:
            raise CliError("--uuid is required for VLESS")
        return VLESS(
            uuid=args.uuid,
            host=args.host,
            port=args.port,
            params=params,
            name=args.name,
        )
    if args.protocol == "trojan":
        if not args.password:
            raise CliError("--password is required for Trojan")
        return Trojan(
            password=args.password,
            host=args.host,
            port=args.port,
            params=params,
            name=args.name,
        )
    if args.protocol == "ss":
        if not args.password:
            raise CliError("--password is required for Shadowsocks")
        if not args.method:
            raise CliError("--method is required for Shadowsocks")
        return Shadowsocks(
            method=args.method,
            password=args.password,
            host=args.host,
            port=args.port,
            params=params,
            name=args.name,
        )
    if args.protocol == "vmess":
        if not args.uuid:
            raise CliError("--uuid is required for VMess")
        options: dict[str, object] = {}
        for key, value in params.items():
            if key in _VMESS_OPTIONS:
                options[_VMESS_OPTIONS[key]] = value
            elif key in _VMESS_INT_OPTIONS:
                try:
                    options[_VMESS_INT_OPTIONS[key]] = int(value)
                except ValueError as exc:
                    raise CliError(f"VMess option {key!r} must be an integer") from exc
            else:
                valid = ", ".join(sorted([*_VMESS_OPTIONS, *_VMESS_INT_OPTIONS]))
                raise CliError(f"unknown VMess option {key!r}; expected one of {valid}")
        return VMess(
            uuid=args.uuid,
            host=args.host,
            port=args.port,
            name=args.name,
            **options,
        )
    raise CliError(f"unsupported protocol: {args.protocol}")  # pragma: no cover


def _cmd_build(args: argparse.Namespace) -> int:
    try:
        print(serialize_link(_build_record(args)))
    except LinkValidationError as exc:
        raise CliError(str(exc)) from exc
    return 0


def _cmd_convert(args: argparse.Namespace) -> int:
    records = _parse_records(args.sources)
    if args.redact or args.hide_hosts:
        records = redact_records(records, keep_host=not args.hide_hosts)
    if args.subscription:
        print(encode_subscription(records, urlsafe=args.urlsafe, padding=not args.no_padding))
    elif args.format == "json":
        print(records_to_json(records))
    elif args.format == "yaml":
        print(records_to_yaml(records), end="")
    else:
        for record in records:
            print(serialize_link(record))
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    links = _load_links(args.sources)
    failures = 0
    for index, link in enumerate(links, start=1):
        try:
            record = parse_link(link)
        except LinkParseError as exc:
            failures += 1
            print(f"invalid #{index}: {exc}", file=sys.stderr)
        else:
            label = record.name or record.host
            print(f"ok #{index}: {protocol_name(record)} {label}")
    if failures:
        print(f"{failures} of {len(links)} link(s) invalid", file=sys.stderr)
        return 1
    print(f"{len(links)} link(s) valid")
    return 0


def _cmd_dedupe(args: argparse.Namespace) -> int:
    records = _parse_records(args.sources)
    unique = dedupe_records(records, include_names=args.keep_names)
    for record in unique:
        print(serialize_link(record))
    print(
        f"removed {len(records) - len(unique)} duplicate(s); {len(unique)} unique",
        file=sys.stderr,
    )
    return 0


def _cmd_normalize(args: argparse.Namespace) -> int:
    records = _parse_records(args.sources)
    for record in records:
        print(serialize_link(normalize_record(record)))
    return 0


def _cmd_summary(args: argparse.Namespace) -> int:
    stats = summarize_records(_parse_records(args.sources))
    if args.format == "table":
        color = _color_enabled(args)
        print(f"total: {stats.total}  unique hosts: {stats.unique_hosts}")
        print()
        print(
            render_table(
                ("Protocol", "Count"),
                stats.by_protocol.items(),
                aligns=("l", "r"),
                color=color,
            )
        )
        print()
        print(
            render_table(
                ("Country", "Count"),
                stats.by_country.items(),
                aligns=("l", "r"),
                color=color,
            )
        )
        print()
        print(
            render_table(
                ("Country", "Protocol", "Count"),
                (
                    (country, protocol, count)
                    for (country, protocol), count in stats.by_country_protocol.items()
                ),
                aligns=("l", "l", "r"),
                color=color,
            )
        )
        return 0
    print(f"total: {stats.total}")
    print(f"unique hosts: {stats.unique_hosts}")
    print("by protocol:")
    for protocol, count in stats.by_protocol.items():
        print(f"  {protocol}: {count}")
    print("by country:")
    for country, count in stats.by_country.items():
        print(f"  {country}: {count}")
    print("by country/protocol:")
    for (country, protocol), count in stats.by_country_protocol.items():
        print(f"  {country}/{protocol}: {count}")
    return 0


def _cmd_qr(args: argparse.Namespace) -> int:
    links = _load_links([args.source])
    if len(links) != 1:
        raise CliError(f"QR output requires exactly one link, found {len(links)}")
    try:
        record = parse_link(links[0])
    except LinkParseError as exc:
        raise CliError(str(exc)) from exc
    print(link_to_ascii_qr(serialize_link(record), border=args.border), end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse command tree."""
    parser = argparse.ArgumentParser(
        prog="vless-toolkit",
        description="Parse, build, validate and convert proxy share links locally.",
    )
    parser.add_argument("--version", action="version", version=f"vless-toolkit {__version__}")
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors (NO_COLOR is also honored)",
    )
    parser.add_argument(
        "--color",
        dest="force_color",
        action="store_true",
        help="force ANSI colors even when stdout is not a TTY",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    parse = commands.add_parser("parse", help="show parsed fields for links")
    parse.add_argument("sources", nargs="+", help="link, file path, or - for stdin")
    parse.add_argument(
        "--format",
        choices=["text", "table", "json", "yaml"],
        default="text",
        help="output format (default: text)",
    )
    parse.add_argument("--redact", action="store_true", help="mask credentials in output")
    parse.add_argument(
        "--hide-hosts",
        action="store_true",
        help="also replace server hosts (implies --redact)",
    )
    parse.set_defaults(func=_cmd_parse)

    build = commands.add_parser("build", help="build a share link from fields")
    build.add_argument("--protocol", required=True, choices=["vless", "vmess", "trojan", "ss"])
    build.add_argument("--host", required=True)
    build.add_argument("--port", required=True, type=_port)
    build.add_argument("--uuid", help="VLESS/VMess user UUID")
    build.add_argument("--password", help="Trojan/Shadowsocks password")
    build.add_argument("--method", help="Shadowsocks cipher")
    build.add_argument("--name", default="", help="display name")
    build.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
    build.set_defaults(func=_cmd_build)

    convert = commands.add_parser("convert", help="convert links between formats")
    convert.add_argument("sources", nargs="+", help="link, file path, or - for stdin")
    convert.add_argument("--subscription", action="store_true", help="emit base64 subscription")
    convert.add_argument("--urlsafe", action="store_true", help="URL-safe subscription base64")
    convert.add_argument("--no-padding", action="store_true", help="omit subscription padding")
    convert.add_argument(
        "--format",
        choices=["links", "json", "yaml"],
        default="links",
        help="output format (default: links)",
    )
    convert.add_argument("--redact", action="store_true", help="mask credentials in output")
    convert.add_argument(
        "--hide-hosts",
        action="store_true",
        help="also replace server hosts (implies --redact)",
    )
    convert.set_defaults(func=_cmd_convert)

    validate = commands.add_parser("validate", help="validate links and report failures")
    validate.add_argument("sources", nargs="+", help="link, file path, or - for stdin")
    validate.set_defaults(func=_cmd_validate)

    dedupe = commands.add_parser(
        "dedupe", help="remove semantic duplicate links (names ignored by default)"
    )
    dedupe.add_argument("sources", nargs="+", help="link, file path, or - for stdin")
    dedupe.add_argument(
        "--keep-names",
        action="store_true",
        help="treat differently named links as distinct",
    )
    dedupe.set_defaults(func=_cmd_dedupe)

    normalize = commands.add_parser("normalize", help="print canonical link forms")
    normalize.add_argument("sources", nargs="+", help="link, file path, or - for stdin")
    normalize.set_defaults(func=_cmd_normalize)

    summary = commands.add_parser("summary", help="count links by protocol and host")
    summary.add_argument("sources", nargs="+", help="link, file path, or - for stdin")
    summary.add_argument(
        "--format",
        choices=["text", "table"],
        default="text",
        help="output format (default: text)",
    )
    summary.set_defaults(func=_cmd_summary)

    qr = commands.add_parser("qr", help="print an ASCII QR code for one link")
    qr.add_argument("source", help="one link, a file with one link, or - for stdin")
    qr.add_argument(
        "--border",
        type=int,
        default=4,
        metavar="N",
        help="quiet-zone width in modules, 0-16 (default: 4)",
    )
    qr.set_defaults(func=_cmd_qr)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (CliError, LinkError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
