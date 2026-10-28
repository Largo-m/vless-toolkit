# vless-toolkit

[![CI](https://github.com/Largo-m/vless-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Largo-m/vless-toolkit/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Parse, validate, build and convert **VLESS**, **VMess**, **Trojan** and
**Shadowsocks** share links and subscription payloads — from a dependency-free
Python library or one command.

`vless-toolkit` runs entirely locally. It never fetches subscription URLs,
sends telemetry or needs a network connection, which keeps credentials on the
machine that already has them. The package has **no runtime dependencies** and
supports Python 3.9 and newer.

## Features

- **All four common link formats** with strict validation and round-trip tests.
- **Subscriptions** in plain text, standard base64 or URL-safe base64, with or
  without padding.
- **Canonical forms** — lower-case hosts/enums, sorted parameters and semantic
  deduplication that ignores display names by default.
- **Safe output** — credential redaction, credential-free tables and
  fingerprinting without writing secrets to logs.
- **Exports** to JSON and a dependency-free YAML emitter (`--format json|yaml`).
- **ASCII QR codes** for any supported link, implemented in pure Python
  (versions 1–10, error correction L).
- **Country summaries** inferred from flags, `[US]`-style tags or country names.
- **Typed public API**, frozen dataclasses and credential-safe `repr` output.

## Installation

From a checkout:

```bash
git clone https://github.com/Largo-m/vless-toolkit.git
cd vless-toolkit
python -m pip install .
```

For an isolated CLI, install with [pipx](https://pipx.pypa.io/):

```bash
pipx install .
```

Development setup installs pytest and ruff:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
```

## Quick start

Set a link in a variable (use single quotes in a real shell; history may still
record it):

```bash
LINK='vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example.com:443?security=tls&type=ws&path=%2Fws#Tokyo'
```

Parse it as text or as a table that never prints the UUID:

```bash
vless-toolkit parse "$LINK"
vless-toolkit parse "$LINK" --format table
```

```text
protocol: vless
name: Tokyo
host: edge.example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
params:
  security: tls
  type: ws
  path: /ws
```

Build a Trojan link, convert a list to a base64 subscription, or inspect a
subscription downloaded elsewhere:

```bash
vless-toolkit build --protocol trojan --host edge.example.com --port 443 \
  --password 'example-password' --name 'Tokyo' --set security=tls

vless-toolkit convert links.txt --subscription > subscription.txt
vless-toolkit parse subscription.txt --format table
vless-toolkit normalize links.txt
vless-toolkit dedupe links.txt
vless-toolkit summary subscription.txt --format table
```

`parse`, `convert` and the other multi-link commands accept literal links, paths
to UTF-8 text/subscription files, or `-` for standard input.

## Library usage

### Parse and build

```python
from vless_toolkit import VLESS, parse_link, serialize_link

node = parse_link(
    "vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example.com:443"
    "?security=tls&type=ws&path=%2Fws#Tokyo"
)
assert node.host == "edge.example.com"
assert node.params["type"] == "ws"
assert node.name == "Tokyo"

rebuilt = serialize_link(
    VLESS(
        uuid=node.uuid,
        host=node.host,
        port=node.port,
        params={"security": "tls", "type": "ws", "path": "/ws"},
        name="Tokyo",
    )
)
print(rebuilt)
```

`parse_link` dispatches on the scheme and returns a frozen `VLESS`, `VMess`,
`Trojan` or `Shadowsocks` record. Invalid input raises `LinkParseError` or
`LinkValidationError`; both inherit from `LinkError`.

### Subscriptions

```python
from vless_toolkit import (
    decode_subscription,
    encode_subscription,
    parse_subscription,
    records_to_json,
)

links = ["vless://...", "trojan://..."]
payload = encode_subscription(links, urlsafe=True, padding=False)
assert decode_subscription(payload) == links

records = parse_subscription(payload)
print(records_to_json(records, indent=2))
```

`decode_subscription` returns validated link strings; `parse_subscription`
returns protocol objects. Both accept plain text and padded or unpadded base64.

### Normalize, deduplicate and summarize

```python
from vless_toolkit import (
    dedupe_records,
    infer_country,
    normalize_record,
    parse_link,
    record_fingerprint,
    summarize_records,
)

records = [parse_link("vless://..."), parse_link("trojan://...")]
print(infer_country("🇯🇵 Tokyo"))                    # "JP"
print(record_fingerprint(records[0]))                # stable SHA-256 hex
print(normalize_record(records[0]))                  # canonical link
print(len(dedupe_records(records)))                  # names ignored by default

stats = summarize_records(records)
print(stats.total, stats.by_protocol, stats.by_country)
```

### Redaction

```python
from vless_toolkit import redact_link, redact_text

safe_link = redact_link("trojan://example-password@edge.example.com:443")
safe_log = redact_text(f"connecting with {safe_link}")
```

Credentials become a valid placeholder UUID or `[REDACTED]`, so redacted links
still parse during diagnostics but cannot authenticate. Use
`redact_record(..., keep_host=False)` to hide the server address too. See
[docs/security.md](docs/security.md) for what redaction does and does not cover.

## Supported formats

| Protocol | Link form | Notes |
| --- | --- | --- |
| VLESS | `vless://<uuid>@<host>:<port>?<query>#<name>` | Query parameters preserved byte-for-byte. Only `encryption=none` is accepted. |
| VMess | `vmess://<base64-json>` | Standard or URL-safe base64; unknown JSON fields are preserved in `VMess.extra`. |
| Trojan | `trojan://<password>@<host>:<port>?<query>#<name>` | Percent-encoded or raw-colon passwords; duplicate query keys rejected. |
| Shadowsocks | `ss://<base64(method:password)>@<host>:<port>?plugin=...#<name>` | SIP002, plain user-info and legacy all-in-one base64 links. |

IPv6 hosts, Unicode display names and non-ASCII passwords are supported.
Duplicate query parameters are rejected rather than silently collapsed.

## CLI reference

| Command | Purpose |
| --- | --- |
| `parse` | Show fields as text, a table, JSON or YAML; `--redact`, `--hide-hosts`. |
| `build` | Create a link from `--protocol`, `--host`, `--port` and credentials. |
| `convert` | Emit links, JSON, YAML or a base64 subscription. |
| `validate` | Parse each link and report failures; exits `1` if any fail. |
| `dedupe` | Remove semantic duplicates; `--keep-names` keeps names significant. |
| `normalize` | Print canonical link forms. |
| `summary` | Count by protocol, country and country/protocol (`--format table`). |
| `qr` | Print an ASCII QR code for exactly one link (`--border 0..16`). |

Global color options are `--color` (force ANSI) and `--no-color`; `NO_COLOR` is
honored when neither is passed. Tables are plain ASCII and omit UUIDs and
passwords, which makes them safe for issue reports.

Exit codes: `0` success, `1` validation failures, `2` usage or parsing errors.

More examples are in [docs/usage.md](docs/usage.md).

## Security

Share links are credentials. Avoid pasting live links into shell history,
issues, CI logs or screenshots; use redaction before sharing diagnostics. This
project performs no network requests, but it cannot protect a secret that was
already copied somewhere unsafe. Read [SECURITY.md](SECURITY.md) and
[docs/security.md](docs/security.md) before reporting a problem.

## Development

- Python 3.9–3.13, no third-party runtime dependencies.
- `pytest` suite plus `ruff` (E, F, I, B, UP, SIM, C4, DTZ, RUF).
- CI runs the suite on Ubuntu, Windows and macOS.

```bash
python -m pytest -q
python -m ruff check .
python -m pytest --cov=vless_toolkit --cov-report=term-missing
pre-commit install
pre-commit run --all-files
```

Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md). Never include real
credentials in tests, issues or pull requests.

## Limitations

- Country grouping uses display names only; records without a recognizable tag
  are reported as `Unknown`.
- QR output supports byte-mode versions 1–10 with error correction L, so very
  long links are rejected instead of producing an unreadable code.
- The library validates syntax and field ranges, not whether a server is online
  or whether credentials are still valid.

## License

MIT © 2026 Largo-m. See [LICENSE](LICENSE).
