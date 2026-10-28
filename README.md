<div align="center">

# vless-toolkit

**Parse, validate, build, convert and redact proxy share links — offline, with zero dependencies.**

A single-file-friendly Python library and a complete command-line tool for
**VLESS**, **VMess**, **Trojan** and **Shadowsocks** links and base64
subscription payloads.

[![CI](https://github.com/Largo-m/vless-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Largo-m/vless-toolkit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Largo-m/vless-toolkit?sort=semver&color=2f81f7)](https://github.com/Largo-m/vless-toolkit/releases)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB.svg)](pyproject.toml)
[![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-2f81f7.svg)](#requirements)
[![License: MIT](https://img.shields.io/badge/license-MIT-2f81f7.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://github.com/astral-sh/ruff)

[Install](#install) ·
[CLI quick start](#cli-quick-start) ·
[Library quick start](#library-quick-start) ·
[Usage guide](docs/usage.md) ·
[Formats](docs/FORMATS.md) ·
[CLI reference](docs/CLI.md) ·
[API reference](docs/API.md) ·
[Security notes](docs/security.md)

</div>

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
- [CLI quick start](#cli-quick-start)
- [Library quick start](#library-quick-start)
- [Format support](#format-support)
- [Redaction: never leak a link](#redaction-never-leak-a-link)
- [Subscriptions](#subscriptions)
- [Normalization and duplicate removal](#normalization-and-duplicate-removal)
- [Export without dependencies](#export-without-dependencies)
- [Design principles](#design-principles)
- [Project layout](#project-layout)
- [Development](#development)
- [FAQ](#faq)
- [Related projects](#related-projects)
- [License](#license)

---

## Why this exists

A proxy share link **is a credential**. It contains your UUID or password, the
server address, and often the Reality public key and short id. Most tooling that
touches those links either sends them to a web service, pulls in a heavy
dependency tree, or silently rewrites parameters it does not understand.

`vless-toolkit` is the opposite:

- **Offline by design.** No network code exists in the package. Nothing leaves the
  machine, not even DNS lookups.
- **Zero runtime dependencies.** Standard library only — it installs in
  milliseconds and runs on a locked-down host.
- **Validating constructors.** A `VLESS`/`VMess`/`Trojan`/`Shadowsocks` object
  cannot exist in an invalid state: ports, UUIDs, ciphers, hosts and params are
  checked on construction and on parse.
- **Round-trip fidelity.** Serializing a parsed link reproduces a semantically
  identical link, and unknown VMess JSON fields are preserved in `extra` instead
  of being dropped.
- **Safe by default in logs.** Built-in redaction for links, records and free
  text, so diagnostics can never leak credentials.
- **Semantic de-duplication.** Two subscriptions that differ only in parameter
  order, casing or display name are correctly recognised as the same server.

It is the parsing engine behind [ExploitFA](#related-projects), a Windows desktop
client, and it is useful on its own for migration scripts, subscription audits
and CI checks.

---

## Features

- [x] Parse and build `vless://`, `vmess://`, `trojan://` and `ss://` links
- [x] SIP002 and legacy base64 Shadowsocks formats
- [x] VMess base64 JSON (schema v2) with duplicate-key rejection
- [x] Unify all four protocols behind `parse_link()` / `serialize_link()`
- [x] Decode and encode base64 subscriptions (standard and URL-safe, padded or not)
- [x] Validate links with per-link, human-readable failure messages
- [x] Canonicalize links (`normalize_link`, `normalize_record`)
- [x] Semantic de-duplication (`dedupe_links`, `dedupe_records`, `record_fingerprint`)
- [x] Redact secrets in records, links and arbitrary text
- [x] Export to JSON or dependency-free YAML
- [x] Pure-Python ASCII QR codes for any link (no `qrcode`/`Pillow`)
- [x] Summarise a subscription: totals, unique hosts, protocol counts, grouping by country and by country/protocol
- [x] Country inference from flag emoji, country names and explicit tags (`infer_country`)
- [x] Unicode-aware ASCII tables with optional colour, `--color`/`--no-color` and `NO_COLOR` support
- [x] Sort a subscription by country, name, host or protocol without rewriting the links
- [x] 214 tests, Ruff-enforced, CI on Linux, Windows and macOS
- [x] `py.typed`, fully type-annotated public API
- [x] No network access, no telemetry, no third-party runtime imports

---

## Requirements

- **Python 3.9+** (3.9 through 3.13 tested)
- No runtime dependencies
- Any OS: Windows, Linux, macOS

---

## Install

```bash
pip install vless-toolkit
```

From source:

```bash
git clone https://github.com/Largo-m/vless-toolkit.git
cd vless-toolkit
python -m pip install -e ".[dev]"
```

Verify:

```bash
vless-toolkit --version
# vless-toolkit 1.0.0
```

The package installs two entry points: the `vless-toolkit` console script and
`python -m vless_toolkit`.

---

## CLI quick start

### Inspect a link

```bash
$ vless-toolkit parse 'vless://11111111-1111-4111-8111-111111111111@de.example.com:443?security=reality&sni=www.example.com&fp=chrome&pb=PUBLICKEY&sid=0123456789abcdef&type=tcp&flow=xtls-rprx-vision#Frankfurt'
protocol: vless
name: Frankfurt
host: de.example.com
port: 443
uuid: 11111111-1111-4111-8111-111111111111
params:
  security: reality
  sni: www.example.com
  fp: chrome
  pb: PUBLICKEY
  sid: 0123456789abcdef
  type: tcp
  flow: xtls-rprx-vision
```

### Inspect it safely

`--redact` masks the UUID (or password) and `--hide-hosts` hides the server:

```bash
$ vless-toolkit parse --redact --hide-hosts 'trojan://secret-password@nl.example.com:443?security=tls&sni=nl.example.com#Amsterdam'
protocol: trojan
name: Amsterdam
host: redacted.invalid
port: 443
password: [REDACTED]
params:
  security: tls
  sni: nl.example.com
```

### Build a link from fields

```bash
$ vless-toolkit build --protocol vless --host de.example.com --port 443 \
    --uuid 11111111-1111-4111-8111-111111111111 --name Frankfurt \
    --set security=reality --set type=tcp
vless://11111111-1111-4111-8111-111111111111@de.example.com:443?security=reality&type=tcp#Frankfurt
```

### Validate a list, with a non-zero exit code for CI

```bash
$ vless-toolkit validate links.txt
ok #1: vless Frankfurt
ok #2: trojan Amsterdam
ok #3: shadowsocks Tokyo
invalid #4: VMess JSON contains duplicate key 'v'
invalid #5: VLESS link is missing the user UUID
2 of 5 link(s) invalid
```

### Summarise a subscription

```bash
$ vless-toolkit summary links.txt
total: 4
unique hosts: 4
by protocol:
  shadowsocks: 1
  trojan: 1
  vless: 1
  vmess: 1
by country:
  DE: 1
  NL: 1
  JP: 1
  SG: 1
by country/protocol:
  DE/vless: 1
  JP/shadowsocks: 1
  NL/trojan: 1
  SG/vmess: 1
```

Or as a table, with colour in a terminal and plain pipes in CI:

```bash
$ vless-toolkit summary --format table links.txt
total: 4  unique hosts: 4

Protocol    | Count
------------+------
shadowsocks |     1
trojan      |     1
vless       |     1
vmess       |     1

Country | Count
--------+------
DE      |     1
JP      |     1
NL      |     1
SG      |     1
```

`parse --format table` gives a one-line-per-link overview with country,
transport and security; `--redact` keeps credentials out of it:

```bash
$ vless-toolkit parse --format table --redact links.txt
# | Protocol | Country | Name      | Host           | Port | Transport | Security
--+----------+---------+-----------+----------------+------+-----------+---------
1 | vless    | DE      | Frankfurt | de.example.com |  443 | tcp       | reality
```

### Canonicalize and de-duplicate

```bash
$ vless-toolkit normalize 'VLESS://11111111-1111-4111-8111-111111111111@DE.Example.com:443?security=REALITY&type=TCP#Frankfurt'
vless://11111111-1111-4111-8111-111111111111@de.example.com:443?security=reality&type=tcp#Frankfurt

$ vless-toolkit dedupe links.txt
removed 1 duplicate(s); 1 unique
vless://11111111-1111-4111-8111-111111111111@de.example.com:443?flow=xtls-rprx-vision&fp=chrome&pb=PUBLICKEY&security=reality&sid=0123456789abcdef&sni=www.example.com&type=tcp#Frankfurt
```

### Sort a subscription

`sort` reorders links and prints them **unchanged** — the original text, not a
normalised form, so signatures and client-specific parameters survive.

```bash
$ vless-toolkit sort --by country links.txt
vless://11111111-1111-4111-8111-111111111111@de.example.com:443?security=tls#Germany%20Frankfurt
trojan://secret-password@jp.example.com:443?security=tls#Japan%20Tokyo
vless://11111111-1111-4111-8111-111111111111@nl.example.com:443?security=tls#Netherlands%20Amsterdam

$ vless-toolkit sort --by name --reverse links.txt
```

Sort fields: `country` (default), `name`, `host`, `protocol`. Links whose country
cannot be inferred go last instead of cluttering the top of the list, and the
sort is stable, so equally ranked links keep their original order.

### Convert to JSON, YAML or a base64 subscription

```bash
$ vless-toolkit convert --format yaml 'trojan://secret-password@nl.example.com:443?security=tls&sni=nl.example.com#Amsterdam'
- protocol: trojan
  name: Amsterdam
  host: nl.example.com
  port: 443
  password: secret-password
  params:
    security: tls
    sni: nl.example.com

$ vless-toolkit convert --subscription --urlsafe --no-padding links.txt > subscription.txt
```

### Print an ASCII QR code

```bash
$ vless-toolkit qr 'vless://11111111-1111-4111-8111-111111111111@de.example.com:443?security=tls#DE'
    ##############    ##          ####    ######  ##    ##      ##############
    ##          ##  ####  ####        ####  ####    ##    ####  ##          ##
    ...
```

Global flags `--color` / `--no-color` control ANSI output (`NO_COLOR` is honoured), and
every command accepts a link, a file path, or `-` for stdin, and can be chained:

```bash
cat subscription.b64 | vless-toolkit convert --format json - | jq '.[].host'
```

Full command reference: [docs/CLI.md](docs/CLI.md).

---

## Library quick start

```python
from vless_toolkit import (
    LinkParseError,
    dedupe_links,
    parse_link,
    redact_link,
    serialize_link,
)

link = (
    "vless://11111111-1111-4111-8111-111111111111@de.example.com:443"
    "?security=reality&sni=www.example.com&fp=chrome#Frankfurt"
)

record = parse_link(link)          # VLESS / VMess / Trojan / Shadowsocks
print(record.host, record.port)    # de.example.com 443
print(record.params["security"])   # reality

# Round trip: build a canonical link back from the record
print(serialize_link(record))

# Log it safely
print(redact_link(link))

try:
    parse_link("vless://nope")
except LinkParseError as error:
    print("invalid:", error)
```

Subscriptions and exports:

```python
from vless_toolkit import (
    decode_subscription,
    encode_subscription,
    parse_subscription,
    records_to_yaml,
)

payload = encode_subscription([link])       # base64 of newline-joined links
links = decode_subscription(payload)         # ["vless://..."]
records = parse_subscription(payload)       # [VLESS(...)]
print(records_to_yaml(records))
```

De-duplication ignores display names by default and compares canonical fields:

```python
from vless_toolkit import dedupe_links

unique = dedupe_links([link, link.replace("#Frankfurt", "#Frankfurt copy")])
assert len(unique) == 1
```

Full API reference: [docs/API.md](docs/API.md).

---

## Format support

| Protocol | Parse | Build | Canonical form | Notes |
| --- | --- | --- | --- | --- |
| VLESS | ✅ | ✅ | `vless://uuid@host:port?params#name` | UUID validated, params normalized, IPv6 supported |
| VMess | ✅ | ✅ | base64 JSON (schema `v2`) | duplicate keys rejected, unknown fields preserved in `extra` |
| Trojan | ✅ | ✅ | `trojan://password@host:port?params#name` | password required, params validated |
| Shadowsocks | ✅ | ✅ | `ss://base64(method:password)@host:port#name` | SIP002 and legacy formats |

| Feature | Supported |
| --- | --- |
| Base64 subscriptions (standard / URL-safe, padded / unpadded) | ✅ |
| JSON and YAML export (no PyYAML) | ✅ |
| Redaction of records, links and free text | ✅ |
| Semantic normalization and fingerprinting | ✅ |
| ASCII QR rendering | ✅ |
| Network access of any kind | ❌ none |

Detailed field-by-field rules per protocol: [docs/FORMATS.md](docs/FORMATS.md).

---

## Redaction: never leak a link

Share links end up in bug reports, CI logs and screenshots. The redaction module
is designed for exactly that boundary:

```python
from vless_toolkit import redact_link, redact_records, redact_secret, redact_text

redact_link("vless://11111111-...@de.example.com:443?security=reality#DE")
# 'vless://00000000-0000-0000-0000-000000000000@de.example.com:443?security=reality#DE'

redact_link(link, keep_host=False)
# host becomes 'redacted.invalid'

redact_secret("super-secret-password", show_last=2)
# '*******************rd'  (short secrets are fully masked)

redact_text("failed to connect to vless://1111...@host:443")
# 'failed to connect to vless://00000000-...@host:443'
```

What is masked:

| Value | Behaviour |
| --- | --- |
| VLESS / VMess UUID | replaced with `00000000-0000-0000-0000-000000000000` |
| Trojan / Shadowsocks password | replaced with `[REDACTED]` |
| Params named `password`, `passwd`, `secret`, `token`, `key`, `api_key`, `apikey`, `auth` | masked |
| Server host | kept unless `keep_host=False` (then `redacted.invalid`) |
| Any `vless://`/`vmess://`/`trojan://`/`ss://` URL inside text | re-redacted in place |

`vless-toolkit`'s own CLI uses the same helpers for every `--redact` call, so the
library and the tool cannot disagree.

---

## Subscriptions

A subscription is a base64 blob containing one link per line. All four base64
dialects used in the wild are accepted:

```python
from vless_toolkit import decode_subscription, encode_subscription

links = decode_subscription(payload)          # tolerant of padding/urlsafe
payload = encode_subscription(links)          # standard base64, padded
payload = encode_subscription(links, urlsafe=True, padding=False)
```

Malformed payloads raise `LinkParseError` with the reason, never a silent empty
list.

---

## Normalization and duplicate removal

Two links can describe the same server while differing in casing, parameter
order or display name. `normalize_record()` produces a canonical form:

- host lower-cased, IPv6 normalized without brackets in the record
- query parameters sorted and their keys lower-cased where the protocol defines
  them (`security`, `type`, `encryption`)
- display name preserved unless `keep_name=False`

`record_fingerprint()` hashes only the connection-relevant fields, and
`dedupe_records()` / `dedupe_links()` keep the first occurrence:

```python
from vless_toolkit import dedupe_records, record_fingerprint

dedupe_records(records)                          # names ignored
dedupe_records(records, include_names=True)      # names are part of identity
record_fingerprint(record)                       # stable hash for caching
```

This is what makes `vless-toolkit dedupe` safe to run on exported subscription
lists before importing them into a client.

---

## Export without dependencies

`records_to_json()` and `records_to_yaml()` emit human-readable documents without
requiring PyYAML. The YAML writer quotes only when necessary (reserved words,
leading special characters, ambiguous scalars), so the output stays diff-friendly.

```python
from vless_toolkit import parse_subscription, records_to_json, records_to_yaml

records = parse_subscription(payload)
print(records_to_json(records, indent=2))
print(records_to_yaml(records))
```

---

## Design principles

1. **No I/O in the core.** Parsing, building, normalizing and redacting are pure
   functions. The CLI is the only module that reads files or stdin.
2. **Validate early, fail loudly.** Models validate in `__post_init__`; every
   failure raises a `LinkParseError`/`LinkValidationError` with a specific
   message.
3. **Preserve what you do not understand.** VMess extension keys survive a round
   trip in `extra`; unknown query parameters are retained.
4. **One public surface.** Everything importable from `vless_toolkit` is listed in
   `__all__` and covered by tests.
5. **Typed.** The package ships `py.typed` and annotates public functions.

---

## Guides

| Guide | Contents |
| --- | --- |
| [Usage](docs/usage.md) | inputs, inspection, conversion, validation, CI pipelines and daily workflows |
| [Formats](docs/FORMATS.md) | field-by-field rules, base64 dialects, country inference, round-trip guarantees |
| [CLI reference](docs/CLI.md) | every command, option, exit code and recipe |
| [API reference](docs/API.md) | every public function, statistics helpers, typical workflows |
| [Security notes](docs/security.md) | threat model, what the toolkit does and does not protect |

## Project layout

```text
vless_toolkit/
├── __init__.py        public API surface
├── errors.py          LinkError / LinkParseError / LinkValidationError
├── vless.py           VLESS model, parser, serializer
├── vmess.py           VMess base64-JSON model, parser, serializer
├── trojan.py          Trojan model, parser, serializer
├── shadowsocks.py     SIP002 + legacy models, parser, serializer
├── parser.py          unified parse_link / serialize_link
├── subscription.py    base64 subscription codecs
├── normalize.py       canonicalization, fingerprints, dedupe
├── redact.py          credential redaction helpers
├── export.py          JSON and dependency-free YAML writers
├── stats.py           country inference and summary statistics
├── table.py           Unicode-aware table rendering and colour detection
├── qr.py              pure-Python QR encoder + ASCII renderer
└── cli.py             argparse command suite

tests/                 208 tests across parsing, building, redaction, exports, QR
docs/                  CLI reference, format rules, API reference
```

---

## Development

```bash
git clone https://github.com/Largo-m/vless-toolkit.git
cd vless-toolkit
python -m pip install -e ".[dev]"

python -m ruff check .
python -m pytest -q
python -m pytest -q --cov=vless_toolkit --cov-report=term-missing
pre-commit install
pre-commit run --all-files
```

CI runs the suite on Ubuntu, Windows and macOS for Python 3.9 through 3.13,
with a 90% coverage gate and linting on every push and pull request.

Pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## FAQ

**Does it send my links anywhere?**
No. There is no networking code in the package, and the test suite runs without
network access.

**Can it change a link, or only read it?**
It can build, rebuild and canonicalize links. Serialization is deterministic, so
the same record always produces the same link.

**Does it support Reality?**
Yes. Reality lives in the VLESS query parameters (`security=reality`, `sni`,
`fp`, `pb`, `sid`, `flow`), all preserved verbatim and reported by `parse`.

**Does it support hysteria2 / tuic?**
No. Those are QUIC-based and do not use the share-link model implemented here.
See the closed tracking issue for details.

**Is it a client or does it connect to a server?**
No — it is a parsing and conversion library. For an actual Windows client, see
[ExploitFA](#related-projects).

**Why zero dependencies?**
So the package can be vendored into a single script, audited quickly, and used in
restricted environments. YAML and QR output are implemented in-tree for that
reason.

**Why Python 3.9 as the floor?**
It covers the widest range of systems that still receive security updates while
allowing modern typing.

---

## Related projects

- **[ExploitFA](https://github.com/Largo-m/ExploitFA)** — an English-first
  PySide6 desktop client for Xray VLESS on Windows that uses this toolkit for
  share-link import.

---

## License

MIT © 2026 Largo-m. See [LICENSE](LICENSE).

<div align="center">

**If this toolkit saves you time, a star helps other people find it.**

</div>
