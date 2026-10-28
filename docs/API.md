# API reference

Everything below is importable directly from the package root:

```python
import vless_toolkit as vt
```

The public surface is exactly `vless_toolkit.__all__`; semantic versioning applies
to it. The package ships `py.typed`, so type checkers and IDEs resolve annotations
without stubs.

---

## Errors

```python
from vless_toolkit import LinkError, LinkParseError, LinkValidationError
```

| Exception | Raised when |
| --- | --- |
| `LinkError` | base class; inherits `ValueError` |
| `LinkParseError` | the input is not a parseable link or payload |
| `LinkValidationError` | the input parses but a field is invalid (port, UUID, cipher, ...) |

Both carry a single human-readable message; nothing is swallowed.

---

## Models

All models are validating dataclasses: an invalid instance cannot be created, and
`__post_init__` normalizes values (UUID lower-casing, host trimming, port checks).

### `VLESS`

```python
VLESS(uuid: str, host: str, port: int, params: dict[str, str] = {}, name: str = "")
```

### `VMess`

```python
VMess(
    uuid: str,
    host: str,
    port: int,
    name: str = "",
    alter_id: int = 0,
    security: str = "auto",
    network: str = "tcp",
    header_type: str = "none",
    tls: str = "",
    sni: str = "",
    host_header: str = "",
    path: str = "",
    alpn: str = "",
    fingerprint: str = "",
    version: str = "2",
    extra: dict[str, Any] = {},
)
```

Unknown JSON keys are preserved in `extra`.

### `Trojan`

```python
Trojan(password: str, host: str, port: int, params: dict[str, str] = {}, name: str = "")
```

### `Shadowsocks`

```python
Shadowsocks(method: str, password: str, host: str, port: int, params: dict[str, str] = {}, name: str = "")
```

---

## Universal parsing

```python
from vless_toolkit import SUPPORTED_SCHEMES, parse_link, serialize_link
```

| Function | Signature | Description |
| --- | --- | --- |
| `parse_link` | `(link: str) -> Link` | dispatch on the scheme; accepts an already-parsed record and returns it unchanged |
| `serialize_link` | `(record: Link) -> str` | inverse of `parse_link` |

`Link` is the union `VLESS | VMess | Trojan | Shadowsocks`.

```python
record = parse_link("trojan://password@example.com:443?security=tls#Name")
text = serialize_link(record)
```

---

## Per-protocol codecs

| Protocol | Parse | Serialize | Model |
| --- | --- | --- | --- |
| VLESS | `parse_vless(link)` | `serialize_vless(record)` | `VLESS` |
| VMess | `parse_vmess(link)` | `serialize_vmess(record)` | `VMess` |
| Trojan | `parse_trojan(link)` | `serialize_trojan(record)` | `Trojan` |
| Shadowsocks | `parse_shadowsocks(link)` | `serialize_shadowsocks(record)` | `Shadowsocks` |

The per-protocol functions raise `LinkParseError` (unparseable) or
`LinkValidationError` (unusable values).

---

## Subscriptions

```python
from vless_toolkit import decode_subscription, encode_subscription, parse_subscription
```

| Function | Signature | Description |
| --- | --- | --- |
| `decode_subscription` | `(payload: str) -> list[str]` | decode base64 to a list of link strings |
| `parse_subscription` | `(payload: str) -> list[Link]` | decode and parse each link |
| `encode_subscription` | `(links: Iterable[str], *, urlsafe: bool = False, padding: bool = True) -> str` | build a base64 payload |

Empty lines are ignored; any undecodable input raises `LinkParseError`.

---

## Normalization

```python
from vless_toolkit import (
    dedupe_links,
    dedupe_records,
    normalize_link,
    normalize_record,
    record_fingerprint,
)
```

| Function | Signature | Description |
| --- | --- | --- |
| `normalize_record` | `(record: Link, *, keep_name: bool = True) -> Link` | canonical copy |
| `normalize_link` | `(link: str, *, keep_name: bool = True) -> str` | parse, canonicalize, serialize |
| `record_fingerprint` | `(record: Link, *, include_name: bool = False) -> str` | stable hash of connection-relevant fields |
| `dedupe_records` | `(records: Iterable[Link], *, include_names: bool = False) -> list[Link]` | keep first occurrence of each fingerprint |
| `dedupe_links` | `(links: Iterable[str], *, include_names: bool = False) -> list[Link]` | parse then `dedupe_records` |

Normalization lower-cases hosts and protocol-defined keys, sorts query parameters
and produces deterministic output:

```python
normalize_link("VLESS://11111111-1111-4111-8111-111111111111@DE.Example.com:443?type=TCP&security=REALITY#F")
# 'vless://11111111-1111-4111-8111-111111111111@de.example.com:443?security=reality&type=tcp#F'
```

---

## Redaction

```python
from vless_toolkit import (
    REDACTED,
    REDACTED_HOST,
    REDACTED_UUID,
    redact_link,
    redact_record,
    redact_records,
    redact_secret,
    redact_text,
)
```

| Function | Signature | Description |
| --- | --- | --- |
| `redact_secret` | `(value: str, *, show_last: int = 0) -> str` | mask a secret, optionally keeping a suffix; returns `[REDACTED]` when it is empty, fully masked, or shorter than the suffix |
| `redact_record` | `(record: Link, *, keep_host: bool = True) -> Link` | mask credentials in a model |
| `redact_link` | `(link: str, *, keep_host: bool = True) -> str` | parse, redact, serialize |
| `redact_records` | `(records: list[Link], *, keep_host: bool = True) -> list[Link]` | map over a list |
| `redact_text` | `(text: str, *, keep_host: bool = True) -> str` | redact every share link inside free text |

Constants: `REDACTED = "[REDACTED]"`, `REDACTED_UUID` (all-zero UUID),
`REDACTED_HOST = "redacted.invalid"`.

Sensitive parameter keys masked automatically: `password`, `passwd`, `secret`,
`token`, `key`, `api_key`, `apikey`, `auth`.

---

## Export

```python
from vless_toolkit import record_to_dict, records_to_json, records_to_yaml
```

| Function | Signature | Description |
| --- | --- | --- |
| `record_to_dict` | `(record: Link) -> dict[str, Any]` | JSON-ready mapping |
| `records_to_json` | `(records: Iterable[Link], *, indent: int = 2) -> str` | JSON document |
| `records_to_yaml` | `(records: Iterable[Link]) -> str` | dependency-free YAML |

The YAML writer quotes reserved words and ambiguous scalars, and keeps parameter
mappings in a readable block style.

---

## Statistics and tables

```python
from vless_toolkit import (
    country_for_record,
    infer_country,
    render_records_table,
    render_table,
    summarize_records,
)
```

| Function | Signature | Description |
| --- | --- | --- |
| `infer_country` | `(name: str) -> str` | best-effort ISO country code from a flag emoji, country name or tag |
| `country_for_record` | `(record: Link) -> str` | country code for a record (`Unknown` when it cannot be inferred) |
| `summarize_records` | `(records: Iterable[Link]) -> SummaryStats` | totals, unique hosts, counts by protocol, by country and by country/protocol |
| `render_table` | `(headers, rows, *, color: bool = False) -> str` | aligned Unicode-aware table |
| `render_records_table` | `(records: Iterable[Link], *, color: bool = False) -> str` | one-line-per-link overview |
| `display_width` | `(value: str) -> int` | terminal width of a string, accounting for wide characters |

Colour is decided by `color_enabled()`, which honours `NO_COLOR`, a TTY check and
explicit overrides. Rendering never emits credentials unless the caller asks for
them.

## QR codes

```python
from vless_toolkit import QRCode, encode_qr, link_to_ascii_qr, qr_to_ascii
```

| Function | Signature | Description |
| --- | --- | --- |
| `encode_qr` | `(text: str) -> QRCode` | pure-Python encoder, error-correction level L, versions 1–10 |
| `qr_to_ascii` | `(qr: QRCode, *, border: int = 4) -> str` | render with a quiet zone |
| `link_to_ascii_qr` | `(text: str, *, border: int = 4) -> str` | convenience wrapper |

`QRCode` exposes the module matrix; text longer than a version-10 symbol raises a
`LinkValidationError` rather than emitting a broken code.

---

## Version

```python
import vless_toolkit

vless_toolkit.__version__   # "1.0.0"
```

---

## Typical workflows

### Auditing a subscription before importing it

```python
from vless_toolkit import (
    dedupe_records,
    normalize_record,
    parse_subscription,
    redact_record,
    records_to_yaml,
)

records = dedupe_records(parse_subscription(payload))
canonical = [normalize_record(record) for record in records]
print(records_to_yaml([redact_record(record, keep_host=False) for record in canonical]))
```

### Migrating links between clients

```python
from vless_toolkit import encode_subscription, parse_link, serialize_link

links = [serialize_link(parse_link(line)) for line in source_lines]
open("subscription.b64", "w").write(encode_subscription(links, urlsafe=True, padding=False))
```

### Validating user input in a web handler

```python
from vless_toolkit import LinkError, parse_link

try:
    record = parse_link(request.form["link"])
except LinkError as error:
    return bad_request(str(error))
```
