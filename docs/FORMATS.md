# Share-link format reference

This page documents exactly what `vless-toolkit` accepts and emits for each
protocol, and which validation rules apply.

Common rules:

- Hosts may be DNS names, IPv4 or IPv6. IPv6 addresses are accepted with or
  without brackets in a share link and stored **without** brackets in the model.
- Ports must be integers in `1..65535`.
- Unknown query parameters are preserved in `params` (VLESS/Trojan/Shadowsocks)
  or in `extra` (VMess), so a round trip never drops data.
- Parsing never performs DNS resolution or any other network access.

---

## VLESS

```text
vless://<uuid>@<host>:<port>?<query>#<name>
```

| Part | Rule |
| --- | --- |
| `uuid` | required, canonical UUID (hyphenated), case-insensitive input, lower-cased in the model |
| `host` | required, non-empty |
| `port` | required, `1..65535` |
| `query` | optional; parsed into `params` |
| `#name` | optional display name, URL-decoded |

Common query parameters (all optional, all preserved verbatim):

| Key | Meaning |
| --- | --- |
| `type` | transport: `tcp`, `ws`, `grpc`, `http`, `quic`, ... |
| `security` | `none`, `tls`, `reality` |
| `encryption` | usually `none` |
| `sni` | TLS server name |
| `fp` | uTLS fingerprint preset, e.g. `chrome` |
| `pb` | Reality public key |
| `sid` | Reality short id |
| `flow` | e.g. `xtls-rprx-vision` |
| `path` / `host` / `serviceName` | transport-specific settings |

```python
from vless_toolkit import VLESS, parse_vless, serialize_vless

record = parse_vless(
    "vless://11111111-1111-4111-8111-111111111111@de.example.com:443"
    "?security=reality&sni=www.example.com&fp=chrome&pb=KEY&sid=abcd&type=tcp#Frankfurt"
)
assert record.uuid == "11111111-1111-4111-8111-111111111111"
assert record.params["security"] == "reality"

copy = VLESS(uuid=record.uuid, host=record.host, port=record.port, name="Copy")
print(serialize_vless(copy))
```

Errors: `VLESS link is missing the user UUID`, `VLESS link has an invalid UUID`,
`Port must be an integer between 1 and 65535`, `VLESS link is missing the host`.

---

## VMess

VMess links are base64-encoded JSON, schema version 2:

```text
vmess://base64(<json object>)
```

| JSON key | Model field | Notes |
| --- | --- | --- |
| `v` | `version` | always `"2"` |
| `ps` | `name` | display name |
| `add` | `host` | server address |
| `port` | `port` | string or number, `1..65535` |
| `id` | `uuid` | user UUID |
| `aid` | `alter_id` | legacy alterId, default `0` |
| `scy` | `security` | cipher, default `auto` |
| `net` | `network` | transport, default `tcp` |
| `type` | `header_type` | obfuscation, default `none` |
| `host` | `host_header` | HTTP host header |
| `path` | `path` | HTTP/WebSocket path |
| `tls` | `tls` | empty or `tls` |
| `sni` | `sni` | TLS server name |
| `alpn` | `alpn` | comma-separated list |
| `fp` | `fingerprint` | TLS fingerprint preset |

Anything else is kept in `extra` and re-emitted on serialization.

**Duplicate keys are rejected.** `{"v": "2", "v": "2"}` raises
`VMess JSON contains duplicate key 'v'` — ambiguous input is never silently
resolved.

```python
from vless_toolkit import parse_vmess, serialize_vmess

record = parse_vmess("vmess://eyJ2IjoiMiIsInBzIjoiU2luZ2Fwb3JlIiw...")
print(record.host, record.port, record.network)
print(serialize_vmess(record))
```

Errors: `VMess link is not valid base64`, `VMess JSON is not an object`,
`VMess JSON contains duplicate key 'x'`, `VMess link is missing the server
address`, `VMess link is missing the user UUID`.

---

## Trojan

```text
trojan://<password>@<host>:<port>?<query>#<name>
```

| Part | Rule |
| --- | --- |
| `password` | required, non-empty, URL-decoded |
| `host`, `port` | as for VLESS |
| `query` | preserved in `params` (`security`, `sni`, `type`, `path`, ...) |

```python
from vless_toolkit import Trojan, parse_trojan, serialize_trojan

record = parse_trojan("trojan://secret-password@nl.example.com:443?security=tls&sni=nl.example.com#Amsterdam")
print(record.password == "secret-password")   # True
print(serialize_trojan(record))
```

Errors: `Trojan link is missing the password`, `Trojan link is missing the host`,
`Port must be an integer between 1 and 65535`.

---

## Shadowsocks

Two formats are supported.

### SIP002 (current)

```text
ss://base64(<method>:<password>)@<host>:<port>?plugin=...#<name>
```

### Legacy (whole authority base64-encoded)

```text
ss://base64(<method>:<password>@<host>:<port>)#<name>
```

| Part | Rule |
| --- | --- |
| `method` | required, e.g. `aes-256-gcm`, `chacha20-ietf-poly1305` |
| `password` | required |
| `host`, `port` | as for VLESS |
| `plugin` / other query keys | preserved in `params` |

Base64 input is accepted with standard or URL-safe alphabets, padded or not.

```python
from vless_toolkit import Shadowsocks, parse_shadowsocks, serialize_shadowsocks

record = parse_shadowsocks("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@jp.example.com:8388#Tokyo")
print(record.method, record.password, record.port)

print(serialize_shadowsocks(Shadowsocks(method="aes-256-gcm", password="secret", host="jp.example.com", port=8388)))
```

Errors: `Shadowsocks link is not valid base64`, `Shadowsocks link is missing the
cipher`, `Shadowsocks link is missing the password`, `Shadowsocks link is missing
the host`.

---

## Unified dispatch

`parse_link()` selects the parser from the scheme and raises
`LinkParseError` for unsupported schemes:

```python
from vless_toolkit import SUPPORTED_SCHEMES, parse_link

SUPPORTED_SCHEMES            # ("vless", "vmess", "trojan", "ss")

record = parse_link("trojan://password@example.com:443#Name")
record = parse_link(record)  # already parsed records pass through
```

`serialize_link()` is the inverse:

```python
from vless_toolkit import parse_link, serialize_link

link = serialize_link(parse_link("vless://11111111-1111-4111-8111-111111111111@example.com:443#Name"))
```

---

## Base64 subscription payloads

A subscription is base64 text whose decoded content is one link per line:

```text
dmxlc3M6Ly8xMTEx...Cg==
```

Behaviour:

- newlines (`\n` and `\r\n`), surrounding whitespace and blank lines are tolerated
- standard and URL-safe alphabets are both accepted, padding optional
- a payload that decodes to something without a single known scheme raises
  `LinkParseError`

```python
from vless_toolkit import decode_subscription, encode_subscription

links = decode_subscription(payload)
payload = encode_subscription(links, urlsafe=True, padding=False)
```

---

## Country inference

Summary statistics group links by country. The code is inferred, in order, from:

1. the display name (flag emoji or a country name such as `Germany`);
2. the `country` query parameter, when present;
3. otherwise `Unknown`.

`infer_country()` is intentionally conservative: it only returns a two-letter ISO
code when it recognises a flag or a known country name, and never guesses from a
hostname.

## Round-trip guarantees

| Input | Guarantee |
| --- | --- |
| Valid VLESS/Trojan/Shadowsocks link | `parse_link()` → `serialize_link()` preserves protocol, host, port, credentials and every query parameter |
| Valid VMess link | same, plus unknown JSON keys survive in `extra` |
| Canonical output | parameter order is deterministic, so repeated runs are byte-identical |
| Malformed link | raises a specific `LinkParseError`, never returns a partially filled object |
