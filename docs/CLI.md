# CLI reference

```bash
vless-toolkit --help
vless-toolkit <command> --help
```

Every command accepts one or more **sources**: a raw link, a path to a file, or
`-` for stdin. Files may contain one link per line; base64 subscription payloads
are detected automatically.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | success |
| `1` | invalid input, unreadable source, or validation failure |

Errors are printed to stderr as a single `error: ...` line.

---

## Global options

| Option | Description |
| --- | --- |
| `-h`, `--help` | show help |
| `--version` | print the package version |
| `--no-color` | disable ANSI colours |
| `--color` | force ANSI colours even when stdout is not a TTY |

Colour is enabled automatically only for a TTY; `NO_COLOR` disables it as well.
Table output stays aligned in plain pipes.

---

## `parse`

Show every parsed field for each link.

```bash
vless-toolkit parse SOURCE...
```

| Option | Description |
| --- | --- |
| `--format {text,table,json,yaml}` | output format (default `text`) |
| `--redact` | mask credentials |
| `--hide-hosts` | also replace hosts (implies `--redact`) |

```text
protocol: vless
name: Frankfurt
host: de.example.com
port: 443
uuid: 11111111-1111-4111-8111-111111111111
params:
  security: reality
  sni: www.example.com
  type: tcp
```

Protocol-specific fields appear at the top level: `uuid` (VLESS/VMess),
`password` (Trojan/Shadowsocks), `method` (Shadowsocks), and the VMess transport
fields (`alter_id`, `network`, `tls`, `path`, ...).

`--format table` renders a compact overview instead:

```text
# | Protocol | Country | Name              | Host           | Port | Transport | Security
--+----------+---------+-------------------+----------------+------+-----------+---------
1 | vless    | DE      | Germany Frankfurt | de.example.com |  443 | tcp       | tls
```

```bash
vless-toolkit parse --format table --redact links.txt
```

---

## `build`

Create a share link from explicit fields.

```bash
vless-toolkit build --protocol vless --host HOST --port PORT [options]
```

| Option | Description |
| --- | --- |
| `--protocol {vless,vmess,trojan,ss}` | required |
| `--host HOST` | required |
| `--port PORT` | required, 1–65535 |
| `--uuid UUID` | VLESS/VMess user id |
| `--password PASSWORD` | Trojan/Shadowsocks password |
| `--method METHOD` | Shadowsocks cipher (e.g. `aes-256-gcm`) |
| `--name NAME` | display name |
| `--set KEY=VALUE` | extra query/JSON field, repeatable |

Protocol-specific `--set` names:

| Protocol | Accepted keys |
| --- | --- |
| VLESS | any query key, e.g. `security=reality`, `sni=...`, `fp=chrome`, `pb=...`, `sid=...`, `type=tcp`, `flow=xtls-rprx-vision` |
| VMess | `security`, `network`, `path`, `host`, `sni`, `tls`, `alpn`, `fp`, `alter-id` |
| Trojan | any query key, e.g. `security=tls`, `sni=...`, `type=grpc` |
| Shadowsocks | `plugin`, `mode`, and other query keys |

---

## `convert`

Convert, re-encode or re-export links.

```bash
vless-toolkit convert SOURCE...
```

| Option | Description |
| --- | --- |
| `--format {links,json,yaml}` | output format (default `links`) |
| `--subscription` | emit a base64 subscription instead of links |
| `--urlsafe` | URL-safe base64 alphabet for `--subscription` |
| `--no-padding` | drop `=` padding for `--subscription` |
| `--redact` / `--hide-hosts` | redact before writing |

Examples:

```bash
# canonical links
vless-toolkit convert links.txt

# JSON for a script
vless-toolkit convert --format json links.txt

# YAML for review
vless-toolkit convert --format yaml links.txt

# base64 subscription for a client
vless-toolkit convert --subscription links.txt > subscription.b64
```

---

## `validate`

Validate each link and report the ones that fail.

```bash
vless-toolkit validate SOURCE...
```

```text
ok #1: vless Frankfurt
ok #2: trojan Amsterdam
invalid #3: VLESS link is missing the user UUID
1 of 3 link(s) invalid
```

Exit code `1` when at least one link is invalid — suitable for CI.

---

## `dedupe`

Remove semantic duplicates, keeping the first occurrence.

```bash
vless-toolkit dedupe SOURCE...
```

| Option | Description |
| --- | --- |
| `--keep-names` | treat differently named links as distinct |

Comparison ignores parameter order, casing of known keys, and display names by
default.

---

## `normalize`

Print the canonical form of every link.

```bash
vless-toolkit normalize SOURCE...
```

Canonicalization lower-cases the host and known parameter keys, sorts query
parameters and keeps the display name. The output is deterministic, so it is safe
to use in diffs.

---

## `sort`

Order links without rewriting them.

```bash
vless-toolkit sort [--by {country,name,host,protocol}] [--reverse] SOURCE...
```

| Option | Description |
| --- | --- |
| `--by` | sort field: `country` (default), `name`, `host`, `protocol` |
| `--reverse` | reverse the resulting order |

`sort` prints the **original link text**, so client-specific parameters and
signatures are preserved; it is a reordering tool, not a normaliser. Sorting is
stable, links whose country cannot be inferred are placed last, and `--by
protocol` groups links by protocol first, then by country.

```bash
vless-toolkit sort --by country links.txt > sorted.txt
vless-toolkit sort --by name --reverse links.txt
```

---

## `summary`

Count links, hosts and protocols.

```bash
vless-toolkit summary [--format {text,table}] SOURCE...
```

| Option | Description |
| --- | --- |
| `--format {text,table}` | output format (default `text`) |

```text
total: 4
unique hosts: 4
by protocol:
  shadowsocks: 1
  trojan: 1
  vless: 1
  vmess: 1
by country:
  DE: 1
  JP: 1
  NL: 1
  SG: 1
by country/protocol:
  DE/vless: 1
  JP/shadowsocks: 1
  NL/trojan: 1
  SG/vmess: 1
```

`--format table` prints the same counters as aligned tables (see
`render_table` in the API reference).

---

## `qr`

Render a link as an ASCII QR code in the terminal.

```bash
vless-toolkit qr SOURCE [--border N]
```

| Option | Description |
| --- | --- |
| `--border N` | quiet zone width in modules, 0–16 (default 4) |

The encoder is pure Python (no `qrcode`, no `Pillow`), uses Reed–Solomon error
correction level L and caps out at QR version 10 (about 213 bytes), which is
enough for typical share links. Longer links fail with a clear error instead of
producing an unscannable code.

---

## Recipes

### Sanitise a list before sharing it

```bash
vless-toolkit convert --redact --hide-hosts --format yaml links.txt > sanitized.yaml
```

### Fail a pipeline on a broken link

```bash
vless-toolkit validate subscription.b64 || exit 1
```

### Migrate to a new client, de-duplicated and canonical

```bash
vless-toolkit dedupe old.txt | vless-toolkit normalize - > new.txt
```

### Inspect an encoded subscription from stdin

```bash
curl -s "$SUBSCRIPTION_URL" | vless-toolkit summary -
```

### Colour in a terminal, plain text in CI

```bash
vless-toolkit parse --format table --color links.txt   # force colour
vless-toolkit parse --format table --no-color links.txt
NO_COLOR=1 vless-toolkit parse --format table links.txt
```

### Scan a QR code from your phone into text

Print with `vless-toolkit qr`, scan with any reader, or feed the resulting link
back into `vless-toolkit parse`.
