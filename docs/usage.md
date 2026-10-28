# Usage guide

This page covers the CLI in more depth. All examples use fake credentials; never
put real subscription links in shell history or shared logs.

## Inputs

Commands that accept `sources` support any mix of:

- a literal share link;
- a path to a UTF-8 file containing one or more links;
- a base64 or plain-text subscription file;
- `-` to read standard input.

```bash
vless-toolkit parse links.txt
curl -sS "$SUBSCRIPTION_URL" | vless-toolkit summary -
vless-toolkit validate ./subscriptions/*.txt
```

The CLI performs no network requests itself. Fetching a subscription URL is left
to a tool you already trust.

## Inspecting links

`parse` accepts `--format text|table|json|yaml`:

```bash
vless-toolkit parse "$LINK"
vless-toolkit parse "$LINK" --format table
vless-toolkit parse links.txt --format json
vless-toolkit parse links.txt --format yaml
```

JSON and YAML preserve every parsed field. The table view is intentionally
credential-free: it shows protocol, country, name, host, port, transport and
security, but never UUIDs or passwords.

Use `--redact` to mask credentials in text/JSON/YAML output and `--hide-hosts` to
hide server addresses as well:

```bash
vless-toolkit parse "$LINK" --redact
vless-toolkit parse "$LINK" --hide-hosts --format yaml
```

Redacted links remain syntactically valid, so they can still be parsed for
diagnostics.

## Building links

`build` requires `--protocol`, `--host` and `--port`. Credentials depend on the
protocol:

```bash
# VLESS
vless-toolkit build --protocol vless \
  --uuid b831381d-6324-4d53-ad4f-8cda48b30811 \
  --host edge.example.com --port 443 \
  --name Tokyo --set security=tls --set type=ws --set path=/ws

# VMess
vless-toolkit build --protocol vmess \
  --uuid b831381d-6324-4d53-ad4f-8cda48b30811 \
  --host edge.example.com --port 443 \
  --set network=ws --set tls=tls --set path=/ws

# Trojan
vless-toolkit build --protocol trojan \
  --host edge.example.com --port 443 \
  --password example-password --set security=tls

# Shadowsocks
vless-toolkit build --protocol ss \
  --host edge.example.com --port 8388 \
  --method aes-256-gcm --password example-password
```

`--set` is repeatable. Unknown query parameters are preserved for VLESS,
Trojan and Shadowsocks; VMess options map to their common JSON names.

## Subscriptions

`convert` emits links by default. Use `--subscription` for standard base64,
`--urlsafe` for URL-safe base64 and `--no-padding` to strip padding:

```bash
vless-toolkit convert links.txt --subscription > subscription.txt
vless-toolkit convert links.txt --subscription --urlsafe --no-padding
vless-toolkit convert subscription.txt --format yaml
```

`parse`, `validate`, `dedupe`, `normalize` and `summary` accept subscription
payloads directly, so decoding to an intermediate file is optional.

## Canonical forms and duplicates

`normalize` lower-cases hosts and known enum values, sorts query parameters,
drops explicit defaults such as `encryption=none`, and sorts VMess extension
fields:

```bash
vless-toolkit normalize links.txt
```

`dedupe` uses the same canonicalization and ignores display names by default:

```bash
vless-toolkit dedupe links.txt
vless-toolkit dedupe --keep-names links.txt
```

The output goes to stdout and a one-line duplicate count goes to stderr.

## Summaries and colors

`summary` reports totals, unique hosts, protocol counts, country counts and
country/protocol groups:

```bash
vless-toolkit summary links.txt
vless-toolkit summary links.txt --format table
```

Country tags are inferred from regional-indicator flags, bracketed or delimited
ISO codes (`[JP]`, `US |`, `| DE |`) and common English country names. Records
without a recognizable tag are counted as `Unknown`.

Tables use ANSI color only when stdout is an interactive TTY. Force or disable it
explicitly:

```bash
vless-toolkit --color summary links.txt --format table
vless-toolkit --no-color summary links.txt --format table
NO_COLOR=1 vless-toolkit summary links.txt --format table
```

`--no-color` wins over `--color`; `--color` wins over `NO_COLOR`.

## Validation and exit codes

`validate` prints one line per link and exits `1` if any link is invalid:

```bash
if vless-toolkit validate links.txt; then
  echo "all links are valid"
fi
```

Exit codes:

- `0` — success;
- `1` — `validate` found at least one invalid link;
- `2` — invalid usage, missing input or an unparseable link in another command.

## QR codes

```bash
vless-toolkit qr "$LINK" --border 2
```

ASCII QR codes are emitted with two characters per module. The implementation
uses byte mode, versions 1–10 and error correction L; links that are too long
fail with an error instead of producing an unusable code.
