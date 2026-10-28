# Security notes

## Threat model

A VLESS, VMess, Trojan or Shadowsocks link contains access credentials.
Anyone who obtains it can usually connect to the proxy and consume its quota.
`vless-toolkit` is a local parser and converter, not a secure vault. It reduces
accidental exposure but cannot protect secrets that were already copied to a
shared location.

Things this project does:

- makes no network requests and sends no telemetry;
- keeps runtime dependencies at zero;
- redacts credentials and free-form text on request;
- omits UUIDs and passwords from table output;
- keeps credential fields out of dataclass `repr` output;
- rejects malformed links instead of guessing.

Things this project does not do:

- fetch or refresh subscription URLs;
- encrypt local files;
- scrub shell history, terminal scrollback, screenshots or clipboard managers;
- validate that a server is trustworthy or that credentials are still active;
- redact arbitrary base64 blobs outside recognizable `vless://`, `vmess://`,
  `trojan://` and `ss://` links.

## Redaction

```python
from vless_toolkit import redact_link, redact_record, redact_text

safe = redact_link(link)
safe_without_host = redact_link(link, keep_host=False)
log_line = redact_text(f"failed to connect with {link}")
```

`redact_link` replaces UUIDs with the nil UUID and passwords with `[REDACTED]`,
masks sensitive query keys and preserves the rest of the record. The result is
still parseable, so it can be attached to a bug report and inspected with the
normal parser. It cannot authenticate.

`redact_text` finds embedded share links in a string and replaces malformed
matches with `<redacted-invalid-link>` rather than echoing them.

Credential fields are hidden from `repr` for Trojan and Shadowsocks; `VLESS` and
`VMess` `repr` still contain their UUID. Never print whole records in logs
without redaction.

## Command-line hygiene

- Prefer a password manager or environment file over pasting a link into a shell.
- If a link must be passed on a command line, single-quote it to avoid shell
  expansion, and remember that history may keep it.
- Do not pipe real output into issue trackers, CI logs or screenshots.
- Use `--redact` or `--hide-hosts` for diagnostics.
- Delete temporary subscription files after use, or store them with restrictive
  filesystem permissions.

## QR codes and screenshots

A QR code is an unencrypted encoding of the whole link. Do not display one on a
shared screen or attach it to a report. The `parse --format table` output is the
safer format for discussing connection problems.

## Reporting vulnerabilities

Use GitHub's private vulnerability reporting (Security → Report a vulnerability)
and include a minimal reproduction without live credentials. Rotate any
credential that may have been exposed in a report, log or commit. General
reporting guidance is in [SECURITY.md](../SECURITY.md).
