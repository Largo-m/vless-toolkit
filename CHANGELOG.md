# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project skeleton, packaging metadata and CI workflow.
- VLESS share-link parser with UUID, host, port, query and display-name
  validation.
- VLESS serializer with RFC 3986 encoding, IPv6 support and round-trip tests.
- VMess base64-JSON codec with unknown-field preservation and duplicate-key
  rejection.
- Trojan share-link parser and serializer with encoded passwords and
  credential-safe reprs.
- Shadowsocks SIP002 and legacy codecs with plugin support and
  credential-safe reprs.
- Unified link dispatch plus base64 subscription decoding/encoding with
  plain-text and unpadded URL-safe support.
- ``vless-toolkit`` CLI with ``parse``, ``build``, ``convert``, ``validate``,
  ``dedupe`` and ``summary`` commands, file/stdin input and no network access.
- JSON and dependency-free YAML export via the library and CLI
  (``--format json|yaml``).
- Pure-Python byte-mode QR generation (versions 1-10, ECC L), ASCII rendering
  and the ``qr`` CLI command.
- Link normalization, credential-safe fingerprints and semantic deduplication
  (with optional display-name sensitivity), plus ``normalize``/``dedupe`` CLI
  support.
- Credential and hostname redaction helpers with free-text log redaction and
  ``--redact``/``--hide-hosts`` CLI flags.
- Country inference (flags, explicit tags and country names) and summary
  statistics grouped by country and country/protocol.
- Unicode-aware ASCII tables for ``parse`` and ``summary`` with credential-free
  output, TTY color detection and ``--color``/``--no-color`` overrides.

### Infrastructure

- CI now runs Python 3.9-3.13 on Ubuntu, Windows and macOS, enforces 90% test
  coverage, builds/install-checks distributions and includes a tag-based GitHub
  release workflow, Dependabot and local pre-commit hooks.

### Documentation

- Expanded README with feature overview, installation, library and CLI examples,
  supported formats and limitations, plus detailed CLI and security guides.

### Tests

- Deterministic property-style tests covering randomized round trips for all
  protocols and subscription encodings.
