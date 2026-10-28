# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-29

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

### Tests

- Deterministic property-style tests covering randomized round trips for all
  protocols and subscription encodings.

### Documentation

- Rewritten README with badges, install instructions, real captured CLI output
  for every command, library quick start, format matrix, redaction table,
  normalisation semantics, project layout and FAQ.
- New `docs/API.md` (every public function and typical workflows),
  `docs/CLI.md` (all eight commands, options, exit codes and recipes),
  `docs/FORMATS.md` (field-by-field rules, base64 dialects, error messages),
  `docs/usage.md` (deeper CLI walkthrough and CI recipes) and
  `docs/security.md` (threat model and explicit non-goals).

### Fixed

- `--version` was hardcoded to `0.1.0` and kept reporting the old version after
  the bump; it now derives from `__version__` and is covered by a test.
- Packaging metadata description contained mojibake and the classifier still
  claimed Beta.

### Changed

- Version bumped to `1.0.0`; the public API is frozen for the `1.x` series.
- Added `py.typed` documentation to the classifier claim and verified every
  documented example against the package.

[1.0.0]: https://github.com/Largo-m/vless-toolkit/releases/tag/v1.0.0
