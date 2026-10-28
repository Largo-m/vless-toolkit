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
