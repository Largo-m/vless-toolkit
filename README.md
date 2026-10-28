# vless-toolkit

[![CI](https://github.com/Largo-m/vless-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Largo-m/vless-toolkit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Parse, validate, build and convert **VLESS**, **VMess**, **Trojan** and
**Shadowsocks** share links and subscription payloads from a dependency-free
Python library or a single command.

Share links are credentials. `vless-toolkit` is designed to make them easier to
inspect and transform without handing your subscriptions to a third-party
service, and it includes redaction and secure-logging helpers for that reason.

## Status

The project is under active development. The initial package skeleton is in
place; parsers, serializers and the CLI are arriving through reviewed pull
requests. See [CHANGELOG.md](CHANGELOG.md) for progress.

## Requirements

- Python 3.9 or newer
- No third-party runtime dependencies

## Development

```bash
git clone https://github.com/Largo-m/vless-toolkit.git
cd vless-toolkit
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
```

## License

MIT © 2026 Largo-m. See [LICENSE](LICENSE).
