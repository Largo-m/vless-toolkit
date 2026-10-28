# Contributing

Thanks for considering a contribution. This project aims to stay small,
readable and dependency-free at runtime.

## Development setup

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
```

## Pull requests

- Use a short-lived feature branch and a conventional commit message, for
  example `feat(parser): add VLESS share-link parser`.
- Keep each pull request focused. Include tests for new behaviour and update
  documentation when user-visible behaviour changes.
- Run `python -m pytest -q` and `python -m ruff check .` before pushing.
- Never include real subscription links, UUIDs, passwords or other credentials
  in commits, issues, tests or screenshots. Use obviously fake fixtures.

## Reporting bugs

Include the Python version, operating system, the exact command, and a
sanitized link or payload that reproduces the problem. See
[SECURITY.md](SECURITY.md) for sensitive reports.
