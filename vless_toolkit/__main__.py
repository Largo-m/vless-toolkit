"""Allow ``python -m vless_toolkit`` to run the CLI."""

from .cli import main

raise SystemExit(main())
