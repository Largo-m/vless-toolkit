import re
from pathlib import Path

from vless_toolkit import __version__

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_package_exposes_a_semantic_version() -> None:
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_pyproject_version_matches_runtime_version() -> None:
    match = re.search(
        r'(?m)^version\s*=\s*"([^"]+)"',
        PYPROJECT.read_text(encoding="utf-8"),
    )
    assert match is not None
    assert match.group(1) == __version__
