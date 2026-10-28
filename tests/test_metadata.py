from importlib.metadata import PackageNotFoundError, version

import pytest
from vless_toolkit import __version__


def test_package_exposes_a_semantic_version() -> None:
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_distribution_metadata_matches_runtime_version() -> None:
    try:
        installed = version("vless-toolkit")
    except PackageNotFoundError:
        pytest.skip("package metadata is unavailable in this environment")
    assert installed == __version__
