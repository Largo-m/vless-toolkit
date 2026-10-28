from vless_toolkit import __version__


def test_package_exposes_a_semantic_version() -> None:
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
