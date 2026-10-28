import pytest
from vless_toolkit.cli import main

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def _link(host: str, name: str, protocol: str = "vless") -> str:
    quoted = name.replace(" ", "%20")
    if protocol == "trojan":
        return f"trojan://secret@{host}:443#{quoted}"
    return f"vless://{UUID}@{host}:443?security=tls#{quoted}"


def test_sort_orders_links_by_country(capsys: pytest.CaptureFixture[str]) -> None:
    links = [
        _link("nl.example.com", "Netherlands Amsterdam"),
        _link("de.example.com", "Germany Frankfurt"),
        _link("jp.example.com", "Japan Tokyo", protocol="trojan"),
    ]

    assert main(["sort", *links]) == 0

    names = [line.rsplit("#", 1)[1] for line in capsys.readouterr().out.splitlines()]
    assert names == ["Germany%20Frankfurt", "Japan%20Tokyo", "Netherlands%20Amsterdam"]


def test_sort_keeps_original_link_text(capsys: pytest.CaptureFixture[str]) -> None:
    first = _link("nl.example.com", "Netherlands")
    second = _link("de.example.com", "Germany")

    assert main(["sort", first, second]) == 0

    assert capsys.readouterr().out.splitlines() == [second, first]


def test_sort_by_name_and_reverse(capsys: pytest.CaptureFixture[str]) -> None:
    links = [_link("a.example.com", "Amsterdam"), _link("z.example.com", "Zurich")]

    assert main(["sort", "--by", "name", "--reverse", *links]) == 0

    names = [line.rsplit("#", 1)[1] for line in capsys.readouterr().out.splitlines()]
    assert names == ["Zurich", "Amsterdam"]


def test_sort_puts_unknown_countries_last(capsys: pytest.CaptureFixture[str]) -> None:
    links = [_link("a.example.com", "Node A"), _link("de.example.com", "Germany")]

    assert main(["sort", *links]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].endswith("#Germany")
    assert lines[1].endswith("#Node%20A")


def test_sort_reports_an_unparsable_link(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["sort", "vmess://not-json"]) == 2
    assert "link 1:" in capsys.readouterr().err


def test_sort_by_protocol_groups_transports(capsys: pytest.CaptureFixture[str]) -> None:
    links = [_link("a.example.com", "Trojan", protocol="trojan"), _link("b.example.com", "VLESS")]

    assert main(["sort", "--by", "protocol", *links]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("trojan://")
    assert lines[1].startswith("vless://")
