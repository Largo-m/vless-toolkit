import re

import pytest
from vless_toolkit import (
    VLESS,
    Shadowsocks,
    Trojan,
    display_width,
    render_records_table,
    render_table,
)
from vless_toolkit.cli import main
from vless_toolkit.errors import LinkValidationError
from vless_toolkit.table import ANSI_HEADER, color_enabled

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


class FakeStream:
    def __init__(self, tty: bool) -> None:
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


def test_display_width_handles_wide_and_combining_text() -> None:
    assert display_width("abc") == 3
    assert display_width("\u6f22\u5b57") == 4
    assert display_width("e\u0301") == 1


def test_render_table_aligns_columns() -> None:
    output = render_table(
        ("Name", "Count"),
        [("a", 1), ("\u6f22", 20)],
        aligns=("l", "r"),
    )
    lines = output.splitlines()
    assert lines[0] == "Name | Count"
    assert lines[1] == "-----+------"
    assert lines[2] == "a    |     1"
    assert lines[3] == "\u6f22   |    20"
    assert len({display_width(line) for line in lines}) == 1


def test_render_table_color_only_wraps_header() -> None:
    plain = render_table(("Name", "Count"), [("node", 2)])
    colored = render_table(("Name", "Count"), [("node", 2)], color=True)
    assert colored.startswith(ANSI_HEADER)
    assert ANSI_PATTERN.sub("", colored) == plain
    assert "node" not in colored.splitlines()[0]


def test_render_table_rejects_malformed_input() -> None:
    with pytest.raises(LinkValidationError, match="at least one column"):
        render_table((), [])
    with pytest.raises(LinkValidationError, match="alignment count"):
        render_table(("A", "B"), [], aligns=("l",))
    with pytest.raises(LinkValidationError, match="alignment"):
        render_table(("A",), [], aligns=("x",))
    with pytest.raises(LinkValidationError, match="expected 2"):
        render_table(("A", "B"), [("only-one",)])


def test_render_table_sanitizes_newlines() -> None:
    output = render_table(("Name",), [("two\nlines",)])
    assert "two lines" in output
    assert len(output.splitlines()) == 3


def test_render_records_table_omits_credentials() -> None:
    records = [
        VLESS(uuid=UUID, host="us.example.com", port=443, params={"security": "tls"}, name="US"),
        Trojan(password="live-secret", host="jp.example.com", name="\U0001f1ef\U0001f1f5"),
        Shadowsocks(method="aes-256-gcm", password="other-secret", host="2001:db8::1"),
    ]
    output = render_records_table(records)
    assert "Protocol" in output
    assert "vless" in output
    assert "US" in output
    assert "tls" in output
    assert "aes-256-gcm" in output
    assert UUID not in output
    assert "live-secret" not in output
    assert "other-secret" not in output


def test_color_enabled_precedence() -> None:
    assert color_enabled(FakeStream(True), environ={}) is True
    assert color_enabled(FakeStream(False), environ={}) is False
    assert color_enabled(FakeStream(False), force_color=True, environ={}) is True
    assert color_enabled(FakeStream(True), no_color=True, force_color=True) is False
    assert color_enabled(FakeStream(True), environ={"NO_COLOR": "1"}) is False
    assert color_enabled(FakeStream(False), force_color=True, environ={"NO_COLOR": "1"}) is True


def test_cli_table_output_is_plain_without_tty(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["parse", "vless://" + UUID + "@example.com:443#Node", "--format", "table"]) == 0
    output = capsys.readouterr().out
    assert "Protocol" in output
    assert "\x1b[" not in output


def test_cli_table_color_flags(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    link = "vless://" + UUID + "@example.com:443#Node"
    assert main(["--color", "parse", link, "--format", "table"]) == 0
    assert "\x1b[" in capsys.readouterr().out

    assert main(["--no-color", "--color", "parse", link, "--format", "table"]) == 0
    assert "\x1b[" not in capsys.readouterr().out

    monkeypatch.setenv("NO_COLOR", "1")
    assert main(["--color", "parse", link, "--format", "table"]) == 0
    assert "\x1b[" in capsys.readouterr().out

    assert main(["--no-color", "parse", link, "--format", "table"]) == 0
    assert "\x1b[" not in capsys.readouterr().out


def test_summary_table(capsys: pytest.CaptureFixture[str]) -> None:
    link = "vless://" + UUID + "@example.com:443#US%20Node"
    assert main(["summary", link, "--format", "table"]) == 0
    output = capsys.readouterr().out
    assert "Protocol" in output
    assert "Country" in output
    assert "US" in output
