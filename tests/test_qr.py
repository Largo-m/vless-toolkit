import pytest
from vless_toolkit import QRCode, encode_qr, link_to_ascii_qr
from vless_toolkit.errors import LinkValidationError
from vless_toolkit.qr import qr_to_ascii


def test_encode_short_text_uses_version_one() -> None:
    qr = encode_qr("A")
    assert isinstance(qr, QRCode)
    assert qr.version == 1
    assert qr.size == 21
    assert 0 <= qr.mask <= 7
    assert len(qr.modules) == 21
    assert all(len(row) == 21 for row in qr.modules)


def test_finder_timing_and_dark_module_patterns() -> None:
    qr = encode_qr("A")
    # Top-left finder pattern outer ring and center.
    assert qr.modules[0][0]
    assert qr.modules[0][6]
    assert not qr.modules[1][1]
    assert qr.modules[3][3]
    # Timing pattern alternates along row 6 outside the finder.
    assert qr.modules[6][8]
    assert not qr.modules[6][9]
    assert qr.modules[6][10]
    # Fixed dark module immediately above the bottom-left format area.
    assert qr.modules[qr.size - 8][8]


def test_qr_version_grows_with_payload() -> None:
    small = encode_qr("A" * 10)
    large = encode_qr("A" * 100)
    assert small.version == 1
    assert large.version > small.version
    assert large.size > small.size


def test_qr_accepts_maximum_version_ten_payload_and_rejects_more() -> None:
    assert encode_qr("x" * 271).version == 10
    with pytest.raises(LinkValidationError, match="too long"):
        encode_qr("x" * 272)


def test_qr_generation_is_deterministic() -> None:
    assert encode_qr("vless://example.com:443") == encode_qr("vless://example.com:443")


def test_qr_rejects_empty_or_non_text_input() -> None:
    with pytest.raises(LinkValidationError, match="not be empty"):
        encode_qr("")
    with pytest.raises(LinkValidationError, match="must be a string"):
        encode_qr(b"bytes")  # type: ignore[arg-type]


def test_ascii_render_has_quiet_zone_and_ascii_only() -> None:
    output = link_to_ascii_qr("vless://example.com:443", border=4)
    lines = output.splitlines()
    assert lines[:4] == [""] * 4
    assert "##" in output
    assert output.isascii()
    assert output.endswith("\n")
    assert all(line == line.rstrip() for line in lines)
    assert max(len(line) for line in lines) <= (21 + 8) * 2


def test_ascii_render_without_border_starts_at_finder() -> None:
    qr = encode_qr("A")
    output = qr_to_ascii(qr, border=0)
    first = output.splitlines()[0]
    assert first.startswith("##")


def test_ascii_render_rejects_bad_arguments() -> None:
    qr = encode_qr("A")
    with pytest.raises(LinkValidationError, match="QRCode instance"):
        qr_to_ascii("not-a-qr")  # type: ignore[arg-type]
    with pytest.raises(LinkValidationError, match="between 0 and 16"):
        qr_to_ascii(qr, border=-1)
    with pytest.raises(LinkValidationError, match="between 0 and 16"):
        qr_to_ascii(qr, border=2.5)  # type: ignore[arg-type]
