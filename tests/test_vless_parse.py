from vless_toolkit import VLESS, parse_vless
from vless_toolkit.errors import LinkParseError


def test_parse_minimal_vless_link() -> None:
    parsed = parse_vless("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443")
    assert parsed == VLESS(
        uuid="b831381d-6324-4d53-ad4f-8cda48b30811",
        host="example.com",
        port=443,
    )
    assert parsed.encryption == "none"
    assert parsed.security == "none"


def test_parse_full_vless_link_with_percent_encoded_name() -> None:
    link = (
        "vless://B831381D-6324-4D53-AD4F-8CDA48B30811@[2001:db8::1]:8443"
        "?encryption=none&security=tls&sni=edge.example.com&type=ws"
        "&host=edge.example.com&path=%2Fws%3Fed%3D2048#Tokyo%20Edge%20%F0%9F%87%AF%F0%9F%87%B5"
    )
    parsed = parse_vless(link)
    assert parsed.uuid == "b831381d-6324-4d53-ad4f-8cda48b30811"
    assert parsed.host == "2001:db8::1"
    assert parsed.port == 8443
    assert parsed.params["path"] == "/ws?ed=2048"
    assert parsed.params["security"] == "tls"
    assert parsed.name == "Tokyo Edge 🇯🇵"


def test_parse_accepts_surrounding_whitespace_and_query_defaults() -> None:
    parsed = parse_vless(
        "  vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:80?"
        "encryption=none&security=none#%20%0A"
    )
    assert parsed.port == 80
    assert parsed.params == {"encryption": "none", "security": "none"}
    assert parsed.name == " \n"


def test_parse_rejects_unsupported_scheme() -> None:
    try:
        parse_vless("trojan://secret@example.com:443")
    except LinkParseError as exc:
        assert "vless://" in str(exc)
    else:  # pragma: no cover - makes a regression explicit
        raise AssertionError("expected LinkParseError")


def test_parse_rejects_bad_uuid() -> None:
    try:
        parse_vless("vless://not-a-uuid@example.com:443")
    except LinkParseError as exc:
        assert "UUID" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected LinkParseError")


def test_parse_rejects_missing_port() -> None:
    try:
        parse_vless("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com")
    except LinkParseError as exc:
        assert "port" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected LinkParseError")


def test_parse_rejects_out_of_range_port() -> None:
    try:
        parse_vless("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:70000")
    except LinkParseError as exc:
        assert "port" in str(exc).lower()
    else:  # pragma: no cover
        raise AssertionError("expected LinkParseError")


def test_parse_rejects_unsupported_encryption() -> None:
    try:
        parse_vless(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=aes-128-gcm"
        )
    except LinkParseError as exc:
        assert "encryption" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected LinkParseError")


def test_parse_rejects_duplicate_query_parameter() -> None:
    try:
        parse_vless(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=ws&type=grpc"
        )
    except LinkParseError as exc:
        assert "duplicate" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected LinkParseError")


def test_parse_rejects_password() -> None:
    try:
        parse_vless("vless://b831381d-6324-4d53-ad4f-8cda48b30811:secret@example.com:443")
    except LinkParseError as exc:
        assert "password" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected LinkParseError")


def test_parse_rejects_unexpected_path() -> None:
    try:
        parse_vless("vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443/ws")
    except LinkParseError as exc:
        assert "path" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected LinkParseError")
