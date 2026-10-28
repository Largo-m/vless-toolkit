import pytest
from vless_toolkit import Trojan, parse_trojan, serialize_trojan
from vless_toolkit.errors import LinkParseError, LinkValidationError


def test_parse_minimal_trojan_link() -> None:
    parsed = parse_trojan("trojan://s3cr3t@example.com:443")
    assert parsed == Trojan(password="s3cr3t", host="example.com", port=443)
    assert parsed.security == "tls"


def test_parse_full_trojan_link_decodes_password_and_name() -> None:
    link = (
        "trojan://p%40ss%3Aword%2F%20x@[2001:db8::1]:8443"
        "?security=tls&sni=edge.example.com&type=ws&host=cdn.example.com"
        "&path=%2Ftrojan%3Fed%3D2048#Tokyo%20Edge"
    )
    parsed = parse_trojan(link)
    assert parsed.password == "p@ss:word/ x"
    assert parsed.host == "2001:db8::1"
    assert parsed.port == 8443
    assert parsed.params["path"] == "/trojan?ed=2048"
    assert parsed.name == "Tokyo Edge"


def test_parse_trojan_accepts_raw_colon_in_password() -> None:
    parsed = parse_trojan("trojan://part1:part2@example.com:443")
    assert parsed.password == "part1:part2"


def test_trojan_password_is_not_in_repr() -> None:
    parsed = parse_trojan("trojan://s3cr3t@example.com:443")
    assert "s3cr3t" not in repr(parsed)
    assert "example.com" in repr(parsed)


def test_serialize_trojan_percent_encodes_secret() -> None:
    record = Trojan(
        password="p@ss:word/ x",
        host="example.com",
        port=443,
        params={"security": "tls", "sni": "example.com"},
        name="A & B",
    )
    link = serialize_trojan(record)
    assert link == (
        "trojan://p%40ss%3Aword%2F%20x@example.com:443"
        "?security=tls&sni=example.com#A%20%26%20B"
    )
    assert parse_trojan(link) == record
    assert str(record) == link


def test_trojan_round_trip_ipv6_and_unicode() -> None:
    record = Trojan(
        password="例 secret",
        host="2001:db8::2",
        port=443,
        params={"type": "grpc", "serviceName": "grpc svc"},
        name="节点 一",
    )
    link = serialize_trojan(record)
    assert "@[2001:db8::2]:443" in link
    assert parse_trojan(link) == record


@pytest.mark.parametrize(
    "link",
    [
        "vless://s3cr3t@example.com:443",
        "trojan://example.com:443",
        "trojan://@example.com:443",
        "trojan://s3cr3t@example.com",
        "trojan://s3cr3t@example.com:70000",
        "trojan://s3cr3t@example.com:443/ws",
        "trojan://s3cr3t@example.com:443?type=ws&type=grpc",
        "trojan://s3cr3t@exa mple.com:443",
    ],
)
def test_parse_trojan_rejects_invalid_links(link: str) -> None:
    with pytest.raises(LinkParseError):
        parse_trojan(link)


def test_trojan_validates_manual_construction() -> None:
    with pytest.raises(LinkValidationError, match="password"):
        Trojan(password="", host="example.com")
    with pytest.raises(LinkValidationError, match="port"):
        Trojan(password="secret", host="example.com", port=0)
    with pytest.raises(LinkValidationError, match="query parameter"):
        Trojan(password="secret", host="example.com", params={"sni": 1})  # type: ignore[dict-item]


def test_serialize_requires_trojan_instance() -> None:
    with pytest.raises(LinkValidationError, match="Trojan instance"):
        serialize_trojan("trojan://x")  # type: ignore[arg-type]
