import base64

import pytest
from vless_toolkit import Shadowsocks, parse_shadowsocks, serialize_shadowsocks
from vless_toolkit.errors import LinkParseError, LinkValidationError


def userinfo(method: str, password: str, *, urlsafe: bool = True, pad: bool = False) -> str:
    raw = f"{method}:{password}".encode()
    encoded = base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)
    text = encoded.decode("ascii")
    return text if pad else text.rstrip("=")


def test_parse_sip002_link_with_plugin() -> None:
    token = userinfo("aes-256-gcm", "s3cr3t")
    link = (
        f"ss://{token}@[2001:db8::1]:8388/"
        "?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls#Tokyo%20SS"
    )
    parsed = parse_shadowsocks(link)
    assert parsed.method == "aes-256-gcm"
    assert parsed.password == "s3cr3t"
    assert parsed.host == "2001:db8::1"
    assert parsed.port == 8388
    assert parsed.plugin == "v2ray-plugin;mode=websocket;tls"
    assert parsed.name == "Tokyo SS"


def test_parse_plain_percent_encoded_userinfo() -> None:
    parsed = parse_shadowsocks("ss://aes-128-gcm:p%40ss%3Aword@example.com:8388#Plain")
    assert parsed.method == "aes-128-gcm"
    assert parsed.password == "p@ss:word"


def test_parse_legacy_base64_link() -> None:
    raw = b"chacha20-ietf-poly1305:legacy@ss@example.com:8388"
    token = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    parsed = parse_shadowsocks(f"ss://{token}#Legacy")
    assert parsed.method == "chacha20-ietf-poly1305"
    assert parsed.password == "legacy@ss"
    assert parsed.host == "example.com"
    assert parsed.port == 8388
    assert parsed.name == "Legacy"


def test_parse_sip002_with_padding_and_standard_base64() -> None:
    token = userinfo("aes-256-gcm", "secret", urlsafe=False, pad=True)
    parsed = parse_shadowsocks(f"ss://{token}@example.com:8388")
    assert parsed.password == "secret"


def test_shadowsocks_round_trip_with_unicode_and_plugin() -> None:
    record = Shadowsocks(
        method="2022-blake3-aes-128-gcm",
        password="密钥 with spaces:@/",
        host="2001:db8::2",
        port=9443,
        params={"plugin": "obfs-local;obfs=http;obfs-host=cdn.example.com"},
        name="节点 二",
    )
    link = serialize_shadowsocks(record)
    assert "=" not in link.split("@")[0].split("//", 1)[1]
    assert "@[2001:db8::2]:9443" in link
    assert parse_shadowsocks(link) == record
    assert str(record) == link


def test_serialize_minimal_shadowsocks_link() -> None:
    record = Shadowsocks(method="aes-256-gcm", password="secret", host="example.com")
    link = serialize_shadowsocks(record)
    assert link.startswith("ss://")
    assert link.endswith("@example.com:8388")
    assert parse_shadowsocks(link) == record


def test_password_is_not_in_repr() -> None:
    record = Shadowsocks(method="aes-256-gcm", password="s3cr3t", host="example.com")
    assert "s3cr3t" not in repr(record)


@pytest.mark.parametrize(
    "link",
    [
        "vless://example.com:443",
        "ss://",
        "ss://not-base64@example.com:8388",
        "ss://%%%@example.com:8388",
        "ss://@example.com:8388",
        "ss://dXNlcjpwYXNz@example.com",
        "ss://dXNlcjpwYXNz@example.com:70000",
        "ss://dXNlcjpwYXNz@example.com:8388/extra",
        "ss://dXNlcjpwYXNz@example.com:8388?plugin=a&plugin=b",
        "ss://YWVzLTI1Ni1nY206@example.com:8388",
        f"ss://{userinfo('aes-256-gcm', 'secret')}@exa mple.com:8388",
    ],
)
def test_parse_shadowsocks_rejects_invalid_links(link: str) -> None:
    with pytest.raises(LinkParseError):
        parse_shadowsocks(link)


def test_shadowsocks_validates_manual_construction() -> None:
    with pytest.raises(LinkValidationError, match="password"):
        Shadowsocks(method="aes-256-gcm", password="", host="example.com")
    with pytest.raises(LinkValidationError, match="port"):
        Shadowsocks(method="aes-256-gcm", password="x", host="example.com", port=0)


def test_serialize_requires_shadowsocks_instance() -> None:
    with pytest.raises(LinkValidationError, match="Shadowsocks instance"):
        serialize_shadowsocks("ss://x")  # type: ignore[arg-type]
