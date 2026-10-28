import base64
import json

import pytest
from vless_toolkit import VMess, parse_vmess, serialize_vmess
from vless_toolkit.errors import LinkParseError, LinkValidationError

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def make_link(payload: dict[str, object], *, urlsafe: bool = True, pad: bool = False) -> str:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    text = encoder(raw).decode("ascii")
    if not pad:
        text = text.rstrip("=")
    return f"vmess://{text}"


def test_parse_vmess_link() -> None:
    link = make_link(
        {
            "v": "2",
            "ps": "Tokyo WS",
            "add": "vmess.example.com",
            "port": "443",
            "id": UUID.upper(),
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/ray",
            "tls": "tls",
            "sni": "vmess.example.com",
            "alpn": "h2,http/1.1",
            "fp": "chrome",
        }
    )
    parsed = parse_vmess(link)
    assert parsed.uuid == UUID
    assert parsed.host == "vmess.example.com"
    assert parsed.port == 443
    assert parsed.name == "Tokyo WS"
    assert parsed.network == "ws"
    assert parsed.tls == "tls"
    assert parsed.host_header == "cdn.example.com"
    assert parsed.path == "/ray"
    assert parsed.extra == {}


def test_parse_vmess_accepts_standard_base64_and_padding() -> None:
    link = make_link(
        {"add": "example.com", "port": 443, "id": UUID},
        urlsafe=False,
        pad=True,
    )
    parsed = parse_vmess(link)
    assert parsed.name == ""
    assert parsed.port == 443
    assert parsed.security == "auto"


def test_vmess_unknown_fields_and_round_trip() -> None:
    link = make_link(
        {
            "add": "example.com",
            "port": "80",
            "id": UUID,
            "ps": "Node A",
            "net": "grpc",
            "vcn": "none",
            "x-custom": {"enabled": True},
        }
    )
    parsed = parse_vmess(link)
    assert parsed.extra == {"vcn": "none", "x-custom": {"enabled": True}}
    serialized = serialize_vmess(parsed)
    assert "=" not in serialized
    assert parse_vmess(serialized) == parsed
    assert str(parsed) == serialized


def test_vmess_to_dict_contains_expected_fields() -> None:
    record = VMess(uuid=UUID, host="example.com", port=443, name="A", path="/ws")
    payload = record.to_dict()
    assert payload["port"] == "443"
    assert payload["aid"] == "0"
    assert payload["ps"] == "A"
    assert payload["path"] == "/ws"


def test_build_and_parse_ipv6_vmess() -> None:
    record = VMess(
        uuid=UUID,
        host="[2001:db8::1]",
        port=8443,
        name="IPv6",
        network="tcp",
        tls="tls",
        sni="ipv6.example.com",
    )
    assert record.host == "2001:db8::1"
    assert parse_vmess(serialize_vmess(record)) == record


@pytest.mark.parametrize(
    "link",
    [
        "https://example.com/sub",
        "vmess://",
        "vmess://not-base64!",
        "vmess://e30",  # {}
        "vmess://W10",  # []
    ],
)
def test_parse_vmess_rejects_invalid_links(link: str) -> None:
    with pytest.raises(LinkParseError):
        parse_vmess(link)


@pytest.mark.parametrize(
    "payload",
    [
        {"add": "example.com", "port": 443, "id": "not-a-uuid"},
        {"add": "example.com", "port": 70000, "id": UUID},
        {"port": 443, "id": UUID},
        {"add": "example.com", "id": UUID},
        {"add": "example.com", "port": 443},
        {"add": "example.com", "port": 443, "id": UUID, "v": "1"},
        {"add": "example.com", "port": 443, "id": UUID, "net": 3},
    ],
)
def test_parse_vmess_rejects_invalid_fields(payload: dict[str, object]) -> None:
    with pytest.raises(LinkParseError):
        parse_vmess(make_link(payload))


def test_parse_vmess_rejects_duplicate_json_keys() -> None:
    raw = f'{{"add":"a.example.com","add":"b.example.com","port":443,"id":"{UUID}"}}'
    encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    with pytest.raises(LinkParseError, match="duplicate"):
        parse_vmess(f"vmess://{encoded}")


def test_vmess_extra_cannot_shadow_known_keys() -> None:
    with pytest.raises(LinkValidationError, match="shadow"):
        VMess(uuid=UUID, host="example.com", port=443, extra={"net": "ws"})


def test_serialize_requires_vmess_instance() -> None:
    with pytest.raises(LinkValidationError, match="VMess instance"):
        serialize_vmess("vmess://x")  # type: ignore[arg-type]
