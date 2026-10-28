import pytest
from vless_toolkit import VLESS, parse_vless, serialize_vless
from vless_toolkit.errors import LinkValidationError

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def test_serialize_minimal_vless_link() -> None:
    record = VLESS(uuid=UUID, host="example.com", port=443)
    assert serialize_vless(record) == f"vless://{UUID}@example.com:443"


def test_serialize_ipv6_and_encoded_name() -> None:
    record = VLESS(
        uuid=UUID,
        host="2001:db8::1",
        port=8443,
        params={"security": "tls", "sni": "edge.example.com"},
        name="Tokyo Edge",
    )
    link = serialize_vless(record)
    assert link == (
        f"vless://{UUID}@[2001:db8::1]:8443"
        "?security=tls&sni=edge.example.com#Tokyo%20Edge"
    )


@pytest.mark.parametrize(
    "link",
    [
        f"vless://{UUID}@example.com:443",
        f"vless://{UUID}@example.com:443?encryption=none",
        f"vless://{UUID}@example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com",
        f"vless://{UUID}@[2001:db8::1]:443?security=reality&sni=example.com#Node%20A",
        f"vless://{UUID}@example.com:80?security=none&type=grpc&serviceName=grpc%20svc#%20",
    ],
)
def test_serialize_round_trips_through_parser(link: str) -> None:
    parsed = parse_vless(link)
    assert parse_vless(serialize_vless(parsed)) == parsed
    assert str(parsed) == serialize_vless(parsed)


def test_serializer_preserves_query_order_and_blank_values() -> None:
    record = VLESS(
        uuid=UUID,
        host="example.com",
        port=443,
        params={"type": "ws", "path": "/a b?c=d", "host": "", "sni": "例.example"},
        name="A & B / C",
    )
    link = serialize_vless(record)
    assert "type=ws&path=%2Fa%20b%3Fc%3Dd&host=&sni=%E4%BE%8B.example" in link
    assert parse_vless(link) == record


def test_serializer_requires_vless_instance() -> None:
    with pytest.raises(LinkValidationError, match="VLESS instance"):
        serialize_vless("vless://example.com")  # type: ignore[arg-type]
