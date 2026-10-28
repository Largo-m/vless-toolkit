import base64

import pytest
from vless_toolkit import (
    VLESS,
    Shadowsocks,
    Trojan,
    VMess,
    parse_link,
    parse_subscription,
    serialize_link,
    serialize_vmess,
)
from vless_toolkit.errors import LinkParseError, LinkValidationError
from vless_toolkit.subscription import decode_subscription, encode_subscription

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

VLESS_LINK = f"vless://{UUID}@vless.example.com:443?security=tls#VLESS"
TROJAN_LINK = "trojan://secret@trojan.example.com:443?security=tls#Trojan"
SHADOWSOCKS_LINK = "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#SS"
VMESS_RECORD = VMess(uuid=UUID, host="vmess.example.com", port=443, name="VMess")
VMESS_LINK = serialize_vmess(VMESS_RECORD)
ALL_LINKS = [VLESS_LINK, VMESS_LINK, TROJAN_LINK, SHADOWSOCKS_LINK]


def test_parse_link_dispatches_each_protocol() -> None:
    assert isinstance(parse_link(VLESS_LINK), VLESS)
    assert parse_link(VMESS_LINK) == VMESS_RECORD
    assert isinstance(parse_link(TROJAN_LINK), Trojan)
    assert isinstance(parse_link(SHADOWSOCKS_LINK), Shadowsocks)


def test_parse_link_is_case_insensitive_for_scheme() -> None:
    parsed = parse_link(VLESS_LINK.replace("vless://", "VLESS://"))
    assert isinstance(parsed, VLESS)


def test_serialize_link_round_trips_all_protocols() -> None:
    for link in ALL_LINKS:
        record = parse_link(link)
        assert parse_link(serialize_link(record)) == record


def test_parse_link_rejects_unsupported_or_missing_scheme() -> None:
    with pytest.raises(LinkParseError, match="unsupported scheme"):
        parse_link("http://example.com")
    with pytest.raises(LinkParseError, match="missing a scheme"):
        parse_link("example.com:443")


def test_serialize_link_rejects_unknown_type() -> None:
    with pytest.raises(LinkValidationError, match="unsupported record type"):
        serialize_link({"host": "example.com"})  # type: ignore[arg-type]


def test_decode_plain_subscription_preserves_order_and_skips_blanks() -> None:
    payload = "\r\n".join(ALL_LINKS) + "\r\n\r\n"
    assert decode_subscription(payload) == ALL_LINKS


@pytest.mark.parametrize("urlsafe", [False, True])
@pytest.mark.parametrize("padding", [False, True])
def test_encode_and_decode_subscription_round_trip(urlsafe: bool, padding: bool) -> None:
    encoded = encode_subscription(ALL_LINKS, urlsafe=urlsafe, padding=padding)
    assert decode_subscription(encoded) == ALL_LINKS
    records = parse_subscription(encoded)
    assert [serialize_link(record) for record in records] == ALL_LINKS


def test_encode_subscription_accepts_records() -> None:
    records = [parse_link(link) for link in ALL_LINKS]
    encoded = encode_subscription(records)
    assert parse_subscription(encoded) == records


def test_decode_subscription_handles_wrapped_base64() -> None:
    encoded = encode_subscription(ALL_LINKS)
    wrapped = "\n".join(encoded[index : index + 32] for index in range(0, len(encoded), 32))
    assert decode_subscription(wrapped) == ALL_LINKS


def test_parse_subscription_reports_line_number() -> None:
    raw = "\n".join([VLESS_LINK, "trojan://missing-port@example.com"]).encode()
    payload = base64.b64encode(raw).decode()
    with pytest.raises(LinkParseError, match="line 2"):
        parse_subscription(payload)


@pytest.mark.parametrize(
    "payload",
    ["", "   ", "%%%not-base64%%%", base64.b64encode(b"hello world").decode()],
)
def test_decode_subscription_rejects_invalid_payloads(payload: str) -> None:
    with pytest.raises(LinkParseError):
        decode_subscription(payload)


def test_encode_subscription_rejects_empty_and_invalid_input() -> None:
    with pytest.raises(LinkValidationError, match="empty subscription"):
        encode_subscription([])
    with pytest.raises(LinkValidationError, match="invalid share link"):
        encode_subscription(["https://example.com"])


def test_encode_subscription_rejects_empty_link() -> None:
    with pytest.raises(LinkValidationError, match="empty share link"):
        encode_subscription(["  "])
