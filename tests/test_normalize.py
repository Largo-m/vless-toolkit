import pytest
from vless_toolkit import (
    VLESS,
    Shadowsocks,
    Trojan,
    VMess,
    normalize_link,
    record_fingerprint,
)
from vless_toolkit.errors import LinkValidationError
from vless_toolkit.normalize import (
    dedupe_links,
    dedupe_records,
    normalize_record,
)

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def test_normalize_vless_sorts_params_and_drops_defaults() -> None:
    record = VLESS(
        uuid=UUID,
        host="EXAMPLE.com",
        port=443,
        params={
            "type": "WS",
            "security": "NONE",
            "sni": "Example.com",
            "encryption": "none",
        },
        name="Node",
    )
    normalized = normalize_record(record)
    assert normalized.host == "example.com"
    assert normalized.params == {"sni": "Example.com", "type": "ws"}
    assert isinstance(normalized, VLESS)
    assert normalized.name == "Node"


def test_normalize_vmess_lowercases_enums_and_sorts_extras() -> None:
    record = VMess(
        uuid=UUID,
        host="VMESS.example.com",
        port=443,
        network="WS",
        security="AUTO",
        header_type="NONE",
        tls="TLS",
        extra={"z": {"b": 1, "a": 2}, "a": True},
    )
    normalized = normalize_record(record)
    assert normalized.host == "vmess.example.com"
    assert normalized.network == "ws"
    assert normalized.security == "auto"
    assert normalized.header_type == "none"
    assert normalized.tls == "tls"
    assert list(normalized.extra) == ["a", "z"]
    assert list(normalized.extra["z"]) == ["a", "b"]


def test_normalize_trojan_and_shadowsocks() -> None:
    trojan = Trojan(
        password="secret",
        host="TROJAN.example.com",
        port=443,
        params={"type": "WS", "security": "TLS"},
    )
    normalized_trojan = normalize_record(trojan)
    assert normalized_trojan.host == "trojan.example.com"
    assert normalized_trojan.params == {"type": "ws"}

    shadowsocks = Shadowsocks(
        method="AES-256-GCM",
        password="secret",
        host="SS.example.com",
        params={"plugin": "v2ray-plugin", "mode": "websocket"},
    )
    normalized_ss = normalize_record(shadowsocks)
    assert normalized_ss.method == "aes-256-gcm"
    assert normalized_ss.host == "ss.example.com"
    assert list(normalized_ss.params) == ["mode", "plugin"]


def test_names_can_be_dropped_for_identity() -> None:
    record = VLESS(uuid=UUID, host="example.com", port=443, name="Named")
    assert normalize_record(record, keep_name=False).name == ""
    assert normalize_link(str(record), keep_name=False).endswith(":443")


def test_fingerprint_ignores_names_by_default() -> None:
    first = VLESS(uuid=UUID, host="example.com", port=443, name="A")
    second = VLESS(uuid=UUID, host="example.com", port=443, name="B")
    assert record_fingerprint(first) == record_fingerprint(second)
    assert record_fingerprint(first, include_name=True) != record_fingerprint(
        second, include_name=True
    )


def test_fingerprint_differs_for_credentials() -> None:
    first = VLESS(uuid=UUID, host="example.com", port=443)
    second = VLESS(
        uuid="c1f6d7b2-5e35-4f6a-9a79-9eb0f18d6b19",
        host="example.com",
        port=443,
    )
    assert record_fingerprint(first) != record_fingerprint(second)


def test_dedupe_is_semantic_and_keeps_first_name() -> None:
    links = [
        f"vless://{UUID}@EXAMPLE.com:443?security=tls&type=ws#First",
        f"vless://{UUID}@example.com:443?type=WS&security=TLS#Second",
        "trojan://secret@example.com:443#T",
    ]
    unique = dedupe_links(links)
    assert len(unique) == 2
    assert unique[0].name == "First"
    assert unique[1].name == "T"


def test_dedupe_can_respect_names() -> None:
    records = [
        VLESS(uuid=UUID, host="example.com", port=443, name="A"),
        VLESS(uuid=UUID, host="example.com", port=443, name="B"),
    ]
    assert len(dedupe_records(records)) == 1
    assert len(dedupe_records(records, include_names=True)) == 2


def test_normalize_link_is_idempotent() -> None:
    link = f"vless://{UUID}@EXAMPLE.com:443?type=WS&security=TLS#Node"
    once = normalize_link(link)
    assert normalize_link(once) == once
    assert once == f"vless://{UUID}@example.com:443?security=tls&type=ws#Node"


def test_normalize_rejects_unknown_types() -> None:
    with pytest.raises(LinkValidationError, match="record type"):
        normalize_record({"host": "example.com"})  # type: ignore[arg-type]
    with pytest.raises(LinkValidationError, match="share-link strings"):
        dedupe_links([object()])  # type: ignore[list-item]
