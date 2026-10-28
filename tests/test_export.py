import json

import pytest
from vless_toolkit import (
    VLESS,
    Shadowsocks,
    Trojan,
    VMess,
    parse_link,
    record_to_dict,
    records_to_json,
    records_to_yaml,
)
from vless_toolkit.errors import LinkValidationError

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

RECORDS = [
    VLESS(
        uuid=UUID,
        host="vless.example.com",
        port=443,
        params={"security": "tls", "sni": "vless.example.com"},
        name="VLESS Node",
    ),
    VMess(
        uuid=UUID,
        host="vmess.example.com",
        port=443,
        name="VMess Node",
        network="ws",
        path="/ray",
        tls="tls",
        extra={"x-custom": {"enabled": True, "tiers": [1, 2]}},
    ),
    Trojan(
        password="s3cr3t",
        host="trojan.example.com",
        port=443,
        params={"sni": "trojan.example.com"},
        name="Trojan: Node",
    ),
    Shadowsocks(
        method="aes-256-gcm",
        password="ss-secret",
        host="ss.example.com",
        port=8388,
        name="SS Node",
    ),
]


def test_record_to_dict_for_each_protocol() -> None:
    dictionaries = [record_to_dict(record) for record in RECORDS]
    assert [item["protocol"] for item in dictionaries] == [
        "vless",
        "vmess",
        "trojan",
        "shadowsocks",
    ]
    assert dictionaries[0]["uuid"] == UUID
    assert dictionaries[1]["extra"] == {"x-custom": {"enabled": True, "tiers": [1, 2]}}
    assert dictionaries[2]["password"] == "s3cr3t"
    assert dictionaries[3]["method"] == "aes-256-gcm"


def test_records_to_json_is_valid_and_roundtrips_links() -> None:
    payload = json.loads(records_to_json(RECORDS))
    assert len(payload) == 4
    assert payload[1]["path"] == "/ray"
    assert payload[2]["params"] == {"sni": "trojan.example.com"}
    links = [record["protocol"] for record in payload]
    assert links == ["vless", "vmess", "trojan", "shadowsocks"]


def test_records_to_yaml_shape_and_quoting() -> None:
    output = records_to_yaml(RECORDS)
    assert output.endswith("\n")
    assert output.startswith("- protocol: vless\n")
    assert "  name: \"VLESS Node\"\n" in output
    assert "  name: \"Trojan: Node\"\n" in output
    assert "  path: \"/ray\"\n" in output
    assert "  extra:\n    x-custom:\n      enabled: true\n      tiers:\n        - 1\n" in output
    assert "  password: s3cr3t\n" in output
    assert "!!python" not in output


def test_yaml_reserved_strings_are_quoted() -> None:
    record = VLESS(uuid=UUID, host="example.com", port=443, name="null")
    output = records_to_yaml([record])
    assert '  name: "null"\n' in output


def test_yaml_numeric_looking_strings_are_quoted() -> None:
    record = Shadowsocks(
        method="aes-256-gcm",
        password="12345",
        host="example.com",
        name="2026-01-01",
    )
    output = records_to_yaml([record])
    assert '  name: "2026-01-01"\n' in output
    assert '  password: "12345"\n' in output
    vmess = VMess(uuid=UUID, host="example.com", port=443)
    assert '  version: "2"\n' in records_to_yaml([vmess])


def test_yaml_scalar_collections_and_empty_values() -> None:
    record = VMess(
        uuid=UUID,
        host="example.com",
        port=443,
        extra={"empty": {}, "items": [], "flag": False, "number": 3.5},
    )
    output = records_to_yaml([record])
    assert "  extra:\n    empty: {}\n    items: []\n    flag: false\n    number: 3.5\n" in output


def test_empty_exports_are_valid() -> None:
    assert records_to_json([]) == "[]"
    assert records_to_yaml([]) == "[]\n"


def test_export_rejects_unsupported_record() -> None:
    with pytest.raises(LinkValidationError, match="record type"):
        record_to_dict({"host": "example.com"})  # type: ignore[arg-type]
    with pytest.raises(LinkValidationError, match="record type"):
        records_to_json([object()])  # type: ignore[list-item]


def test_exported_links_can_be_parsed_back() -> None:
    for record in RECORDS:
        data = record_to_dict(record)
        assert parse_link(str(record)).host == data["host"]
