import pytest
from vless_toolkit import (
    VLESS,
    Shadowsocks,
    Trojan,
    VMess,
    protocol_name,
    summarize_records,
)
from vless_toolkit.errors import LinkValidationError
from vless_toolkit.stats import UNKNOWN_COUNTRY, country_for_record, infer_country

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("\U0001f1ef\U0001f1f5 Tokyo", "JP"),
        ("[us] East", "US"),
        ("DE | Frankfurt", "DE"),
        ("Node | SG | Premium", "SG"),
        ("Toronto CA", "CA"),
        ("Netherlands Premium", "NL"),
        ("United States West", "US"),
        ("random premium node", UNKNOWN_COUNTRY),
        ("ZZ | invalid code", UNKNOWN_COUNTRY),
    ],
)
def test_infer_country(name: str, expected: str) -> None:
    assert infer_country(name) == expected


def test_infer_country_rejects_non_text() -> None:
    with pytest.raises(LinkValidationError, match="display name"):
        infer_country(42)  # type: ignore[arg-type]


def test_protocol_names() -> None:
    assert protocol_name(VLESS(uuid=UUID, host="example.com", port=443)) == "vless"
    assert protocol_name(VMess(uuid=UUID, host="example.com", port=443)) == "vmess"
    assert protocol_name(Trojan(password="secret", host="example.com")) == "trojan"
    assert (
        protocol_name(Shadowsocks(method="aes-256-gcm", password="secret", host="example.com"))
        == "shadowsocks"
    )
    with pytest.raises(LinkValidationError, match="record type"):
        protocol_name(object())  # type: ignore[arg-type]


def test_summarize_records_by_country_and_protocol() -> None:
    records = [
        VLESS(uuid=UUID, host="us.example.com", port=443, name="\U0001f1fa\U0001f1f8 US"),
        Trojan(password="secret", host="us.example.com", port=443, name="Tokyo JP"),
        VMess(uuid=UUID, host="de.example.com", port=443, name="DE | Frankfurt"),
        Shadowsocks(
            method="aes-256-gcm",
            password="secret",
            host="xx.example.com",
            port=8388,
            name="Mystery",
        ),
    ]
    stats = summarize_records(records)
    assert stats.total == 4
    assert stats.unique_hosts == 3
    assert stats.by_protocol == {"shadowsocks": 1, "trojan": 1, "vless": 1, "vmess": 1}
    assert stats.by_country == {"DE": 1, "JP": 1, "US": 1, UNKNOWN_COUNTRY: 1}
    assert stats.by_country_protocol[("US", "vless")] == 1
    assert stats.by_country_protocol[(UNKNOWN_COUNTRY, "shadowsocks")] == 1


def test_country_for_record_uses_name() -> None:
    record = Trojan(password="secret", host="example.com", name="Canada")
    assert country_for_record(record) == "CA"


def test_summarize_empty_records() -> None:
    stats = summarize_records([])
    assert stats.total == 0
    assert stats.unique_hosts == 0
    assert stats.by_protocol == {}
    assert stats.by_country == {}
