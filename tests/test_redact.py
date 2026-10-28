import pytest
from vless_toolkit import (
    VLESS,
    Shadowsocks,
    Trojan,
    VMess,
    parse_link,
    redact_link,
    redact_record,
    redact_secret,
    redact_text,
)
from vless_toolkit.errors import LinkValidationError

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def test_redact_secret() -> None:
    assert redact_secret("supersecret") == "[REDACTED]"
    assert redact_secret("supersecret", show_last=4) == "*******cret"
    assert redact_secret("short", show_last=9) == "[REDACTED]"
    assert redact_secret("") == ""
    with pytest.raises(LinkValidationError, match="non-negative"):
        redact_secret("secret", show_last=-1)


@pytest.mark.parametrize(
    "link",
    [
        f"vless://{UUID}@example.com:443?security=tls&token=live-secret#VLESS",
        "trojan://live-secret@example.com:443#Trojan",
        "ss://YWVzLTI1Ni1nY206bGl2ZS1zZWNyZXQ@example.com:8388#SS",
    ],
)
def test_redact_link_removes_credentials(link: str) -> None:
    redacted = redact_link(link)
    assert "live-secret" not in redacted
    assert "example.com" in redacted
    parsed = parse_link(redacted)
    assert parsed.name is not None


def test_redact_vless_uuid_and_sensitive_query() -> None:
    link = (
        f"vless://{UUID}@example.com:443"
        "?security=tls&token=live-secret&sni=example.com#Node"
    )
    record = parse_link(redact_link(link))
    assert record.uuid == "00000000-0000-0000-0000-000000000000"
    assert record.params["token"] == "[REDACTED]"
    assert record.params["sni"] == "example.com"
    assert record.name == "Node"


def test_redact_vmess_credentials_and_extra() -> None:
    record = VMess(
        uuid=UUID,
        host="vmess.example.com",
        port=443,
        extra={"token": "live-secret", "nested": {"password": "nested-secret"}},
    )
    redacted = redact_record(record)
    assert redacted.uuid == "00000000-0000-0000-0000-000000000000"
    assert redacted.extra["token"] == "[REDACTED]"
    assert redacted.extra["nested"]["password"] == "[REDACTED]"
    reparsed = parse_link(redact_link(str(record)))
    assert reparsed.extra["token"] == "[REDACTED]"


def test_redact_trojan_and_shadowsocks_passwords() -> None:
    trojan = Trojan(password="live-secret", host="example.com")
    redacted_trojan = redact_record(trojan)
    assert redacted_trojan.password == "[REDACTED]"
    assert isinstance(redacted_trojan, Trojan)

    ss = Shadowsocks(method="aes-256-gcm", password="live-secret", host="example.com")
    redacted_ss = redact_record(ss)
    assert redacted_ss.password == "[REDACTED]"
    assert isinstance(redacted_ss, Shadowsocks)


def test_hide_hosts() -> None:
    redacted = redact_record(
        VLESS(uuid=UUID, host="private.example.com", port=443), keep_host=False
    )
    assert redacted.host == "redacted.invalid"


def test_redact_text_preserves_surrounding_content() -> None:
    text = (
        f"before vless://{UUID}@example.com:443#A "
        "middle trojan://live-secret@example.com:443#B after"
    )
    redacted = redact_text(text)
    assert redacted.startswith("before vless://")
    assert redacted.endswith(" after")
    assert "live-secret" not in redacted
    assert UUID not in redacted
    assert "example.com" in redacted


def test_redact_text_replaces_malformed_links() -> None:
    redacted = redact_text("bad vless://definitely-not-a-link here")
    assert redacted == "bad <redacted-invalid-link> here"


def test_redact_rejects_unsupported_input() -> None:
    with pytest.raises(LinkValidationError, match="record type"):
        redact_record({"host": "example.com"})  # type: ignore[arg-type]
    with pytest.raises(LinkValidationError, match="text"):
        redact_text(42)  # type: ignore[arg-type]
