import io
import json
import sys
from pathlib import Path

import pytest
from vless_toolkit import parse_link
from vless_toolkit.cli import main
from vless_toolkit.subscription import decode_subscription

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
VLESS_LINK = f"vless://{UUID}@vless.example.com:443?security=tls#VLESS"
TROJAN_LINK = "trojan://secret@trojan.example.com:443#Trojan"


def test_parse_command_outputs_fields(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["parse", VLESS_LINK]) == 0
    output = capsys.readouterr().out
    assert "protocol: vless" in output
    assert "name: VLESS" in output
    assert "host: vless.example.com" in output
    assert "port: 443" in output
    assert f"uuid: {UUID}" in output
    assert "security: tls" in output


def test_parse_json_and_yaml_formats(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["parse", VLESS_LINK, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["protocol"] == "vless"
    assert payload[0]["host"] == "vless.example.com"

    assert main(["parse", VLESS_LINK, "--format", "yaml"]) == 0
    assert capsys.readouterr().out.startswith("- protocol: vless\n")


def test_convert_json_and_yaml_formats(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["convert", VLESS_LINK, TROJAN_LINK, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [item["protocol"] for item in payload] == ["vless", "trojan"]

    assert main(["convert", VLESS_LINK, "--format", "yaml"]) == 0
    assert capsys.readouterr().out.startswith("- protocol: vless\n")


def test_build_vless_round_trip(capsys: pytest.CaptureFixture[str]) -> None:
    status = main(
        [
            "build",
            "--protocol",
            "vless",
            "--host",
            "example.com",
            "--port",
            "443",
            "--uuid",
            UUID,
            "--name",
            "Built Node",
            "--set",
            "security=tls",
            "--set",
            "sni=example.com",
        ]
    )
    assert status == 0
    link = capsys.readouterr().out.strip()
    parsed = parse_link(link)
    assert parsed.host == "example.com"
    assert parsed.name == "Built Node"
    assert parsed.params["sni"] == "example.com"


def test_build_trojan_and_shadowsocks(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(
            [
                "build",
                "--protocol",
                "trojan",
                "--host",
                "example.com",
                "--port",
                "443",
                "--password",
                "s3cr3t",
            ]
        )
        == 0
    )
    trojan_link = capsys.readouterr().out.strip()
    assert parse_link(trojan_link).password == "s3cr3t"

    assert (
        main(
            [
                "build",
                "--protocol",
                "ss",
                "--host",
                "example.com",
                "--port",
                "8388",
                "--method",
                "aes-256-gcm",
                "--password",
                "s3cr3t",
            ]
        )
        == 0
    )
    ss_link = capsys.readouterr().out.strip()
    assert parse_link(ss_link).method == "aes-256-gcm"


def test_build_vmess_with_known_options(capsys: pytest.CaptureFixture[str]) -> None:
    status = main(
        [
            "build",
            "--protocol",
            "vmess",
            "--host",
            "vmess.example.com",
            "--port",
            "443",
            "--uuid",
            UUID,
            "--set",
            "network=ws",
            "--set",
            "path=/ray",
            "--set",
            "tls=tls",
            "--set",
            "alter-id=0",
        ]
    )
    assert status == 0
    parsed = parse_link(capsys.readouterr().out.strip())
    assert parsed.network == "ws"
    assert parsed.path == "/ray"
    assert parsed.tls == "tls"


def test_build_reports_missing_required_fields(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["build", "--protocol", "vless", "--host", "x", "--port", "443"]) == 2
    assert "--uuid is required" in capsys.readouterr().err

    assert (
        main(
            [
                "build",
                "--protocol",
                "vmess",
                "--host",
                "x",
                "--port",
                "443",
                "--uuid",
                UUID,
                "--set",
                "bogus=1",
            ]
        )
        == 2
    )
    assert "unknown VMess option" in capsys.readouterr().err


def test_convert_to_subscription(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["convert", "--subscription", VLESS_LINK, TROJAN_LINK]) == 0
    payload = capsys.readouterr().out.strip()
    links = decode_subscription(payload)
    assert links == [VLESS_LINK, TROJAN_LINK]


def test_convert_subscription_file(tmp_path: Path) -> None:
    path = tmp_path / "sub.txt"
    path.write_text(f"{VLESS_LINK}\n\n{TROJAN_LINK}\n", encoding="utf-8")
    assert main(["convert", str(path)]) == 0


def test_validate_reports_valid_and_invalid_links(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["validate", VLESS_LINK, "trojan://missing-port@example.com"]) == 1
    captured = capsys.readouterr()
    assert "ok #1: vless VLESS" in captured.out
    assert "invalid #2" in captured.err
    assert "1 of 2 link(s) invalid" in captured.err


def test_dedupe_exact_duplicates(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["dedupe", VLESS_LINK, VLESS_LINK, TROJAN_LINK]) == 0
    captured = capsys.readouterr()
    assert len(captured.out.strip().splitlines()) == 2
    assert "removed 1 duplicate" in captured.err


def test_summary(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["summary", VLESS_LINK, TROJAN_LINK, VLESS_LINK]) == 0
    output = capsys.readouterr().out
    assert "total: 3" in output
    assert "unique hosts: 2" in output
    assert "trojan: 1" in output
    assert "vless: 2" in output


def test_stdin_source(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"{VLESS_LINK}\n{TROJAN_LINK}\n"))
    assert main(["summary", "-"]) == 0
    assert "total: 2" in capsys.readouterr().out


def test_missing_file_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["parse", "does-not-exist.txt"]) == 2
    assert "source not found" in capsys.readouterr().err


def test_invalid_set_argument(capsys: pytest.CaptureFixture[str]) -> None:
    status = main(
        [
            "build",
            "--protocol",
            "vless",
            "--host",
            "example.com",
            "--port",
            "443",
            "--uuid",
            UUID,
            "--set",
            "novalue",
        ]
    )
    assert status == 2
    assert "expected KEY=VALUE" in capsys.readouterr().err
