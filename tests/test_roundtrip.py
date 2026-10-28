"""Deterministic property-style round-trip tests.

The project intentionally has no Hypothesis dependency, so these tests build
pseudo-random but valid records from fixed seeds. Every failure is reproducible
from the seed printed by pytest.
"""

from __future__ import annotations

import random
import string
from uuid import UUID

import pytest
from vless_toolkit import (
    VLESS,
    Shadowsocks,
    Trojan,
    VMess,
    decode_subscription,
    encode_subscription,
    parse_link,
    serialize_link,
)

HOSTS = ("example.com", "node-1.example", "127.0.0.1", "2001:db8::1")
TEXT = (
    string.ascii_letters
    + string.digits
    + " _-./:@?#&=%+[]{}!$'()*,;~"
    + "\u00e9\u6f22\U0001f642"
)
METHODS = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")
UUID_BITS = 128


def _text(rng: random.Random, *, allow_empty: bool = True) -> str:
    length = rng.randint(0 if allow_empty else 1, 24)
    return "".join(rng.choice(TEXT) for _ in range(length))


def _name(rng: random.Random) -> str:
    return _text(rng)


def _uuid(rng: random.Random) -> str:
    return str(UUID(int=rng.getrandbits(UUID_BITS), version=4))


def _params(rng: random.Random) -> dict[str, str]:
    params: dict[str, str] = {}
    for index in range(rng.randint(0, 5)):
        params[f"k{index}_{_text(rng, allow_empty=False)[:8]}"] = _text(rng)
    return params


def _extra(rng: random.Random) -> dict[str, object]:
    extra: dict[str, object] = {}
    for index in range(rng.randint(0, 3)):
        key = f"ext_{index}"
        value = rng.choice(
            [
                _text(rng),
                rng.randint(-1000, 1000),
                rng.choice([True, False, None]),
                [_text(rng), rng.randint(0, 10)],
                {"nested": _text(rng)},
            ]
        )
        extra[key] = value
    return extra


def _random_record(rng: random.Random) -> VLESS | VMess | Trojan | Shadowsocks:
    host = rng.choice(HOSTS)
    port = rng.randint(1, 65535)
    kind = rng.randrange(4)
    if kind == 0:
        params = _params(rng)
        if rng.random() < 0.5:
            params["encryption"] = "none"
        return VLESS(
            uuid=_uuid(rng),
            host=host,
            port=port,
            params=params,
            name=_name(rng),
        )
    if kind == 1:
        return VMess(
            uuid=_uuid(rng),
            host=host,
            port=port,
            name=_name(rng),
            alter_id=rng.randint(0, 64),
            security=rng.choice(METHODS),
            network=rng.choice(("tcp", "ws", "grpc", "h2")),
            header_type=rng.choice(("none", "http")),
            tls=rng.choice(("", "tls", "reality")),
            sni=_text(rng),
            host_header=_text(rng),
            path=_text(rng),
            alpn=_text(rng),
            fingerprint=_text(rng),
            extra=_extra(rng),
        )
    if kind == 2:
        return Trojan(
            password=_text(rng, allow_empty=False),
            host=host,
            port=port,
            params=_params(rng),
            name=_name(rng),
        )
    return Shadowsocks(
        method=rng.choice(METHODS),
        password=_text(rng, allow_empty=False),
        host=host,
        port=port,
        params=_params(rng),
        name=_name(rng),
    )


@pytest.mark.parametrize("seed", range(20))
def test_serialize_parse_roundtrip_for_random_records(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(25):
        record = _random_record(rng)
        link = serialize_link(record)
        parsed = parse_link(link)
        assert parsed == record, link
        assert serialize_link(parsed) == link


@pytest.mark.parametrize("urlsafe", [False, True])
@pytest.mark.parametrize("padding", [False, True])
def test_random_subscription_roundtrip(urlsafe: bool, padding: bool) -> None:
    rng = random.Random(1000 + int(urlsafe) * 2 + int(padding))
    links = [serialize_link(_random_record(rng)) for _ in range(30)]
    payload = encode_subscription(links, urlsafe=urlsafe, padding=padding)
    decoded_links = decode_subscription(payload)
    assert decoded_links == links
    assert parse_link(decoded_links[0]) == parse_link(links[0])


def test_vless_fragment_survives_unusual_characters() -> None:
    record = VLESS(
        uuid=_uuid(random.Random(7)),
        host="example.com",
        port=443,
        params={"path": "/a b?c=d&e#f", "security": "tls"},
        name="  spaced #name? + percent%  ",
    )
    assert parse_link(serialize_link(record)) == record
