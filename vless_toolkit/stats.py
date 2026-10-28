"""Summary statistics and country inference for proxy records.

Country information is derived from display names, which is the only location
carried by the standard share-link formats. Explicit tags such as ``[JP]``,
``US |`` or a regional-indicator flag are preferred over country-name words.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from .errors import LinkValidationError
from .parser import Link, protocol_name

UNKNOWN_COUNTRY = "Unknown"

_ISO_TEXT = """
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ
BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR
CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU
ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ
LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ
MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF
PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI
SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR
TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
"""

_ISO_CODES = frozenset(re.findall(r"[A-Z]{2}", _ISO_TEXT))

_COUNTRY_NAMES = {
    "argentina": "AR",
    "armenia": "AM",
    "australia": "AU",
    "austria": "AT",
    "azerbaijan": "AZ",
    "bangladesh": "BD",
    "belgium": "BE",
    "brazil": "BR",
    "bulgaria": "BG",
    "canada": "CA",
    "chile": "CL",
    "croatia": "HR",
    "czech republic": "CZ",
    "czechia": "CZ",
    "denmark": "DK",
    "egypt": "EG",
    "estonia": "EE",
    "finland": "FI",
    "france": "FR",
    "georgia": "GE",
    "germany": "DE",
    "greece": "GR",
    "hong kong": "HK",
    "hungary": "HU",
    "iceland": "IS",
    "india": "IN",
    "indonesia": "ID",
    "ireland": "IE",
    "israel": "IL",
    "italy": "IT",
    "japan": "JP",
    "kazakhstan": "KZ",
    "korea": "KR",
    "kuwait": "KW",
    "latvia": "LV",
    "lithuania": "LT",
    "luxembourg": "LU",
    "malaysia": "MY",
    "mexico": "MX",
    "moldova": "MD",
    "mongolia": "MN",
    "myanmar": "MM",
    "nepal": "NP",
    "netherlands": "NL",
    "new zealand": "NZ",
    "norway": "NO",
    "pakistan": "PK",
    "philippines": "PH",
    "poland": "PL",
    "portugal": "PT",
    "qatar": "QA",
    "romania": "RO",
    "russia": "RU",
    "saudi arabia": "SA",
    "serbia": "RS",
    "singapore": "SG",
    "slovakia": "SK",
    "slovenia": "SI",
    "south africa": "ZA",
    "south korea": "KR",
    "spain": "ES",
    "sri lanka": "LK",
    "sweden": "SE",
    "switzerland": "CH",
    "taiwan": "TW",
    "thailand": "TH",
    "turkey": "TR",
    "turkiye": "TR",
    "uae": "AE",
    "uk": "GB",
    "ukraine": "UA",
    "united arab emirates": "AE",
    "united kingdom": "GB",
    "united states": "US",
    "usa": "US",
    "vietnam": "VN",
}

_FLAG_PAIR = re.compile("[\U0001f1e6-\U0001f1ff]{2}")
_BRACKETED = re.compile(r"[\[(\uff08{]\s*([A-Za-z]{2})\s*[\]\uff09}]")
_PREFIX = re.compile(r"^\s*([A-Za-z]{2})\s*(?:[|:\u00b7\u2022\u2013\u2014-]\s*|\s+)")
_SUFFIX = re.compile(r"\s+([A-Za-z]{2})\s*$")
_DELIMITED = re.compile(
    r"[|\u00b7\u2022\u2013\u2014]\s*([A-Za-z]{2})\s*(?=[|\u00b7\u2022\u2013\u2014]|$)"
)
_COUNTRY_NAME_PATTERN = re.compile(
    r"(?<![A-Za-z])("
    + "|".join(re.escape(name) for name in sorted(_COUNTRY_NAMES, key=len, reverse=True))
    + r")(?![A-Za-z])",
    re.IGNORECASE,
)


def _valid_code(value: str) -> str | None:
    """Return an upper-case ISO code, or None for unknown values."""
    code = value.upper()
    return code if code in _ISO_CODES else None


def _country_from_flag(name: str) -> str | None:
    """Decode the first regional-indicator flag in a display name."""
    for match in _FLAG_PAIR.finditer(name):
        code = "".join(chr(ord(character) - 0x1F1E6 + ord("A")) for character in match.group())
        if code in _ISO_CODES:
            return code
    return None


def infer_country(name: str) -> str:
    """Infer an ISO 3166-1 alpha-2 country code from a display name.

    Flags and explicit two-letter tags are recognized before English country
    names. Returns :data:`UNKNOWN_COUNTRY` when nothing can be inferred.
    """
    if not isinstance(name, str):
        raise LinkValidationError("display name must be a string")
    flag = _country_from_flag(name)
    if flag:
        return flag
    for pattern in (_BRACKETED, _PREFIX, _DELIMITED, _SUFFIX):
        for match in pattern.finditer(name):
            code = _valid_code(match.group(1))
            if code:
                return code
    country_match = _COUNTRY_NAME_PATTERN.search(name)
    if country_match:
        return _COUNTRY_NAMES[country_match.group(1).lower()]
    return UNKNOWN_COUNTRY


def country_for_record(record: Link) -> str:
    """Return the inferred country code for a parsed record."""
    return infer_country(record.name)


@dataclass(frozen=True)
class SummaryStats:
    """Aggregated counts for a collection of proxy records."""

    total: int
    unique_hosts: int
    by_protocol: dict[str, int]
    by_country: dict[str, int]
    by_country_protocol: dict[tuple[str, str], int]


def _country_sort_key(item: tuple[str, int]) -> tuple[bool, str]:
    country, _ = item
    return (country == UNKNOWN_COUNTRY, country)


def summarize_records(records: Iterable[Link]) -> SummaryStats:
    """Summarize records by protocol, country and country/protocol pair."""
    materialized = list(records)
    protocols: Counter[str] = Counter()
    countries: Counter[str] = Counter()
    groups: Counter[tuple[str, str]] = Counter()
    hosts: set[str] = set()
    for record in materialized:
        protocol = protocol_name(record)
        country = country_for_record(record)
        protocols[protocol] += 1
        countries[country] += 1
        groups[(country, protocol)] += 1
        hosts.add(record.host.lower())
    return SummaryStats(
        total=len(materialized),
        unique_hosts=len(hosts),
        by_protocol=dict(sorted(protocols.items())),
        by_country=dict(sorted(countries.items(), key=_country_sort_key)),
        by_country_protocol=dict(
            sorted(
                groups.items(),
                key=lambda item: (
                    _country_sort_key((item[0][0], 0)),
                    item[0][1],
                ),
            )
        ),
    )
