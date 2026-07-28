"""Shared PAN-OS normalization helpers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


# ---------------------------------------------------------------------------
# Provenance helpers — used across all PAN-OS normalizers
# ---------------------------------------------------------------------------

# Returned as raw_key when the payload key was absent entirely.
# Callers check `raw_key is ABSENT` to skip FieldProvenance row creation.
ABSENT = object()

_PROVENANCE_KEYS = ("@ptpl", "@loc", "@panorama")


def classify_prov_type(raw_key: str | None) -> str:
    """Map a raw PAN-OS provenance key to a FieldProvenance.ProvenanceType value."""
    if raw_key == "@ptpl":
        return "template"
    if raw_key == "@loc":
        return "device_group"
    if raw_key == "@panorama":
        return "panorama"
    return "local"


def scalar_value(node: Any) -> tuple[str, Any, str | None]:
    """Extract value and provenance from a PAN-OS scalar node.

    Returns (value, raw_key, raw_provenance_value) where:
    - raw_key is ABSENT if node is None (field absent from payload)
    - raw_key is None if the node is a plain string (locally configured)
    - raw_key is "@ptpl" | "@loc" | "@panorama" when a provenance marker is present
    """
    if node is None:
        return "", ABSENT, None
    if isinstance(node, dict):
        text = str(node.get("#text") or "").strip()
        for key in _PROVENANCE_KEYS:
            if key in node:
                return text, key, str(node[key] or "")
        return text, None, None
    return str(node).strip(), None, None


def parse_yes_no_field(
    node: Any,
    *,
    default_effective: bool,
) -> tuple[bool, Any, str | None]:
    """Parse a PAN-OS yes/no boolean scalar.

    Returns (effective_value, raw_key, raw_provenance_value).
    raw_key is ABSENT when the field was not present in the payload.
    """
    raw_value, raw_key, raw_prov = scalar_value(node)
    if not raw_value:
        return default_effective, raw_key, raw_prov
    return raw_value.lower() == "yes", raw_key, raw_prov


def parse_integer_field(
    node: Any,
    *,
    default_effective: int,
) -> tuple[int, Any, str | None]:
    """Parse a PAN-OS integer scalar.

    Returns (effective_value, raw_key, raw_provenance_value).
    raw_key is ABSENT when the field was not present in the payload.
    """
    raw_value, raw_key, raw_prov = scalar_value(node)
    if not raw_value:
        return default_effective, raw_key, raw_prov
    try:
        return int(raw_value), raw_key, raw_prov
    except ValueError:
        return default_effective, raw_key, raw_prov


def entry_provenance(entry: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return (raw_key, raw_value) for an entry's own provenance annotation.

    Checks @ptpl and @loc only. @panorama is intentionally excluded here
    because at the entry level it appears as the boolean flag "@panorama": "true"
    (a routing signal used by default_rule_source), not a provenance pointer.
    Scalar-level @panorama is handled by scalar_value().
    """
    for key in ("@ptpl", "@loc"):
        if key in entry:
            return key, str(entry[key] or "")
    return None, None


def iter_member_values(node: Any) -> list[tuple[str, str]]:
    """Return (value, prov_string) for each member in a PAN-OS member/entry list.

    prov_string is the raw @loc/@ptpl value, or "" for locally-defined members.
    Used for member and tag models that store provenance as a direct CharField,
    not as FieldProvenance rows.
    """
    if node is None:
        return []
    if isinstance(node, dict):
        node_prov = ""
        for key in _PROVENANCE_KEYS:
            if key in node:
                node_prov = str(node[key] or "")
                break

        # Handle entry-keyed lists (e.g. profile-setting entries)
        entries = node.get("entry")
        if entries is not None:
            values: list[tuple[str, str]] = []
            for item in ensure_list(entries):
                if isinstance(item, dict):
                    item_prov = node_prov
                    for key in _PROVENANCE_KEYS:
                        if key in item:
                            item_prov = str(item[key] or "")
                            break
                    values.append((str(item.get("#text") or item.get("@name") or ""), item_prov))
                else:
                    values.append((str(item), node_prov))
            return values

        # Standard member lists
        members = ensure_list(node.get("member"))
        values = []
        for member in members:
            if isinstance(member, dict):
                member_prov = node_prov
                for key in _PROVENANCE_KEYS:
                    if key in member:
                        member_prov = str(member[key] or "")
                        break
                values.append((str(member.get("#text") or ""), member_prov))
            else:
                values.append((str(member), node_prov))
        return values

    if isinstance(node, list):
        return [(str(m), "") for m in node]
    return [(str(node), "")]


def member_values(node: Any) -> list[tuple[str, str]]:
    """Alias for iter_member_values — used by address normalizer."""
    return iter_member_values(node)


# ---------------------------------------------------------------------------
# General structural helpers
# ---------------------------------------------------------------------------

def ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping/adjacent (start, end) integer intervals into the minimal sorted,
    disjoint set. Shared by dynamic_address_content.py (EDL/FQDN resolved entries) and
    security_rules.py (negate-complement computation) - lives here, not in either of those
    modules, so importing it doesn't create a cross-module dependency between them."""
    if not intervals:
        return []
    sorted_intervals = sorted(intervals)
    merged = [sorted_intervals[0]]
    for start, end in sorted_intervals[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def first_text(mapping: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        if isinstance(value, (str, int, float)):
            text = str(value).strip()
            if text:
                return text
    return ""


def iter_nested_entries(node: Any) -> Iterable[dict[str, Any]]:
    if isinstance(node, list):
        for item in node:
            yield from iter_nested_entries(item)
        return

    if not isinstance(node, dict):
        return

    if "entry" in node:
        for item in ensure_list(node["entry"]):
            if isinstance(item, dict):
                yield item

    for value in node.values():
        yield from iter_nested_entries(value)


# ---------------------------------------------------------------------------
# Payload structure helpers — shared across address and security rule normalizers
# ---------------------------------------------------------------------------

# Literal string returned by the PAN-OS API for show_pushed_shared_policy_vsys when a
# vsys has no Panorama device group assignment. This is a legitimate first-class state:
# a vsys can be fully operational with local rules on a Panorama-managed appliance.
# The vsys can still reference objects pushed to the device's shared scope by Panorama.
NO_PUSHED_POLICY_MESSAGE = "No shared policy pushed to device"


def merged_vsys_entry(payload: dict[str, Any], vsys_name: str) -> dict[str, Any]:
    """Return the named vsys entry dict from a show_merged_config payload."""
    config = payload.get("config", {})
    devices = config.get("devices", {}) if isinstance(config, dict) else {}
    device_entry = ensure_list(devices.get("entry"))[0] if isinstance(devices, dict) and ensure_list(devices.get("entry")) else {}
    vsys = device_entry.get("vsys", {}) if isinstance(device_entry, dict) else {}
    for entry in ensure_list(vsys.get("entry")) if isinstance(vsys, dict) else []:
        if isinstance(entry, dict) and entry.get("@name") == vsys_name:
            return entry
    return {}


def merged_shared(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the shared subtree from a show_merged_config payload."""
    config = payload.get("config", {})
    if not isinstance(config, dict):
        return {}
    shared = config.get("shared", {})
    return shared if isinstance(shared, dict) else {}


def pushed_shared(payload: dict[str, Any] | Any) -> dict[str, Any]:
    """Extract the shared subtree from a show_pushed_shared_policy payload."""
    if not isinstance(payload, dict):
        raise ValueError(f"unexpected pushed shared payload type: {type(payload).__name__}")
    shared = payload.get("shared", {})
    if not isinstance(shared, dict):
        raise ValueError(f"unexpected pushed shared subtree type: {type(shared).__name__}")
    return shared


def pushed_vsys_panorama(payload: dict[str, Any] | Any) -> dict[str, Any]:
    """Extract the panorama subtree from a show_pushed_shared_policy_vsys payload.

    Returns {} when payload is NO_PUSHED_POLICY_MESSAGE (vsys has no device group
    assignment in Panorama — a legitimate operational state, not an error).
    """
    if payload == NO_PUSHED_POLICY_MESSAGE:
        return {}
    if not isinstance(payload, dict):
        raise ValueError(f"unexpected pushed policy payload type: {type(payload).__name__}")
    policy = payload.get("policy", {})
    if not isinstance(policy, dict):
        raise ValueError(f"unexpected pushed policy root type: {type(policy).__name__}")
    panorama = policy.get("panorama", {})
    if not isinstance(panorama, dict):
        raise ValueError(f"unexpected pushed panorama subtree type: {type(panorama).__name__}")
    return panorama


# ---------------------------------------------------------------------------
# Builtin region codes — used by security-rule address-ref resolution
# ---------------------------------------------------------------------------

# PAN-OS lets a rule's source/destination address list reference a country/region
# directly by its ISO 3166-1 alpha-2 code (e.g. "BY" for Belarus), resolved against an
# internal geo-IP database rather than any configured object. That database isn't
# exposed via any <show><config> xpath (merged, pushed-shared-policy, or the vsys
# variant), so there's nothing to collect from the device — this is a static reference
# table instead. Only codes appearing here are treated as a builtin region reference;
# anything else still surfaces as an unresolved-address-reference failure.
ISO_3166_1_ALPHA2_REGIONS: dict[str, str] = {
    "AD": "Andorra",
    "AE": "United Arab Emirates",
    "AF": "Afghanistan",
    "AG": "Antigua and Barbuda",
    "AI": "Anguilla",
    "AL": "Albania",
    "AM": "Armenia",
    "AO": "Angola",
    "AQ": "Antarctica",
    "AR": "Argentina",
    "AS": "American Samoa",
    "AT": "Austria",
    "AU": "Australia",
    "AW": "Aruba",
    "AX": "Aland Islands",
    "AZ": "Azerbaijan",
    "BA": "Bosnia and Herzegovina",
    "BB": "Barbados",
    "BD": "Bangladesh",
    "BE": "Belgium",
    "BF": "Burkina Faso",
    "BG": "Bulgaria",
    "BH": "Bahrain",
    "BI": "Burundi",
    "BJ": "Benin",
    "BL": "Saint Barthelemy",
    "BM": "Bermuda",
    "BN": "Brunei Darussalam",
    "BO": "Bolivia",
    "BQ": "Bonaire, Sint Eustatius and Saba",
    "BR": "Brazil",
    "BS": "Bahamas",
    "BT": "Bhutan",
    "BV": "Bouvet Island",
    "BW": "Botswana",
    "BY": "Belarus",
    "BZ": "Belize",
    "CA": "Canada",
    "CC": "Cocos (Keeling) Islands",
    "CD": "Congo, Democratic Republic of the",
    "CF": "Central African Republic",
    "CG": "Congo",
    "CH": "Switzerland",
    "CI": "Cote d'Ivoire",
    "CK": "Cook Islands",
    "CL": "Chile",
    "CM": "Cameroon",
    "CN": "China",
    "CO": "Colombia",
    "CR": "Costa Rica",
    "CU": "Cuba",
    "CV": "Cabo Verde",
    "CW": "Curacao",
    "CX": "Christmas Island",
    "CY": "Cyprus",
    "CZ": "Czechia",
    "DE": "Germany",
    "DJ": "Djibouti",
    "DK": "Denmark",
    "DM": "Dominica",
    "DO": "Dominican Republic",
    "DZ": "Algeria",
    "EC": "Ecuador",
    "EE": "Estonia",
    "EG": "Egypt",
    "EH": "Western Sahara",
    "ER": "Eritrea",
    "ES": "Spain",
    "ET": "Ethiopia",
    "FI": "Finland",
    "FJ": "Fiji",
    "FK": "Falkland Islands (Malvinas)",
    "FM": "Micronesia, Federated States of",
    "FO": "Faroe Islands",
    "FR": "France",
    "GA": "Gabon",
    "GB": "United Kingdom",
    "GD": "Grenada",
    "GE": "Georgia",
    "GF": "French Guiana",
    "GG": "Guernsey",
    "GH": "Ghana",
    "GI": "Gibraltar",
    "GL": "Greenland",
    "GM": "Gambia",
    "GN": "Guinea",
    "GP": "Guadeloupe",
    "GQ": "Equatorial Guinea",
    "GR": "Greece",
    "GS": "South Georgia and the South Sandwich Islands",
    "GT": "Guatemala",
    "GU": "Guam",
    "GW": "Guinea-Bissau",
    "GY": "Guyana",
    "HK": "Hong Kong",
    "HM": "Heard Island and McDonald Islands",
    "HN": "Honduras",
    "HR": "Croatia",
    "HT": "Haiti",
    "HU": "Hungary",
    "ID": "Indonesia",
    "IE": "Ireland",
    "IL": "Israel",
    "IM": "Isle of Man",
    "IN": "India",
    "IO": "British Indian Ocean Territory",
    "IQ": "Iraq",
    "IR": "Iran",
    "IS": "Iceland",
    "IT": "Italy",
    "JE": "Jersey",
    "JM": "Jamaica",
    "JO": "Jordan",
    "JP": "Japan",
    "KE": "Kenya",
    "KG": "Kyrgyzstan",
    "KH": "Cambodia",
    "KI": "Kiribati",
    "KM": "Comoros",
    "KN": "Saint Kitts and Nevis",
    "KP": "Korea, Democratic People's Republic of",
    "KR": "Korea, Republic of",
    "KW": "Kuwait",
    "KY": "Cayman Islands",
    "KZ": "Kazakhstan",
    "LA": "Lao People's Democratic Republic",
    "LB": "Lebanon",
    "LC": "Saint Lucia",
    "LI": "Liechtenstein",
    "LK": "Sri Lanka",
    "LR": "Liberia",
    "LS": "Lesotho",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "LV": "Latvia",
    "LY": "Libya",
    "MA": "Morocco",
    "MC": "Monaco",
    "MD": "Moldova",
    "ME": "Montenegro",
    "MF": "Saint Martin (French part)",
    "MG": "Madagascar",
    "MH": "Marshall Islands",
    "MK": "North Macedonia",
    "ML": "Mali",
    "MM": "Myanmar",
    "MN": "Mongolia",
    "MO": "Macao",
    "MP": "Northern Mariana Islands",
    "MQ": "Martinique",
    "MR": "Mauritania",
    "MS": "Montserrat",
    "MT": "Malta",
    "MU": "Mauritius",
    "MV": "Maldives",
    "MW": "Malawi",
    "MX": "Mexico",
    "MY": "Malaysia",
    "MZ": "Mozambique",
    "NA": "Namibia",
    "NC": "New Caledonia",
    "NE": "Niger",
    "NF": "Norfolk Island",
    "NG": "Nigeria",
    "NI": "Nicaragua",
    "NL": "Netherlands",
    "NO": "Norway",
    "NP": "Nepal",
    "NR": "Nauru",
    "NU": "Niue",
    "NZ": "New Zealand",
    "OM": "Oman",
    "PA": "Panama",
    "PE": "Peru",
    "PF": "French Polynesia",
    "PG": "Papua New Guinea",
    "PH": "Philippines",
    "PK": "Pakistan",
    "PL": "Poland",
    "PM": "Saint Pierre and Miquelon",
    "PN": "Pitcairn",
    "PR": "Puerto Rico",
    "PS": "Palestine, State of",
    "PT": "Portugal",
    "PW": "Palau",
    "PY": "Paraguay",
    "QA": "Qatar",
    "RE": "Reunion",
    "RO": "Romania",
    "RS": "Serbia",
    "RU": "Russian Federation",
    "RW": "Rwanda",
    "SA": "Saudi Arabia",
    "SB": "Solomon Islands",
    "SC": "Seychelles",
    "SD": "Sudan",
    "SE": "Sweden",
    "SG": "Singapore",
    "SH": "Saint Helena, Ascension and Tristan da Cunha",
    "SI": "Slovenia",
    "SJ": "Svalbard and Jan Mayen",
    "SK": "Slovakia",
    "SL": "Sierra Leone",
    "SM": "San Marino",
    "SN": "Senegal",
    "SO": "Somalia",
    "SR": "Suriname",
    "SS": "South Sudan",
    "ST": "Sao Tome and Principe",
    "SV": "El Salvador",
    "SX": "Sint Maarten (Dutch part)",
    "SY": "Syrian Arab Republic",
    "SZ": "Eswatini",
    "TC": "Turks and Caicos Islands",
    "TD": "Chad",
    "TF": "French Southern Territories",
    "TG": "Togo",
    "TH": "Thailand",
    "TJ": "Tajikistan",
    "TK": "Tokelau",
    "TL": "Timor-Leste",
    "TM": "Turkmenistan",
    "TN": "Tunisia",
    "TO": "Tonga",
    "TR": "Turkey",
    "TT": "Trinidad and Tobago",
    "TV": "Tuvalu",
    "TW": "Taiwan",
    "TZ": "Tanzania, United Republic of",
    "UA": "Ukraine",
    "UG": "Uganda",
    "UM": "United States Minor Outlying Islands",
    "US": "United States",
    "UY": "Uruguay",
    "UZ": "Uzbekistan",
    "VA": "Holy See",
    "VC": "Saint Vincent and the Grenadines",
    "VE": "Venezuela",
    "VG": "Virgin Islands, British",
    "VI": "Virgin Islands, U.S.",
    "VN": "Viet Nam",
    "VU": "Vanuatu",
    "WF": "Wallis and Futuna",
    "WS": "Samoa",
    "YE": "Yemen",
    "YT": "Mayotte",
    "ZA": "South Africa",
    "ZM": "Zambia",
    "ZW": "Zimbabwe",
}

# Palo Alto's builtin region namespace is ISO-derived but not strictly current ISO
# 3166-1: it retains a withdrawn code for legacy IP ranges, and adds several
# vendor-specific pseudo-country codes for geolocation cases that don't map to a real
# country. Kept separate from the table above so that one stays a clean, verifiable
# mirror of the current ISO 3166-1 standard. Add entries here (not above) as real rules
# are found referencing a code neither table covers yet.
PANOS_VENDOR_REGION_CODES: dict[str, str] = {
    # Withdrawn ISO 3166-1 code, retained by PAN-OS: Netherlands Antilles dissolved in
    # 2010 into BQ/CW/SX, but PAN-OS still emits AN for IP ranges not yet reclassified.
    "AN": "Netherlands Antilles (withdrawn ISO code)",
    # Vendor-specific geolocation fallback classifications - not ISO 3166-1 codes, and
    # (per Palo Alto's own documentation) AP/EU are fallback classifications rather than
    # geographic supersets of their member countries.
    "A1": "Anonymous Proxy",
    "A2": "Satellite Provider",
    "AP": "Asia Pacific",
    "EU": "European Union",
    # Vendor-specific codes for contested Ukrainian territories, not ISO 3166-1 codes.
    "CE": "Crimea",
    "DN": "Donetsk",
    "LN": "Luhansk",
    # User-assigned code (ISO 3166-1 user-assigned range, not officially allocated) for
    # Kosovo, widely used by PAN-OS and other vendors pending an official ISO allocation.
    "XK": "Kosovo",
}
