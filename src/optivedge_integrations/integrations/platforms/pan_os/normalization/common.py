"""Shared PAN-OS normalization helpers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Provenance helpers — used across all PAN-OS normalizers
# ---------------------------------------------------------------------------

# Returned as raw_key when the payload key was absent entirely AND the caller declared no
# implicit value. Callers check `raw_key is ABSENT` to skip FieldProvenance row creation - it
# means the field is not tracked, which is now the ONLY thing a missing row means.
ABSENT = object()

_PROVENANCE_KEYS = ("@ptpl", "@loc", "@panorama")


@dataclass(frozen=True)
class Implicit:
    """What PAN-OS does when a key is absent - and whether we KNOW or are inferring.

    Every site that stores a value for an absent key makes a claim about the vendor's behaviour.
    Before 2026-09-21 that claim was a bare `default_effective=False` with nothing saying where
    it came from, and an audit of all 33 sites found three kinds mixed together: defaults
    measured on hardware and recorded in the payload contract, defaults documented in a vendor
    guide, and defaults nobody had ever checked - including `log-start` and `log-end`, which
    `read-a-security-rule.md` explicitly says must be measured rather than assumed.

    So the constructor is not available: a site uses `Implicit.measured(value, citation)` or
    `Implicit.assumed(value, why)` and cannot avoid saying which. The citation travels in code
    next to the value it justifies, rather than in a database column that would copy a constant
    and then drift from it.
    """

    value: Any
    #: Where the measurement is recorded. None means nobody has measured it.
    citation: str | None
    #: Why we infer this value, for an assumed default. Empty for a measured one.
    reasoning: str = ""

    def __post_init__(self):
        # On the type rather than only in the two constructors below, because `Implicit(x, "")`
        # would otherwise reach a provenance row as a measured default carrying no measurement.
        if self.citation is None and not self.reasoning:
            raise ValueError(
                f"Implicit({self.value!r}) states neither a citation nor what the inference "
                f"rests on. Use Implicit.measured() or Implicit.assumed().")
        if self.citation is not None and len(self.citation) < 12:
            raise ValueError(f"Implicit({self.value!r}) citation is too short to check")

    @classmethod
    def measured(cls, value: Any, citation: str) -> "Implicit":
        """A default someone established, naming where it is written down.

        The citation is required and must be specific enough to check - a payload contract node
        and field, a guide and its statement, or a dated measurement. "PAN-OS docs" is not a
        citation; a reader cannot go and disagree with it.
        """
        if not citation or len(citation) < 12:
            raise ValueError(
                f"Implicit.measured({value!r}) needs a citation a reader can check, not "
                f"{citation!r}. If nobody has measured it, that is Implicit.assumed().")
        return cls(value=value, citation=citation)

    @classmethod
    def assumed(cls, value: Any, why: str) -> "Implicit":
        """A default we infer. Honest, and never to be presented as a vendor fact.

        `why` says what the inference rests on - the neighbouring keys' polarity, the UI, a
        vendor statement about a different field - so that whoever measures it later knows what
        they are testing against.
        """
        if not why:
            raise ValueError(f"Implicit.assumed({value!r}) must say what the inference rests on")
        return cls(value=value, citation=None, reasoning=why)

    @classmethod
    def not_assumed(cls, why: str) -> "Implicit":
        """Absent, and normalization stores NOTHING rather than guess.

        The field ends up null and the provenance row says so. This is the right declaration
        wherever a wrong guess would be worse than no answer - the security rule log flags,
        where the corpus says the defaults are unmeasured and a control turns on them.
        """
        if not why:
            raise ValueError("Implicit.not_assumed() must say why nothing is assumed")
        return cls(value=None, citation=None, reasoning=why)

    @property
    def stores_nothing(self) -> bool:
        return self.citation is None and self.value is None

    @property
    def provenance_type(self) -> str:
        if self.citation:
            return "pan_os_default"
        return "not_configured" if self.stores_nothing else "assumed_default"


def was_absent(raw_key: Any) -> bool:
    """Did the payload carry this key at all?

    Callers used to ask `raw_key is ABSENT`, which stopped being the whole answer on 2026-09-21
    when an absent key started coming back as an `Implicit` instead. Two lines in the security
    rule normalizer asked the old question and would have turned the log flags from null into
    False - silently, on the two fields the corpus says must not be assumed. Ask this instead.
    """
    return raw_key is ABSENT or isinstance(raw_key, Implicit)


def classify_prov_type(raw_key: Any) -> str:
    """Map a raw PAN-OS provenance key to a FieldProvenance.ProvenanceType value.

    An `Implicit` arrives here when the key was ABSENT and the reading site declared what PAN-OS
    does without it; it classifies as the measured or assumed default according to its own
    citation, which is the one place that decision is made.
    """
    if isinstance(raw_key, Implicit):
        return raw_key.provenance_type
    if raw_key == "@ptpl":
        return "template"
    if raw_key == "@loc":
        return "device_group"
    if raw_key == "@panorama":
        return "panorama"
    return "local"


def provenance_value(raw_key: Any, raw_value: str | None) -> str:
    """What goes in `FieldProvenance.raw_value`.

    For a present key that is the marker's value - the template name, the device group. For an
    absent key it is the defaulted VALUE, so a reader of the row can see what was assumed
    without resolving the field on the object.
    """
    if isinstance(raw_key, Implicit):
        return _as_text(raw_key.value)
    return raw_value or ""


def provenance_raw_key(raw_key: Any) -> str:
    """The payload key a row came from. Empty for a default: there was no key."""
    if isinstance(raw_key, Implicit) or raw_key is ABSENT or raw_key is None:
        return ""
    return str(raw_key)


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    return "" if value is None else str(value)


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


def parse_yes_no_field(node: Any, *, implicit: Implicit) -> tuple[bool, Any, str | None]:
    """Parse a PAN-OS yes/no boolean scalar.

    Returns (effective_value, raw_key, raw_provenance_value). When the key was ABSENT the
    returned raw_key is the `implicit` declaration itself, so the provenance row records WHY the
    stored value is what it is - measured vendor default or our inference - instead of the row
    being skipped, which is what made those two indistinguishable until 2026-09-21.

    `implicit` replaced `default_effective` and is deliberately not optional: storing a value for
    an absent key is a claim about PAN-OS, and every site now has to say whether it can back it.
    """
    raw_value, raw_key, raw_prov = scalar_value(node)
    if raw_key is ABSENT:
        return implicit.value, implicit, None
    if not raw_value:
        # The key is PRESENT and carries no text. The value falls back to the implicit one, but
        # the provenance is the key's own - something wrote this element, and saying "default"
        # about a node the payload contains would hide that.
        return implicit.value, raw_key, raw_prov
    return raw_value.lower() == "yes", raw_key, raw_prov


def parse_integer_field(node: Any, *, implicit: Implicit) -> tuple[int, Any, str | None]:
    """Parse a PAN-OS integer scalar. See `parse_yes_no_field` for the `implicit` contract."""
    raw_value, raw_key, raw_prov = scalar_value(node)
    if raw_key is ABSENT:
        return implicit.value, implicit, None
    if not raw_value:
        return implicit.value, raw_key, raw_prov
    try:
        return int(raw_value), raw_key, raw_prov
    except ValueError:
        # Present and unparseable. The value falls back, the provenance stays the key's: the
        # device does hold something here, and it is not a default.
        return implicit.value, raw_key, raw_prov


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


SHARED_LOC = "shared"


def pushed_entry_scope(entry: dict[str, Any], vsys_name: str) -> tuple[str, str]:
    """Return (namespace_type, namespace_value) for a Panorama-pushed entry, from @loc.

    Scope MUST come from @loc, never from which query returned the entry. On a
    single-vsys firewall the vsys and non-vsys pushed responses are byte-identical, so
    read position classifies every Panorama-Shared object as vsys-scoped - which then
    wrongly outranks a local shared object of the same name. Measured on both lab
    devices: the PA-VM's non-vsys read carries a device-group object, and the PA-5220's
    per-vsys read carries only device-group objects.

        @loc == "shared"        -> shared scope, PANORAMA_SHARED
        @loc == <device group>  -> vsys scope,   PUSHED_VSYS_EFFECTIVE

    namespace_value is the vsys name for device-group objects, not the device-group
    name: @loc names where the object was *authored* in the Panorama hierarchy, not the
    namespace it occupies on the firewall. The authoring location is recorded separately
    as FieldProvenance via entry_provenance().

    An absent @loc falls back to VSYS scope. This used to raise, on the grounds that all
    398 pushed entries across both lab devices carried one, so absence was unobserved and
    guessing looked worse than failing. Absence is observed now: an Azure cloud firewall
    pushes `azure-healthcheck-address` with no marker, and the raise took down the whole
    address build for that enforcement point - 242 objects and every rule on it - over one
    plugin-injected entry.

    Vsys is the conservative fallback. It is the narrower scope, so an unmarked entry
    cannot leak across the other vsys of a group the way a wrong shared classification
    would; the cost is that an unmarked object appearing in the group-wide read is stored
    once per point instead of once. It is also what the pre-@loc code effectively did for
    entries from the per-vsys read.

    Callers that need to know use `pushed_entry_is_unmarked()` - the fallback must stay
    visible rather than becoming another silent inference.
    """
    # Imported here to avoid a circular import: models.policy imports from this package.
    from optivedge_integrations.integrations.models.policy.base import PolicyObjectNamespace

    raw_key, raw_value = entry_provenance(entry)
    if raw_key != "@loc" or not raw_value:
        return PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE, vsys_name
    if raw_value == SHARED_LOC:
        return PolicyObjectNamespace.PANORAMA_SHARED, SHARED_LOC
    return PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE, vsys_name


def pushed_entry_is_unmarked(entry: dict[str, Any]) -> bool:
    """Whether a pushed entry lacks the @loc marker that would fix its scope.

    Separate from pushed_entry_scope() so the fallback can be reported without repeating
    the classification rule. Diagnostics surface these; normalization does not fail on
    them, because failing one point's entire build over a single vendor-injected object
    is out of proportion to not knowing its scope.
    """
    raw_key, raw_value = entry_provenance(entry)
    return raw_key != "@loc" or not raw_value


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
    """Extract the object-bearing subtree from a show_pushed_shared_policy payload.

    The non-vsys response roots differently by device, so both shapes are accepted:

        result.shared            multi-vsys PA-5220, 11.1.13-h3
        result.policy.panorama   single-vsys PA-VM,  11.2.3

    Do not branch on device type to pick one. Two samples cannot separate model,
    version and vsys mode, and the @loc classification downstream makes the
    distinction unnecessary anyway - scope comes from the marker, not the root.

    Reading only `shared` returned {} silently on the PA-VM. No objects were lost
    there only because its two pushed reads are byte-identical, so the per-vsys read
    caught what this one dropped - luck, not design. A device with this shape AND
    genuine separation between the two reads (the PA-5220 has such separation:
    shared-object optimization keeps its 176 Shared objects out of every per-vsys
    response) would lose every Panorama-Shared object with no error at all.

    A dict carrying neither root raises rather than yielding {}: an unrecognised
    shape is not evidence of an empty one.

    DELIBERATELY ASYMMETRIC with pushed_vsys_panorama(): that one absorbs
    NO_PUSHED_POLICY_MESSAGE and returns {}, this one raises on any non-dict payload.
    Do not "align" them - they answer different questions.

    A vsys with no device-group assignment having nothing pushed is an ordinary, measured
    state, so the per-vsys reader is right to absorb it. A Panorama-managed device
    answering the DEVICE-WIDE shared query with something that is not config data has
    never been observed, and nothing establishes it would be benign - it fits a lost
    Panorama association or a query sent to the wrong target just as well as an empty
    result. Returning {} here would turn an unexplained response into a confident "this
    device has no shared objects", silently dropping every Panorama-Shared object for the
    enforcement point.

    If this ever raises in the field, the exception is the observation - which is why the
    payload value is included below, not just its type.
    """
    if not isinstance(payload, dict):
        raise ValueError(
            f"unexpected pushed shared payload type: {type(payload).__name__}: {payload!r}"
        )

    if "shared" in payload:
        shared = payload["shared"]
        if not isinstance(shared, dict):
            raise ValueError(f"unexpected pushed shared subtree type: {type(shared).__name__}")
        return shared

    policy = payload.get("policy")
    if isinstance(policy, dict) and "panorama" in policy:
        panorama = policy["panorama"]
        if not isinstance(panorama, dict):
            raise ValueError(f"unexpected pushed panorama subtree type: {type(panorama).__name__}")
        return panorama

    raise ValueError(
        f"unrecognised pushed shared payload root: expected 'shared' or 'policy.panorama', "
        f"got keys {sorted(payload)}"
    )


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


def merge_pushed_entries(
    reads: list[tuple[dict[str, Any], Any]],
    kind: str,
    *,
    vsys_name: str,
    label: str,
) -> list[tuple[dict[str, Any], Any, str, str]]:
    """Merge the pushed reads into one scope-classified set of `kind` entries.

    `reads` is [(payload_root, source_snapshot), ...] - the non-vsys and per-vsys
    pushed-shared-policy responses. Both are views of the same pushed policy, and which
    objects each carries depends on the device rather than on the scope being asked
    about, so they are merged and then classified per entry by @loc.

    Deduplication is keyed by (name, namespace_type, namespace_value) - the object's
    identity on the firewall. That key handles both measured cases with no special-casing:

    - Single-vsys (PA-VM): the two responses are byte-identical, so every object arrives
      twice with the same @loc -> same key -> one row. Classifying by read position
      instead put the same object in two different scopes.
    - Multi-vsys (PA-5220): a name defined in both Panorama Shared and a device group is
      delivered twice with *different* @loc -> different keys -> two rows. That is a
      legitimate cross-scope override pair; collapsing it would discard the losing
      definition and hide the override.

    A collision whose entries differ is neither case and raises: two disagreeing
    definitions of one object in one scope is a state PAN-OS rejects, so it can only mean
    a collection or classification fault.

    Returns ([(entry, source_snapshot, namespace_type, namespace_value), ...], conflicts)
    with the first read winning and insertion order preserved, so output stays
    reproducible. `notes` is [(severity, reason, entry), ...] - names the two reads disagree
    about (an error: two views of one policy cannot legitimately differ), and entries with
    no @loc (a warning: an observed state whose scope is a documented fallback). Both are
    reported per entry rather than raised, since neither should discard every pushed
    object for the enforcement point.
    """
    merged: dict[tuple[str, str, str], tuple[dict[str, Any], Any, str, str]] = {}
    notes: list[tuple[str, str, dict[str, Any]]] = []  # (severity, reason, entry)
    for root, snapshot in reads:
        node = root.get(kind)
        if not isinstance(node, dict):
            continue
        for entry in ensure_list(node.get("entry")):
            if not isinstance(entry, dict):
                continue
            if pushed_entry_is_unmarked(entry):
                # A real, observed state - see pushed_entry_scope(). The object is kept;
                # only its scope is a fallback, so this is a warning, not a fault.
                notes.append((
                    "warning",
                    f"pushed {kind} {entry.get('@name')!r} carries no @loc, so its scope "
                    f"cannot be read from the payload; falling back to vsys scope",
                    entry,
                ))
            namespace_type, namespace_value = pushed_entry_scope(entry, vsys_name)
            key = (str(entry.get("@name") or ""), str(namespace_type), namespace_value)
            existing = merged.get(key)
            if existing is None:
                merged[key] = (entry, snapshot, namespace_type, namespace_value)
                continue
            if existing[0] != entry:
                # Scoped to this name rather than raised. One disagreeing definition used
                # to discard every pushed object for the point, which misattributes the
                # fault to whatever a rule happened to reference first.
                notes.append((
                    "error",
                    f"the two pushed reads disagree about {kind} {'/'.join(key)} on {label}. "
                    f"They are two views of one pushed policy, so they cannot legitimately "
                    f"differ - this indicates a collection fault. Keeping the first, because "
                    f"dropping it would fail every rule referencing it.",
                    entry,
                ))
    return list(merged.values()), notes
