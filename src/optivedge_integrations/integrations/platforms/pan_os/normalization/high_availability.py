"""One appliance's high-availability relationship - PAN-HAP-001 to 004.

TWO READS, AND THE SECOND ONE IS WHAT THE CONTROLS ACTUALLY TURN ON.

  - `show config merged` supplies `deviceconfig/high-availability`: every configuration column.
  - `show high-availability all` supplies the runtime half. Whether a peer is answering, whether
    state is being exchanged, whether the control link is really encrypted, and
    `ha1-encrypt-imported`, which has no configuration node anywhere.

Until the second collector runs on an estate, every verdict that rests on it holds its FIRING
default and `ha_runtime_state_collected` is false - which is what tells a reader "we have not
established a live peer" apart from "this appliance has no live peer". The direction is
deliberate and is `rules.md`'s: a missing reading reported as compliant is a customer told they
are safe on the strength of nothing.

THE MONITORING ENABLES READ `yes` WITH THE KEYS ABSENT, measured in both directions on
fw-core-tpa-a across commit jobs 538 and 539 (2026-10-26). So they are stored as the vendor fact
they are and NOTHING CLAUSES ON THEM; `ha_monitors_nothing` is the verdict PAN-HAP-004 reads, and
it asks whether any interface or destination is actually under monitoring.

THE `interface/ha1-backup` CONTAINER IS PRESENT AND EMPTY on both PA-5220s - it answers as a key
with a null value in all three config views while `port`, `ip-address` and `netmask` are all
absent beneath it. `if node:` at that container reports a backup control link that does not
exist, so this module tests for the KEY and never for the node's truthiness, and the container's
presence is what puts this estate in the `backup-link-without-peer-address` band.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, HighAvailabilityConfig, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    choice_child,
    classify_prov_type,
    ensure_list,
    parse_text_field,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot, latest_merged_snapshot)

#: `enabled` absent means the appliance is in NO HA relationship. The one implicit on this node
#: with a measured value: `show high-availability state` answers `enabled: no` where the key is
#: absent and `enabled: yes` where it is present and yes, read on all four lab appliances in one
#: pass. Confirmed again 2026-10-29 on both PA-VMs, which hold no node and answer `enabled: no`.
HA_DISABLED = Implicit.measured(
    False,
    "stage4-ha-panorama.json, firewall-high-availability field `enabled`: `show "
    "high-availability state` answers `enabled: no` where the key is absent and `enabled: yes` "
    "where it is present, read on all four lab appliances 2026-10-26 and again 2026-10-29")

#: The two monitoring enables. ABSENT MEANS ENABLED, which is the vendor telling the truth and
#: useless as a test: `show high-availability state` answers `enabled: yes` with `groups: null`
#: on an appliance whose configuration holds no `group/monitoring` node at all.
MONITORING_ENABLED_BY_DEFAULT = Implicit.measured(
    True,
    "stage4-ha-panorama.json, firewall-high-availability fields "
    "`group/monitoring/{link,path}-monitoring/enabled`: positive control paid in BOTH "
    "directions on fw-core-tpa-a 2026-10-26 - staged `enabled: no` left the oracle at `yes`, "
    "commit job 538 moved it to `no`, deleting `group/monitoring` and commit job 539 returned "
    "it to `yes`, with all three config views back to their pre-experiment answers")

#: Every switch below is `not_assumed`, each for its own measured reason, and together they are
#: why this model has five nullable booleans. `Implicit.not_assumed` stores None and writes a
#: `not_configured` provenance row saying why - "the field is null and we say why".
CLUSTER_UNMEASURED = Implicit.not_assumed(
    "`show high-availability cluster` was never asked, so nothing distinguishes 'not a cluster "
    "member' from 'this read does not report clusters'. Storing a guess would decide "
    "PAN-HAP-001's cluster branch on nothing")
CONFIG_SYNC_UNMEASURED = Implicit.not_assumed(
    "no appliance in the estate lacks `group/configuration-synchronization/enabled`, so the "
    "absent state was never available, and deleting it on a live pair was outside what the "
    "measuring run would do")
STATE_SYNC_UNMEASURED = Implicit.not_assumed(
    "`group/state-synchronization/enabled` is present on every appliance that has the node, so "
    "the absent state does not occur in this estate")
HA1_ENCRYPTION_UNMEASURED = Implicit.not_assumed(
    "the positive control cannot be paid at any price short of importing an HA key onto both "
    "members: `validate full` job 535 returned FAIL with 'High-availability ha1 encryption "
    "requires an import of the high-availability-key(Module: ha_agent)', so the value can never "
    "be committed and the oracle can never be moved off `no`. A control that cannot be paid is "
    "a finding about the node rather than a reason to promote a good reading")
HEARTBEAT_BACKUP_UNMEASURED = Implicit.not_assumed(
    "`show high-availability state` carries `heartbeat-interval` but no key reporting whether "
    "the management-port backup path is in use, so there is no oracle for this value and no "
    "control to pay. The position answers `code=6 Invalid sequence` on a PA-VM, where "
    "`group/election-option` has three children rather than four")
HA1_BACKUP_PORT_UNMEASURED = Implicit.not_assumed(
    "the operational oracle has no field for the backup control link's port, so there was "
    "nothing to move and no oracle to move it in, and writing a port here would give a live "
    "pair a second control path it is not cabled for")
PEER_IP_BACKUP_UNMEASURED = Implicit.not_assumed(
    "no oracle reports `group/peer-ip-backup`, and writing an address for a peer the pair is "
    "not cabled to on a live Active-Passive pair was judged the wrong experiment")
FAILURE_CONDITION_UNMEASURED = Implicit.not_assumed(
    "`action=complete` was never asked at this leaf and the key sat at `any` through both arms "
    "of the monitoring experiment, which makes it a stable reading and not a controlled one. "
    "Help p.811 documents `Any-(default)`, which is the vendor saying so and not a measurement")
HA_MODE_UNMEASURED = Implicit.not_assumed(
    "both arms of the natural experiment carry the same value, so the oracle never moved and "
    "what looks like a positive control is two readings of one answer. The vendor's absent-key "
    "reading is almost certainly active-passive - fw-core-tpa-b holds no `mode` key while the "
    "runtime read answers `mode: Active-Passive` - but that reading was not controlled")
#: `ha1-encrypt-imported` is a key of an OPERATIONAL REPLY and is never absent FROM that reply -
#: it is present with a value on all four lab appliances, including the two where HA is off
#: entirely. A null in the column means the REPLY was not collected, which is what
#: `ha_runtime_state_collected` records, and this declaration is what the parser needs to
#: produce that null rather than False. NO PROVENANCE ROW IS WRITTEN FROM IT: see the note in
#: `HighAvailabilityConfig.DERIVED_FIELDS`. The first readback of this stage wrote one and it
#: classified as `local`, which asserts an administrator configured a key that has no
#: configuration node anywhere - found by comparing stored provenance against the device on all
#: four appliances, not by a test.
KEY_IMPORTED_UNCOLLECTED = Implicit.not_assumed(
    "`ha1-encrypt-imported` is a key of an OPERATIONAL REPLY and is never absent FROM that "
    "reply - it is present with a value on all four lab appliances, including the two where HA "
    "is off entirely. Null here means the reply itself was not collected, which is what "
    "`ha_runtime_state_collected` records")

#: `show high-availability all`'s own view of whether the pair is exchanging STATE. Measured
#: 2026-10-29 on both PA-5220s: `User-disabled`, with `state-synchronization/enabled: no` in the
#: configuration - so the two agree here, and neither of them is "synchronized".
_STATE_SYNC_EXCHANGING = ("synchronized", "sync enabled", "enabled")
#: What `group/local-info/state` reads on a member that is carrying or ready to carry traffic.
#: `suspended`, `non-functional` and `initial` are NOT in it: a suspended member has no live
#: redundant peer however healthy the link looks.
_LIVE_LOCAL_STATES = ("active", "passive", "active-primary", "active-secondary")


def latest_high_availability_snapshot(appliance: Appliance) -> Snapshot | None:
    """The newest `show high-availability all` reply for this appliance, or None.

    None is the state of every estate until the collector runs, and it is not an error: it is
    what `ha_runtime_state_collected` reports. Shaped like
    `log_settings.latest_logging_status_snapshot`, which is the precedent for an op-command
    source type read back per appliance.
    """
    return (
        Snapshot.objects.filter(appliance=appliance, source_type="show_high_availability_all")
        .order_by("-collected_at", "-pk")
        .first()
    )


def _runtime(snapshot: Snapshot | None) -> dict[str, Any]:
    """The runtime reply's useful middle, or {} when nobody collected it.

    The payload is `{"response": {"result": {...}}}` as persisted, and the result is what
    `show high-availability all` returns: `enabled`, and a `group` carrying `local-info`,
    `peer-info`, `link-monitoring`, `path-monitoring`, `running-sync` and
    `running-sync-enabled`. An appliance with HA off answers a SHORT reply rather than nothing -
    `{"enabled": "no", "group": {"local-info": {"ha1-encrypt-imported": "no"}}}` - so an empty
    `group` is a real reading and not a failed one.
    """
    if snapshot is None:
        return {}
    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    result = ((payload.get("response") or {}).get("result")
              if isinstance(payload.get("response"), dict) else None)
    if not isinstance(result, dict):
        # A reply shape nobody has seen. Treated as NOT COLLECTED rather than as a healthy
        # reading, which is the direction every unknown on this model takes.
        return {}
    return result


#: The link-group collection's own absence declaration. A separate function rather than a
#: constant because the answer depends on whether the CONTAINER is there: a present and empty
#: container is a collection somebody created and emptied, and an absent one is nobody having
#: configured monitoring at all - two states the count cannot tell apart either.
def link_groups_raw_key(link_monitoring: Any):
    if isinstance(link_monitoring, dict) and "link-group" in link_monitoring:
        return None
    return Implicit.not_assumed(
        "an entry was staged at `group/monitoring/link-monitoring/link-group` and `validate "
        "full` accepted it, but it was never committed, so the oracle's `groups: null` was "
        "never moved to a populated list and empty-versus-absent was not separated. Stage 4 "
        "measured that a link group carrying NO interface is valid configuration, which is why "
        "the verdict counts POPULATED groups rather than entries")


def _link_groups(link_monitoring: Any) -> tuple[list[str], int]:
    """(group names, how many of them monitor at least one interface).

    A LINK GROUP CARRYING NO INTERFACE IS VALID CONFIGURATION - stage 4 wrote
    `<entry name='oep-hap-lg'/>` at the container and `validate full` job 536 answered
    "Configuration is valid". So the state the vendor warns about twice on this control's own
    screen passes commit-time validation as readily as a real one, and a COUNT alone cannot
    report it: a count of one can still monitor nothing. The second number is what the verdict
    uses; the first is what the sheet shows.
    """
    container = link_monitoring.get("link-group") if isinstance(link_monitoring, dict) else None
    names: list[str] = []
    populated = 0
    for entry in ensure_list((container or {}).get("entry") if isinstance(container, dict) else None):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("@name") or "").strip()
        if name:
            names.append(name)
        interfaces = entry.get("interface")
        members = [str(m).strip() for m in ensure_list(
            interfaces.get("member") if isinstance(interfaces, dict) else interfaces)
            if str(m).strip()]
        if members:
            populated += 1
    return names, populated


def _path_groups_populated(path_monitoring: Any) -> int:
    """How many path groups hold at least one monitored destination.

    `group/monitoring/path-monitoring` holds three sibling containers - `virtual-wire`, `vlan`
    and `virtual-router` - and stage 4 has NO FIELD RECORD for any of them, so this reads the
    key set rather than a measured field and says so. The runtime reply answers all three as
    null on both PA-5220s, which is the same answer the configuration gives by holding no
    `group/monitoring` node at all.
    """
    if not isinstance(path_monitoring, dict):
        return 0
    populated = 0
    for kind in ("virtual-wire", "vlan", "virtual-router"):
        container = path_monitoring.get(kind)
        for entry in ensure_list((container or {}).get("entry")
                                 if isinstance(container, dict) else None):
            if not isinstance(entry, dict):
                continue
            destinations = entry.get("destination-ip")
            members = [str(m).strip() for m in ensure_list(
                destinations.get("member") if isinstance(destinations, dict) else destinations)
                if str(m).strip()]
            if members:
                populated += 1
    return populated


def _subnet(address: str, netmask: str) -> str:
    """A crude network identity for the vendor's "different subnet" independence test.

    Compares the leading octets the mask covers, which is enough for the only question asked:
    does the backup control link sit somewhere the primary does not. It is deliberately NOT a
    full IPv4 arithmetic: a wrong answer here can only make the independence test STRICTER -
    reporting a second path as not independent - which is the firing direction.
    """
    octets = [o for o in str(address or "").split("/")[0].split(".") if o != ""]
    mask = [m for m in str(netmask or "").split(".") if m != ""]
    if len(octets) != 4:
        return ""
    if len(mask) != 4:
        # No mask to compare with: treat the whole address as the network, which makes two
        # different addresses two different subnets.
        return ".".join(octets)
    kept = [o if m == "255" else "0" for o, m in zip(octets, mask)]
    return ".".join(kept)


def _primary_control_port(ha1: Any, runtime_local: dict[str, Any], runtime_collected: bool) -> str:
    """Which port the PRIMARY HA1 control link rides.

    `interface/ha1/port` IS ABSENT from the configuration on both PA-5220s in both config views
    while the operational read answers `ha1-port: ha1-a` on both members - so the configuration
    alone cannot classify the exposure band, and the runtime reply is used where it exists. That
    is a departure from stage 5's `derived_from` for `ha1_control_link_exposure`, which names
    the configuration key alone; it moves this estate from `unencrypted-port-unknown` to
    `unencrypted-dedicated-ha-port`, which stage 3 places at the SAME baseline severity, so the
    gain is accuracy with no severity consequence.
    """
    configured = str((ha1 or {}).get("port") or "").strip() if isinstance(ha1, dict) else ""
    if configured:
        return configured
    if runtime_collected:
        return str(runtime_local.get("ha1-port") or "").strip()
    return ""


def _exposure_band(not_encrypted: bool, port: str) -> str:
    model = HighAvailabilityConfig
    if not not_encrypted:
        return model.EXPOSURE_ENCRYPTED
    if not port:
        return model.EXPOSURE_PORT_UNKNOWN
    if port == model.HA_PORT_MANAGEMENT:
        return model.EXPOSURE_MANAGEMENT_PORT
    if port in model.DEDICATED_HA_PORTS:
        return model.EXPOSURE_DEDICATED_HA_PORT
    # An ethernet or aggregate interface name: the control conversation rides a data-plane
    # interface and travels as far as that interface does.
    return model.EXPOSURE_IN_BAND


def normalize_high_availability(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        # No merged config at all. NOTHING IS WRITTEN, which leaves the previous row - or no row
        # - rather than replacing a real reading with defaults. Same shape as every device-wide
        # normalizer here.
        return {"high_availability_configs": 0}
    entry = device_entry_from_snapshot(snapshot)
    collected = isinstance(entry, dict)
    deviceconfig = (entry.get("deviceconfig") or {}) if collected else {}
    ha = deviceconfig.get("high-availability")
    ha = ha if isinstance(ha, dict) else {}
    interface = ha.get("interface") if isinstance(ha.get("interface"), dict) else {}
    group = ha.get("group") if isinstance(ha.get("group"), dict) else {}
    monitoring = group.get("monitoring") if isinstance(group.get("monitoring"), dict) else {}
    link_monitoring = (monitoring.get("link-monitoring")
                       if isinstance(monitoring.get("link-monitoring"), dict) else {})
    path_monitoring = (monitoring.get("path-monitoring")
                       if isinstance(monitoring.get("path-monitoring"), dict) else {})
    ha1 = interface.get("ha1") if isinstance(interface.get("ha1"), dict) else {}
    ha1_backup = (interface.get("ha1-backup")
                  if isinstance(interface.get("ha1-backup"), dict) else {})
    #: THE KEY, NOT THE NODE. `interface/ha1-backup` is present and EMPTY on both PA-5220s, so
    #: `if interface.get("ha1-backup")` is False on a container the device does hold.
    ha1_backup_container_present = "ha1-backup" in interface

    runtime_snapshot = latest_high_availability_snapshot(appliance)
    runtime = _runtime(runtime_snapshot)
    runtime_collected = bool(runtime)
    runtime_group = runtime.get("group") if isinstance(runtime.get("group"), dict) else {}
    local_info = (runtime_group.get("local-info")
                  if isinstance(runtime_group.get("local-info"), dict) else {})
    peer_info = (runtime_group.get("peer-info")
                 if isinstance(runtime_group.get("peer-info"), dict) else {})

    # --- the configuration columns, each with its own absence declaration -------------------
    ha_enabled, enabled_rk, enabled_rv = parse_yes_no_field(ha.get("enabled"),
                                                            implicit=HA_DISABLED)
    cluster = ha.get("cluster") if isinstance(ha.get("cluster"), dict) else {}
    cluster_enabled, cluster_rk, cluster_rv = parse_yes_no_field(
        cluster.get("enabled"), implicit=CLUSTER_UNMEASURED)
    mode_branch, _ = choice_child(group.get("mode"), HighAvailabilityConfig.MODE_CHOICES)
    mode_rk = HA_MODE_UNMEASURED if not mode_branch else None
    config_sync, config_sync_rk, config_sync_rv = parse_yes_no_field(
        (group.get("configuration-synchronization") or {}).get("enabled")
        if isinstance(group.get("configuration-synchronization"), dict) else None,
        implicit=CONFIG_SYNC_UNMEASURED)
    state_sync, state_sync_rk, state_sync_rv = parse_yes_no_field(
        (group.get("state-synchronization") or {}).get("enabled")
        if isinstance(group.get("state-synchronization"), dict) else None,
        implicit=STATE_SYNC_UNMEASURED)
    encryption, encryption_rk, encryption_rv = parse_yes_no_field(
        (ha1.get("encryption") or {}).get("enabled")
        if isinstance(ha1.get("encryption"), dict) else None,
        implicit=HA1_ENCRYPTION_UNMEASURED)
    backup_port, backup_port_rk, backup_port_rv = parse_text_field(
        ha1_backup.get("port"), implicit=HA1_BACKUP_PORT_UNMEASURED)
    peer_ip_backup, peer_ip_rk, peer_ip_rv = parse_text_field(
        group.get("peer-ip-backup"), implicit=PEER_IP_BACKUP_UNMEASURED)
    heartbeat_backup, heartbeat_rk, heartbeat_rv = parse_yes_no_field(
        (group.get("election-option") or {}).get("heartbeat-backup")
        if isinstance(group.get("election-option"), dict) else None,
        implicit=HEARTBEAT_BACKUP_UNMEASURED)
    link_enabled, link_enabled_rk, link_enabled_rv = parse_yes_no_field(
        link_monitoring.get("enabled"), implicit=MONITORING_ENABLED_BY_DEFAULT)
    path_enabled, path_enabled_rk, path_enabled_rv = parse_yes_no_field(
        path_monitoring.get("enabled"), implicit=MONITORING_ENABLED_BY_DEFAULT)
    link_condition, link_condition_rk, link_condition_rv = parse_text_field(
        link_monitoring.get("failure-condition"), implicit=FAILURE_CONDITION_UNMEASURED)
    path_condition, path_condition_rk, path_condition_rv = parse_text_field(
        path_monitoring.get("failure-condition"), implicit=FAILURE_CONDITION_UNMEASURED)
    link_group_names, link_groups_populated = _link_groups(link_monitoring)
    path_groups_populated = _path_groups_populated(path_monitoring)

    # --- the runtime column -----------------------------------------------------------------
    if runtime_collected:
        key_imported, _, _ = parse_yes_no_field(
            local_info.get("ha1-encrypt-imported"), implicit=KEY_IMPORTED_UNCOLLECTED)
    else:
        key_imported = None

    # --- the verdicts -----------------------------------------------------------------------
    local_state = str(local_info.get("state") or "").strip().lower()
    peer_conn = str(peer_info.get("conn-status") or "").strip().lower()
    running_sync = str(runtime_group.get("running-sync") or "").strip().lower()
    state_sync_runtime = str(local_info.get("state-sync") or "").strip().lower()

    # "Formed" is the runtime read showing a peer answering AND state being exchanged, never the
    # configuration switch alone. This pair is exactly why: `enabled: yes` and
    # `configuration-synchronization/enabled: yes` on both members, `state-sync: User-disabled`.
    pair_formed = bool(
        ha_enabled
        and runtime_collected
        and local_state in _LIVE_LOCAL_STATES
        and peer_conn == "up"
        and running_sync == "synchronized"
        and state_sync is True
        and any(token in state_sync_runtime for token in _STATE_SYNC_EXCHANGING)
    )
    # The cluster branch of PAN-HAP-001. `cluster_enabled` is NULL on every appliance in every
    # estate until somebody asks the device, so this is False by the absence of a reading rather
    # than by a reading - which is the firing direction.
    cluster_formed = bool(cluster_enabled and runtime_collected and peer_conn == "up")
    no_live_redundant_peer = not (pair_formed or cluster_formed)

    monitors_nothing = not (link_groups_populated or path_groups_populated)
    if not collected:
        monitoring_state = HighAvailabilityConfig.MONITORING_UNKNOWN
    elif not link_enabled and not path_enabled:
        monitoring_state = HighAvailabilityConfig.MONITORING_NEITHER_ENABLED
    elif monitors_nothing:
        monitoring_state = HighAvailabilityConfig.MONITORING_ENABLED_NO_GROUP
    elif link_groups_populated and path_groups_populated:
        monitoring_state = HighAvailabilityConfig.MONITORING_LINK_AND_PATH
    else:
        monitoring_state = HighAvailabilityConfig.MONITORING_LINK_ONLY

    # The vendor's independence tests for the backup control link: a different port from the
    # primary, and a different subnet. A backup link that rides the primary's port or sits on
    # the primary's subnet fails with it, which is the whole point of the control.
    primary_port = _primary_control_port(ha1, local_info, runtime_collected)
    backup_subnet = _subnet(ha1_backup.get("ip-address"), ha1_backup.get("netmask"))
    primary_subnet = _subnet(ha1.get("ip-address"), ha1.get("netmask"))
    backup_link_complete = bool(
        backup_port and peer_ip_backup
        and (not primary_port or backup_port != primary_port)
        and (not (backup_subnet and primary_subnet) or backup_subnet != primary_subnet)
    )
    # THE HEARTBEAT BRANCH REVERSES MEANING when the primary control link already rides the
    # management port: a "backup path over management" is then the same path, and a pair with it
    # switched on has one keepalive route and not two.
    heartbeat_mechanism = bool(
        heartbeat_backup and primary_port != HighAvailabilityConfig.HA_PORT_MANAGEMENT)
    mechanisms = int(backup_link_complete) + int(heartbeat_mechanism)
    no_second_path = mechanisms == 0

    if not collected:
        keepalive_state = HighAvailabilityConfig.KEEPALIVE_UNKNOWN
    elif mechanisms >= 2:
        keepalive_state = HighAvailabilityConfig.KEEPALIVE_BOTH
    elif mechanisms == 1:
        keepalive_state = HighAvailabilityConfig.KEEPALIVE_ONE_COMPLETE
    elif (ha1_backup_container_present or backup_port) and not peer_ip_backup:
        # NOTE WHAT THIS BAND DOES ON A PA-VM, where `interface/ha1-backup` is a position the
        # schema does not have at all (`code=6 Invalid sequence` at the leaf, 2026-10-26): the
        # container cannot be present, so a PA-VM falls to `neither-mechanism` below and the
        # band names the worst rank for a node that cannot exist there. PAN-HAP-003's
        # applicability clause is `ha_enabled equals True`, which suppresses it on every PA-VM
        # in this estate - but a later stage that removes that clause reinstates the problem.
        # Stage 3's second rank, and the measured state of both PA-5220s: a backup control link
        # begun and not finished. The CONTAINER's presence is the evidence - it holds no port,
        # no address and no netmask - so no column of this model carries it and the band is the
        # only place the reading survives.
        keepalive_state = HighAvailabilityConfig.KEEPALIVE_BACKUP_WITHOUT_PEER
    else:
        keepalive_state = HighAvailabilityConfig.KEEPALIVE_NEITHER

    # Encryption needs all three: the switch, the runtime confirmation, and the imported key.
    # The switch can read `yes` on a link that is not encrypted, which is why the runtime
    # reading is not optional here.
    runtime_encrypt = str(local_info.get("ha1-encrypt-enable") or "").strip().lower()
    not_encrypted = not (
        encryption is True and runtime_collected and runtime_encrypt == "yes"
        and key_imported is True)
    exposure = _exposure_band(not_encrypted, primary_port)

    content_type = ContentType.objects.get_for_model(HighAvailabilityConfig)
    with transaction.atomic():
        row, _ = HighAvailabilityConfig.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                "ha_config_collected": collected,
                "ha_runtime_state_collected": runtime_collected,
                "ha_enabled": bool(ha_enabled),
                "cluster_participation_enabled": cluster_enabled,
                "ha_mode": mode_branch[:32],
                "config_sync_enabled": config_sync,
                "state_sync_enabled": state_sync,
                "ha1_encryption_enabled": encryption,
                "ha1_encryption_key_imported": key_imported,
                "ha1_backup_port": backup_port[:32],
                "peer_ip_backup": peer_ip_backup[:64],
                "heartbeat_backup_enabled": heartbeat_backup,
                "link_monitoring_enabled": bool(link_enabled),
                "path_monitoring_enabled": bool(path_enabled),
                "link_monitoring_failure_condition": link_condition[:16],
                "path_monitoring_failure_condition": path_condition[:16],
                "monitored_link_groups": link_group_names,
                "monitored_link_group_count": len(link_group_names),
                "no_live_redundant_peer": no_live_redundant_peer,
                "ha_monitors_nothing": monitors_nothing,
                "ha_monitoring_state": monitoring_state,
                "no_independent_second_keepalive_path": no_second_path,
                "second_keepalive_path_state": keepalive_state,
                "ha1_control_link_not_encrypted": not_encrypted,
                "ha1_control_link_exposure": exposure,
            },
        )
        FieldProvenance.objects.filter(content_type=content_type, object_id=row.pk).delete()
        entries = [
            ("ha_enabled", enabled_rk, enabled_rv),
            ("cluster_participation_enabled", cluster_rk, cluster_rv),
            ("ha_mode", mode_rk, None),
            ("config_sync_enabled", config_sync_rk, config_sync_rv),
            ("state_sync_enabled", state_sync_rk, state_sync_rv),
            ("ha1_encryption_enabled", encryption_rk, encryption_rv),
            ("ha1_backup_port", backup_port_rk, backup_port_rv),
            ("peer_ip_backup", peer_ip_rk, peer_ip_rv),
            ("heartbeat_backup_enabled", heartbeat_rk, heartbeat_rv),
            ("link_monitoring_enabled", link_enabled_rk, link_enabled_rv),
            ("path_monitoring_enabled", path_enabled_rk, path_enabled_rv),
            ("link_monitoring_failure_condition", link_condition_rk, link_condition_rv),
            ("path_monitoring_failure_condition", path_condition_rk, path_condition_rv),
            ("monitored_link_groups", link_groups_raw_key(link_monitoring), None),
        ]
        FieldProvenance.objects.bulk_create([
            FieldProvenance(
                content_type=content_type, object_id=row.pk, field_name=field_name,
                provenance_type=classify_prov_type(rk),
                raw_key=provenance_raw_key(rk), raw_value=provenance_value(rk, rv)[:128])
            for field_name, rk, rv in entries if rk is not ABSENT])
    return {"high_availability_configs": 1}
