# Reading a zone

> Zone data, without inverting a default or mistaking a group for an address.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-26. Re-verify after a PAN-OS upgrade.*

## Key on (enforcement point, name), never on name

`transit` exists in vsys1 through vsys5 of one device simultaneously. A zone name is unique
only within its vsys, so anything keyed on name alone silently merges five different zones.

## Get the type by key presence, not truthiness

Exactly one of `layer3` `layer2` `virtual-wire` `tap` `tunnel` `external` is present under
`network`, and an empty one serialises as **`null`**. A truthiness test returns "unknown"
for every zone that has no interfaces yet — which is most of them during a build.

They are mutually exclusive **by silent replacement**: setting a second type deletes the
first rather than erroring. So "first key found wins" is safe and iteration order cannot
matter.

`comment` is a sibling of the type key at entry level, and is *rejected* inside it.

## `enable-packet-buffer-protection` absent means ON

The one field where absence inverts the obvious reading.

| Config | Means |
|---|---|
| absent | the default — **enabled** |
| `no` | explicitly off |
| `yes` | explicitly on |

**`None` is the normal reading for a real zone** — every zone in the lab shows the box
ticked in the UI and carries no element. Rendering it as "disabled" or "not configured" is
wrong on essentially every zone in a deployment.

Related, and useful for provenance: the UI can only produce *absent* or *no*, because
ticking writes nothing. A stored `yes` came from the API, a template or Panorama — never
from a human clicking the box.

## ACL members are not addresses

`user-acl` and `device-acl` include/exclude lists mix literal addresses with the **names of
address objects and groups**. `ag-agent-desktop-services` in a real sample is a group.

PAN-OS validates them — a member that resolves to neither is rejected — so anything in a
committed config is one or the other. But **do not compute an address set from them without
resolving the names**, and do not display them as addresses.

If you are classifying a rejection: the message says

    include-list <name> is an invalid ipv4/v6 address

for what is really an *unresolvable name*. PAN-OS tries the IP parse first and reports that
failure. Do not tell an operator they typed a bad IP.

**Validation is not resolution.** That a group name is accepted does not establish what
addresses the zone applies at runtime, and no compiled view for these ACLs has been found —
so if you need the effective set, that is currently unanswerable from this corpus.

## Element names you cannot guess

Four of these are not derivable from the UI label they appear under:

| UI label | Element |
|---|---|
| Enable L3 & L4 Header Inspection | `net-inspection` |
| Pre-NAT: Source Lookup | `enable-prenat-source-policy-lookup` |
| Pre-NAT: Enable Original ID Downstream | `enable-prenat-source-ip-downstream` |
| Device-ID ACL | `device-acl` — **not** `device-id-acl` |

A typo in any of them yields a silent `False`, not an error. Pin them in tests against
captured wire bytes rather than against what the parser expects — a fixture written from the
same misunderstanding as the code will confirm it.

## Interfaces are joined by name, from elsewhere

A zone's `member` list names interfaces; the interface itself is defined in
`network/interface`, imported to the vsys separately, and routed separately. See
`read-an-interface` — a zone tells you the binding, not the interface.

An interface not imported into the vsys cannot be referenced by that vsys's zones at all,
and the failure is a different message from putting a layer3 interface in a layer2 zone.

## Which config you are reading

`show config merged` follows the **candidate**, so a zone staged and not committed appears
as though live, and a staged deletion makes a live zone vanish. See
`merged-config-is-candidate-based`.
