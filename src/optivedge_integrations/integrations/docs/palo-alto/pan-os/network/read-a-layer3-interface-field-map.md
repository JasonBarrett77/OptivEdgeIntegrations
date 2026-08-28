# Layer-3 interface field map

> Which element backs each field of the Ethernet Interface dialog, and what a blank one means.

*Established against the lab — PA-5220 (11.1.13-h3), PA-VM (11.2.3, Azure) — 2026-08-27. Re-verify after a PAN-OS upgrade.*

`read-an-interface.md` covers assembling an interface's configuration and which source
answers which question. This is the narrower companion: the **field inventory** of a layer-3
ethernet interface, and what the UI renders where the config says nothing.

## Two levels, and the split is not where the dialog suggests

The Ethernet Interface dialog presents one form. The config splits it in two, and a
collector reading only `layer3` misses three fields.

The **interface mode** is a child of the physical entry — `layer3`, `layer2`,
`virtual-wire`, `tap`, `ha` — which is why the modes are mutually exclusive by replacement
rather than by a type field. The Advanced tab's **Link Settings** live on the physical entry
too, not under `layer3`, and that is the split a uniform reader gets wrong.

The field inventories themselves are data, not prose. All ten layer-3 attachment points are
enumerated in `OptivEdgeProbe/reference/panos-payload-contract.json` under the
`layer3-interface` node, each `applies_to` entry carrying its child count and its `omits` /
`adds` against the ethernet baseline. Two things worth knowing without opening it:

- **The variance is wide.** `loopback/units` carries 7 children against ethernet's 20,
  dropping ARP, DDNS, DHCP client, NDP proxy, PPPoE and SD-WAN link settings. `tunnel`
  uniquely omits `adjust-tcp-mss`. Aggregate-ethernet adds `lacp`; tunnel subinterfaces add
  `link-tag`.
- **Only two fields exist on all ten paths** — `interface-management-profile` and `mtu`.
  Anything else has to be checked per path before a collector assumes it.

## Dialog to element

| dialog | element | level |
|---|---|---|
| Interface Type | the child node name itself (`layer3`, `layer2`, `virtual-wire`, `tap`, `ha`) | physical |
| Comment | `comment` | physical |
| Netflow Profile | `netflow-profile` | layer3 |
| Config → Virtual System / Security Zone | not on the interface — the vsys and zone reference *it* | — |
| IPv4 → Static | `ip` | layer3 |
| IPv4 → PPPoE | `pppoe` | layer3 |
| IPv4 → DHCP Client | `dhcp-client` | layer3 |
| IPv6 | `ipv6` | layer3 |
| SD-WAN | `sdwan-link-settings` | layer3 |
| Advanced → Link Speed / Duplex / State | `link-speed` / `link-duplex` / `link-state` | **physical** |
| Advanced → Management Profile | `interface-management-profile` | layer3 |
| Advanced → MTU | `mtu` | layer3 |
| Advanced → Adjust TCP MSS | `adjust-tcp-mss` | layer3 |
| Advanced → Untagged Subinterface | `untagged-sub-interface` | layer3 |
| Advanced → ARP Entries | `arp` | layer3 |
| Advanced → ND Entries / NDP Proxy | `ipv6` / `ndp-proxy` | layer3 |
| Advanced → LLDP | `lldp` | layer3 |
| Advanced → DDNS | `ddns-config` | layer3 |

Six `layer3` children have no field in the dialog at all: `bonjour`,
`cluster-interconnect`, `df-ignore`, `proxy-protocol`, `traffic-interconnect`, and `units`
(which the dialog exposes as the separate Add Subinterface action). **The UI is not a
complete inventory of what the schema accepts** — do not derive a field list from screenshots.

## Absent is the normal state

A configured, in-service interface stores almost nothing. On the lab PA-5220, `ethernet1/1`
stores exactly one child — `layer3` — and that stores exactly `ip` and `units`. Every field
below is absent on it:

| element | absent on a real interface | UI renders |
|---|---|---|
| `link-speed` / `link-duplex` / `link-state` | yes | `auto` |
| `mtu` | yes | blank, hint `[576-1500]` |
| `adjust-tcp-mss` | yes | unticked |
| `adjust-tcp-mss/ipv4-mss-adjustment` | yes | `40`, greyed until enabled |
| `adjust-tcp-mss/ipv6-mss-adjustment` | yes | `60`, greyed until enabled |
| `untagged-sub-interface` | yes | unticked |
| `interface-management-profile` | yes | `None` |
| `netflow-profile` | yes | `None` |

**The UI column is the only available source for these.** An absent element has no value to
read back, so no API call reports `auto` or `40` — the dialog is the oracle, and the values
above were read from it rather than from the device. A consumer that renders an absent
`link-speed` as "not configured" is reporting something different from what an administrator
sees.

**`40` and `60` are doubly implicit**: they are defaults *of a feature that is itself off*.
Reporting "IPv4 MSS adjustment: 40" on an interface where `adjust-tcp-mss` is absent states
a number that adjusts nothing.

## Limits

Field inventory and absence are measured; **every value in the "UI renders" column is read
from a screenshot, not from the device**, and none was confirmed by observing behaviour. In
particular it is not established that an absent `link-speed` negotiates rather than
defaulting to a fixed rate — only that the dialog displays `auto`.

Also not established:

- whether these defaults hold across platforms; only the PA-5220 dialog was read, and the
  PA-VM has a different child count at `layer3` (19 vs 20)
- what any of the six dialog-less elements do
- the `units` / subinterface dialog, which was not opened
- anything about `layer2`, `virtual-wire` or `tap` interfaces beyond their child counts.
  Field *names* for every layer-3 path are enumerated in the contract; **names are all**
  `action=complete` **reports** — no value, and no implicit value, for any of them
- whether a template-pushed interface renders the same defaults, since provenance markers
  were not exercised here

## Reproducing

    python -m probe.investigations.interface_management_profiles ifdefaults

prints both halves — the `complete` inventory at all three levels, and which of the fields
above a real interface actually stores.
