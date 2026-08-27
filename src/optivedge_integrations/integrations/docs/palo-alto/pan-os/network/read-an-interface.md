# Reading an interface

> The four places an interface lives, and which question each one answers.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-26. Re-verify after a PAN-OS upgrade.*

## Read four places, not one

An interface is defined in four subtrees keyed only by its **name**. Nothing links them.

    network/interface/<container>/entry[@name]           type and addressing
    vsys/entry/import/network/interface/member           which vsys owns it
    vsys/entry/zone/entry/network/<type>/member          which zone it is in
    network/virtual-router/entry/interface/member        which routing instance

Read only the first and you get an interface with no vsys, no zone and no routing — which
is coherent, plausible, and not the interface the firewall is using. Any report on
"interfaces" that does not join all four is describing something else.

## Get the type right, including the one that is not a subtree

Exactly one type key is present per entry. Test **key presence**, not truthiness: an empty
subtree serialises as `null`.

| Key | Shape |
|---|---|
| `layer3`, `layer2`, `virtual-wire`, `tap`, `ha` | subtree, possibly `null` |
| `aggregate-group` | **a string** naming the parent aggregate |

Code that finds the present type key and reads `.get("member")` or iterates its children
returns nothing for an aggregate member, silently and without error. Handle it explicitly.

`comment` is a sibling of the type key, not inside it. The available type set is
**platform-dependent** — `decrypt-mirror` is refused on a PA-5220 and exists elsewhere — so
an unknown type key is a reason to report, not to assume corruption.

## Addressing is three alternatives, and two of them have no address

`ip`, `dhcp-client` and `pppoe` are mutually alternative. Only `ip` states an address; a
DHCP or PPPoE interface legitimately has none in configuration, because the lease is
runtime state. **Absent addressing is not missing data** — check which of the three is
present before concluding anything.

`ipv6` is a separate node from `ip` and carries its own `address` list. An interface can
have both, one, or neither.

## Configuration and runtime answer different questions

`<show><interface>all</interface></show>` returns `ifnet` and `hw`, and neither replaces
the config:

- **config** — what was intended
- **`ifnet`** — what it resolved to: `vsys` (a *number* as a string, `"0"` for none),
  `zone` (`null` when unzoned), and `fwd`, a compact runtime type discriminator —
  `vr:<name>` / `vwire:<peer>` / `tap` / `ha` / `N/A`
- **`hw`** — whether it is physically up: `mac`, `speed`, `duplex`, `state`

Three literals to handle: `ip` is the string `"N/A"` when absent, `speed`/`duplex` are
`"ukn"` on a down port, and `addr6` contains **auto-generated link-local addresses that
configuration does not have**.

An aggregate **member** appears in `hw` and *not* in `ifnet` — physically real, logically
not an interface. And aggregates point opposite ways: config has the member naming its
parent, runtime has the parent listing its members under `hw`/`ae_member`.

## If you are writing, not just reading

- **Order matters.** A reference is rejected until its target exists — create the aggregate
  before the member names it.
- **Some constraints only appear at commit.** A DHCP or PPPoE layer3 interface writes
  cleanly and then fails validation with `has no virtual-router configured`. The same
  pattern as assigning a device group to a zoneless vsys: accepted at the write, refused at
  the commit.
- **An aggregate member cannot be imported into a vsys.** Import the aggregate.

## Remember which config you are reading

`show config merged` follows the **candidate**, so an interface an administrator has staged
but not committed appears here as though it were live — and a staged deletion makes a live
interface vanish. See `merged-config-is-candidate-based`.


## A logical interface is not a small ethernet interface

vlan, tunnel, loopback and sdwan units differ from physical ports in three ways, each of
which silently breaks ethernet-shaped code:

- **No `hw` block at runtime**, only `ifnet`. An `hw.state` liveness check finds nothing.
- **No type key in the config.** The entry holds `ip` and `comment` and nothing that says
  what it is — the type is the **container path**
  (`network/interface/{vlan,tunnel,loopback}/units`). Do not apply the ethernet type
  discriminator here; for these, path *is* type.
- **The VLAN binding is one-directional.** `vlan.N` carries no reference to its VLAN. The
  link lives on the VLAN object (`network/vlan/entry/virtual-interface/interface`), so
  answering "which VLAN does this serve" means reading the VLAN objects and inverting.

The six categories are enumerable from the device rather than hard-coded: `action=complete`
against the interface xpath returns what that node actually accepts.

## Prefer runtime for bindings, config for intent

`vr`, `vsys` and `zone` are each stored somewhere different in configuration and all three
appear resolved in `show interface <name>`. Read bindings from runtime.

On a **live** port, `speed_c`/`duplex_c`/`state_c` are the *configured* values and
`speed`/`duplex`/`state` are what the port negotiated — on ethernet1/1 they disagree
(`auto` versus `1000`/`full`/`up`). Report the bare field as operational state. On a down
port both read `ukn`/`auto`, so a down port cannot teach you this distinction.

## Building one: watch where each rule is enforced

    reference to a missing interface   -> refused at the WRITE
    interface with no zone / no VR     -> commit WARNING, commit still succeeds
    IPSec tunnel on a VR-less interface -> commit ERROR, config invalid

The same missing virtual router is tolerable in one case and fatal in the other. Read the
commit's *result*, not only its warning list.
