# Reading an interface management profile

> The second management plane: which data-plane interfaces are administrative surfaces, and who may reach them.

*Established against the lab — PA-5220 (11.1.13-h3), PA-VM (11.2.3, Azure) — 2026-08-27. Re-verify after a PAN-OS upgrade.*

An Interface Management Profile turns an ordinary forwarding interface into an
administrative surface. It carries its own service set and its own permitted-IP list, and
it is configured nowhere near `deviceconfig/system`. A device with a locked-down MGT
interface can still be administrable over a data-plane interface, and nothing in the
management-plane config says so.

Two objects, in different places:

    network/profiles/interface-management-profile/entry[@name]   the profile - services + permitted IPs
    network/interface/<container>/…/interface-management-profile  a scalar reference to one, by name

## The profile is a network-plane object

Both live under `network/`, which is why this guide is here rather than in `management/`.
See `../management/read-device-configuration.md` for the `deviceconfig/system` plane, and
read both: **neither answers "is this device administratively exposed" on its own.**

## How the attachment table was established

`action=complete` reports what the **schema** permits, not what the device has configured —
verified rather than assumed, because every row below depends on it. Completing the same
node on a configured interface and on one that does not exist returns identical counts:

    fw-core-tpa-a   ethernet1/1 (real)   layer3 20, layer2 3, virtual-wire 4, tap 1
                    ethernet1/99 (absent) layer3 20, layer2 3, virtual-wire 4, tap 1

So a negative means the schema forbids it, never "that interface is not configured here".

**Zero completions is ambiguous, and must be resolved by walking up.** A node returning
nothing may be absent from the schema *or* present with no children. `ha` is the case that
proves it: the physical ethernet entry lists `ha` among its valid children, yet completing
`.../ha` returns nothing, because it is a bare marker node. Treating both as "absent"
reports one of them wrongly.

    python -m probe.investigations.interface_management_profiles method

## Where a profile can attach

Measured with `action=complete` at each node, and matching Palo Alto's own wording —
"Layer 3 Ethernet interfaces (including subinterfaces) and to logical interfaces
(aggregate group, VLAN, loopback, and tunnel interfaces)".

| node | attaches |
|---|---|
| `ethernet/entry[@name]/layer3` | yes |
| `ethernet/entry[@name]/layer3/units/entry[@name]` | yes |
| `aggregate-ethernet/entry[@name]/layer3` | yes |
| `aggregate-ethernet/entry[@name]/layer3/units/entry[@name]` | yes |
| `vlan` and `vlan/units/entry[@name]` | yes |
| `loopback` and `loopback/units/entry[@name]` | yes |
| `tunnel` and `tunnel/units/entry[@name]` | yes |
| `ethernet/…/layer2`, `/virtual-wire`, `/tap` | **no** — the node exists and has no such child |
| `sdwan/units/entry[@name]` | **no** — exists, 7 children, none of them this |
| `ethernet/…/ha` | **no** — present but childless; a marker, not a container |
| `ethernet/…/log-card`, `/decrypt-mirror` | absent from the PA-5220 schema entirely |
| `cellular`, `cluster-ethernet` | container absent on both lab platforms |

**Layer 3 only.** The three non-L3 ethernet modes have no such child, and neither does an
SD-WAN logical interface — a negative worth keeping, because SD-WAN sits in the same UI
list as the types that do.

`vlan`, `loopback` and `tunnel` are inherently layer 3, so the profile hangs directly off
the container with **no `layer3` node in the path**. A collector walking a uniform
`…/layer3/interface-management-profile` path finds ethernet and aggregate-ethernet and
silently misses the other three.

`cellular` and `cluster-ethernet` expose the leaf in the CLI corpus, but only in the
Panorama capture. **Measured:** on both lab platforms the containers are absent — completing
them returns nothing *and* their parent returns nothing, which is how a missing container is
told apart from a childless node. Whether the leaf behaves the same on a platform that has
them is untested.

## Platform reach is not uniform

On the Azure PA-VM, `layer2`, `virtual-wire`, `tap` and `vlan` return **zero completions** —
the nodes are absent from the schema, not merely empty. Only layer3, aggregate-ethernet,
loopback and tunnel exist.

**Inferred:** that this reflects the hypervisor's layer3-only operation rather than a
PAN-OS version difference. The measurement is the completion count; the reason is not
established. Either way, **do not derive the set of interface types from one platform.**

## The eleven services, and their element names

Not one of the User-ID names is derivable from its label.

| UI label | element |
|---|---|
| HTTP / HTTPS / Telnet / SSH | `http` `https` `telnet` `ssh` |
| Ping | `ping` |
| HTTP OCSP | `http-ocsp` |
| SNMP | `snmp` |
| Response Pages | `response-pages` |
| User-ID | `userid-service` |
| User-ID Syslog Listener-SSL | `userid-syslog-listener-ssl` |
| User-ID Syslog Listener-UDP | `userid-syslog-listener-udp` |

**Absent means off, and a new profile is entirely absent.** A profile created with no
services stores as a bare `<entry name="X"/>` — no keys at all. Both `yes` and `no`
persist as written when set through the API, so a consumer must treat absent, `no` and
`yes` as three readable states that collapse to two meanings.

Note this polarity is the **opposite** of `deviceconfig/system/service`, whose keys are
negative (`disable-http`) and where absent means the service is *on*. The two management
planes disagree about what silence means. Reading one with the other's assumption inverts
every service on the profile.

## permitted-ip accepts less than an address object does

Measured by driving each form against a live device:

| form | interface profile | `deviceconfig/system` |
|---|---|---|
| IPv4 host `192.168.250.11` | accepted | accepted |
| IPv4 CIDR `10.20.0.0/16`, `/32` | accepted | accepted |
| IPv4 wildcard `0.0.0.0/0` | accepted | accepted |
| **IPv6 host** `2001:db8:123:1::1` | **accepted** | **accepted** |
| **IPv6 CIDR** `2001:db8:123:1::/64`, `::/0` | **accepted** | **accepted** |
| IPv4 range `10.30.0.1-10.30.0.9` | **rejected** | **rejected** |
| address-object or group name | **rejected** | **rejected** |
| a bare hostname | **rejected** | not tried |
| `<description>` child | **rejected** | **accepted** |

Three things follow.

**IPv6 is first-class on both planes.** Any consumer treating `permitted_ip_values` as
IPv4-only mis-reads a v6-restricted interface. The compiled ACL keeps them apart as
`peers` and `v6peers`.

**A name is not a value here.** `ag-agent-desktop-services` is rejected as "an invalid
ipv4/v6 address" on both planes, so unlike zone `user-acl`/`device-acl` members — which
*do* mix literals with object names — a permitted-IP entry is always a literal. Nothing
needs resolving.

**The two planes differ by exactly one field.** `description` is accepted under
`deviceconfig/system/permitted-ip` and rejected under the interface profile. The CLI
corpus predicts this (`set deviceconfig system permitted-ip <name> description <value>`
exists; no such path under `network profiles`) and the device confirms it. A shared model
across both planes must make description nullable and must not expect it here.

**A rejected entry rejects the whole write.** Sending six entries where one is a range
fails all six with `code=12`; nothing is partially applied. Useful when writing, and it
means a stored list never contains an entry PAN-OS considers invalid.

## An absent permitted-ip list means ANY — measured by connection

This was an open question through two rounds; it is now settled by driving the three states
on a live interface and attempting a real connection to each. `ethernet1/1` sits at
`192.168.250.101/24`, routable from the probe host, so the test is a genuine connection
rather than a config read.

Profile enabling **https and ping only**, bound to `ethernet1/1`, committed each time:

| permitted-ip state | port 443 | port 22 |
|---|---|---|
| **node absent entirely** | **OPEN** | closed |
| node present, one non-matching address (`10.99.99.99`) | closed | closed |
| node present, no entries | **OPEN** | closed |
| **one IPv6 entry only** (`2001:db8:123:1::/64`) | **closed** | closed |
| that IPv6 entry **plus a matching IPv4 range** | **OPEN** | closed |

Four things this establishes.

**No list means anyone who can route to the interface.** Same semantics as the dedicated
management port, and the security-relevant direction: a profile written without a
permitted-IP list exposes its services to every source that can reach the address. Nothing
in the profile says so.

**The middle row is the control, and it matters.** Without it, the OPEN results would be
ambiguous between "an absent list means any" and "the profile is not being enforced at all".
A non-matching address closes the port, so the access control is live and the OPEN rows mean
what they appear to mean.

**Empty and absent are the same state, because PAN-OS will not store an empty container.**
Setting `<permitted-ip></permitted-ip>` and reading the config back returns an entry with no
`permitted-ip` node at all. There are only two states to model — no list, or a populated one.

**A non-empty list restricts, whatever family its entries are — and the families are
evaluated independently.** An IPv6-only list denies IPv4 outright; adding a matching IPv4
range to that same list reopens it. So a v6 entry does not suppress v4 matching, and a
v6-only list is genuinely restrictive rather than accidentally permissive.

That last row overturned a plausible inference worth recording, because the premise was
right and the conclusion was not. The compiled ACL keeps `peers` and `v6peers` apart, and an
empty `peers` **is** what unrestricted looks like — so a v6-only list, leaving `peers`
empty, seemed likely to leave IPv4 wide open. It does not. **An empty `peers` means
unrestricted only when the whole list is empty**; with `v6peers` populated it means "no IPv4
source is permitted." Same observation, opposite conclusion, and only a connection could
tell them apart.

**Service toggles are enforced individually at runtime**, confirming the config-layer
polarity finding from the other side: `https` set to yes opened 443, while `ssh` left absent
kept 22 closed throughout.

## `0.0.0.0/0` is kept here, and dropped on the management plane

**The two planes disagree, and this is the second thing they disagree about.** They already
spell services with opposite polarity; they also treat the all-addresses entry differently.
Both halves are now measured, and neither was safe to infer from the other.

On the deviceconfig planes PAN-OS **drops** the entry when it compiles the ACL, so
`[0.0.0.0/0, 10.99.99.99]` permits that one host and nobody else. See
`../management/read-device-configuration.md`.

**On a profile the entry is kept.** The same list permits everyone. Measured by connection,
because a profile has no compiled ACL to read:

| permitted-ip list | port 443 | what it establishes |
|---|---|---|
| `10.99.99.99` | closed | the control — enforcement is live on this surface today |
| `0.0.0.0/0` | **OPEN** | unrestricted either way; needs no measurement |
| **`0.0.0.0/0` + `10.99.99.99`** | **OPEN** | **the finding — the wildcard is honoured** |
| `0.0.0.0/0` + `192.168.250.0/24` | **OPEN** | a two-entry list that opens for a matching entry |

Port 22 stayed closed in every row. The profile enabled `https` and `ping` only, so each row
carries its own evidence that the profile was what governed the surface rather than something
else on the device.

**The first row is what makes the third readable.** If the wildcard is honoured then every
wildcard state is OPEN, so nothing in that group can come back closed and a harness that had
stopped working would read exactly like the finding. The control has to be a state with no
wildcard in it, and it has to actually close.

**The third row was run twice, the second time from a freshly closed baseline.** On the first
pass it followed the wildcard-alone state, so OPEN followed OPEN and the surface was never
observed to *change* into it — which is weaker evidence than it looks, since a surface that
never re-closed reads the same way. Re-running the control first gives closed → OPEN across
the single change of adding `0.0.0.0/0`.

**Which entries match is a property of the prober, not of PAN-OS.** `10.99.99.99` is
non-matching and `192.168.250.0/24` is matching *for the probe host*, which reaches the lab
through NAT and does not arrive as its own address. Both are established by the rows above
rather than assumed. Repeating this anywhere else means re-establishing them.

**What this changes for a consumer.** `exposure.classify()` takes the plane, and both branches
are now measured facts:

    deviceconfig plane   wildcard dropped   [0.0.0.0/0, jump host] -> restricted
    profile              wildcard kept      [0.0.0.0/0, jump host] -> unrestricted

`undetermined` is no longer produced for this combination. It now means only what it was
introduced to mean: an entry nothing can parse. PAN-MGT-003 matches `unrestricted` and
`undetermined` both, so the same surfaces are reported — but the verdict behind the report is
measured rather than a hedge, and a hardened management interface carrying
`[0.0.0.0/0, jump host]` is still correctly not flagged.

**The general shape, worth carrying to the next plane-spanning question:** one rule with an
unmeasured half is an assumption wearing a measurement's clothes. The wildcard was documented
as a single PAN-OS behaviour with one side unchecked; the unchecked side turned out to be the
opposite. The cost of finding out was four commits.


## There is no runtime witness for a data-plane profile

For the management plane, `show system state filter cfg.net.s0.eth*.acl` reports the
compiled ACL — the authoritative answer to what is actually reachable. **No equivalent
exists for a data-plane interface carrying a management profile**, which was measured rather
than assumed:

- `cfg.net.*` returns 46 keys, all under slot 0, all management-plane ports (`eth0` through
  `eth6` plus `pci0`). Binding a profile to `ethernet1/1` and committing added no key.
- `cfg.net.s0.fwd_dpmp_acl` looked promising — it reads
  `enable: True, port: [443, 80], todp_if: pci0, toext_if: eth0` — but its value is
  **identical before, during and after** a profile was bound. It is static forwarding
  configuration, not a witness for this.

So the two planes cannot be assessed the same way. Management-plane exposure is readable from
compiled state; data-plane exposure is readable only from configuration, and confirmable only
by attempting a connection. An assessment that reports on one using the other's method will
be wrong about the data plane.

## An empty container still carries template provenance

On the PA-VM, which is template-stack managed, the node exists and is empty:

```json
{"interface-management-profile": {"@ptpl": "temp-stck-jb-rg", "@src": "tpl"}}
```

No `entry` children — the container itself is template-sourced. **Node presence is not
profile presence.** A collector testing "does this node exist" concludes a
template-managed device has profiles when it has none, and a reader expecting `entry` to
be present will hit a `KeyError` rather than an empty list.

A **populated** pushed profile carries the markers at every level, not only on the
container. Read from `ptpl_fw-core-tpa` on both PA-5220s:

```json
{"@name": "oep-tpl-bound", "@ptpl": "ptpl_fw-core-tpa", "@src": "tpl",
 "https": {"@ptpl": "ptpl_fw-core-tpa", "@src": "tpl", "#text": "yes"},
 "permitted-ip": {"@ptpl": "ptpl_fw-core-tpa", "@src": "tpl",
                  "entry": [{"@name": "10.9.9.0/24", "@ptpl": "ptpl_fw-core-tpa",
                             "@src": "tpl"}]}}
```

Four levels: the `entry`, each service leaf, the `permitted-ip` container, and each
`permitted-ip` entry. So a service leaf arrives as a dict with `#text` rather than the bare
string a locally-set profile gives — the same normalisation trap the interface reference
has, one level deeper. A reader comparing `entry["https"] == "yes"` succeeds on a local
profile and fails on a pushed one.

## Reading it

The reference is a plain scalar on the interface:

```json
{"@name": "loopback.99",
 "interface-management-profile": {"#text": "profile-name", "@admin": "...", "@dirtyId": "..."}}
```

so it arrives as a dict with `#text` on a candidate read and may be a bare string elsewhere —
normalise before comparing. Resolve the name against
`network/profiles/interface-management-profile`; the profile is device-scoped, not vsys-scoped.

## Reproducing all of this

Every table above is regenerated by one subcommand; none of it rests on a one-off script.

    python -m probe.investigations.interface_management_profiles method      # the schema-vs-instance proof
    python -m probe.investigations.interface_management_profiles attach      # the attachment table
    python -m probe.investigations.interface_management_profiles ifdefaults  # field inventory + defaults
    python -m probe.investigations.interface_management_profiles compare     # the permitted-ip table
    python -m probe.investigations.interface_management_profiles measure     # profile storage shapes
    python -m probe.investigations.interface_management_runtime wrongonly    # the controls and
    python -m probe.investigations.interface_management_runtime anywrong     # the wildcard result

`compare` and `measure` write to the candidate config. Both refuse to start if the candidate
is already dirty, never commit, and revert when done.

The `interface_management_runtime` phases are the exception to that: runtime behaviour does
not exist until a commit, so they commit for real. Each refuses to start on a dirty
candidate, and `cleanup` restores the binding the scaffolding displaced.

## Limits

Everything above was established on one PA-5220 (11.1.13-h3) and one Azure PA-VM (11.2.3),
via candidate-config writes that were reverted, never committed. Specifically **not**
established:

- the IPv6 wildcard `::/0` alongside other entries. Only `0.0.0.0/0` was driven; `::/0`
  is treated identically by `exposure.classify()`, which tests prefix length rather than
  family, and that is an **inference** from the v4 result. It is a smaller gap than the
  one it replaces — the families are already known to be evaluated independently — but
  it is the same class of assumption that made the v4 case worth measuring, and no
  connection has ever been attempted over IPv6 on this plane at all
- the runtime results come from **one interface on one firewall**, with https and ping as
  the only enabled services. Other services were not driven
- **no connection was ever attempted over IPv6.** The v6 rows above were measured by
  connecting over IPv4 to an interface whose list held v6 entries, which establishes what a
  v6 entry does to IPv4 reachability and nothing about v6 reachability itself
- the mechanism behind the v6 result is inferred, not read. The compiled ACL is legible only
  on the management plane, and setting the MGT permitted-IP list to IPv6-only to observe
  `peers`/`v6peers` directly risked management access to a lab device for confirmation of a
  conclusion the connection test already established
- whether the UI writes `no` or removes the key when a service is unticked — the API
  stores what it is sent, and the UI was not driven
- `cellular` and `cluster-ethernet` attachment, absent from both lab platforms
- the documented 31-character name limit, taken from Palo Alto's docs and not tested
- whether a **local profile can override a template-pushed one of the same name**. Both
  forms exist in the lab, but never under one name, so precedence between them is untested
  here. The override refusals recorded in the discovery log are about the XML API path, not
  about which value wins
