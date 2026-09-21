# Reading device configuration

> Management-plane configuration, without reporting a device clean when it is not.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-26. Re-verify after a PAN-OS upgrade.*

## `deviceconfig/system` is not the whole management plane

A data-plane interface carrying an `interface-management-profile` is a second
administrative surface, with its own services and its own permitted-source list, configured
nowhere near here — see `../network/read-an-interface-management-profile.md`. **Neither
guide answers "is this device administratively exposed" on its own.**

The two planes also disagree about what silence means. Keys here are negative
(`disable-http`) and absent means the service is **on**; interface-profile keys are positive
(`http`) and absent means **off**. Reading one with the other's assumption inverts every
service.

## Never infer a management service from the config subtree alone

`deviceconfig/system/service` holds only **negative** keys (`disable-telnet`,
`disable-http`) and is frequently **absent entirely**. Absence does not mean "nothing
enabled" — measured, a device with no `service` node at all is running **ssh, https and
icmp**.

A control that reads the subtree and reports what it finds will pass a firewall with SSH and
HTTPS exposed. One of the two lab firewalls is in exactly that state, so this is not a
hypothetical.

**Read `show system services` instead, or as well.** It is a compiled view: it lists what is
actually running after the device resolved the config. Where a control must cite
configuration, cite the compiled view alongside it.

**But it covers MGT only.** Measured: aux-1 with `disable-ssh` and `disable-https` set
explicitly left `show system services` unchanged.

**Use the per-interface compiled ACL instead — it covers every management plane:**

    show system state filter cfg.net.s0.eth*.acl

Each entry carries `peers` (the compiled `permitted-ip`) and `services` (the compiled service
set). On a PA-5220, `eth0` is MGT and `eth5` is Aux-1. This is the single best source for
"what is actually reachable on this device", and it resolves both the service defaults and the
permitted-ip semantics without reading the config at all.

Do not extend the measured table beyond the five services observed.

**Unmeasured:** whether `disable-*` keys beyond those five exist at all.

## Working decision: implicit service values

Jason's decision, 2026-08-26. Recorded as a **working rule for consumers**, not as a
measured result. Use it until `validate-aux-service-enablement` is answered.

> **Use the implicit value when the explicit value is missing.**
>
>     Management interface  implicit = HTTPS, SSH, PING enabled
>     Aux interfaces        implicit = all disabled

That gives a collector a defined answer for every field instead of "unknown", which is the
point: an absent key must normalise to something, and silently treating it as *disabled* on
MGT is the failure mode this whole subject exists to prevent.

**The basis is deliberate: it matches what the UI reports, because that is how an assessment
is performed.** An assessor works from what is observable at the console, and the detail
dialog has been reliable in every state tested. Where the device's *behaviour* diverges from
that, it matters - but it is unproven while the aux ports are uncabled, and an unproven
divergence is not a basis for normalisation. Revisit if
`validate-aux-service-enablement` proves reachability.

### One measured exception, and it runs the unsafe way

The rule matches measurement when the `service` **node is absent**. It does not when the node
is present and the individual key is missing:

| state | the rule says | the device does |
|---|---|---|
| aux, no `service` node | all disabled | all disabled ✓ |
| aux, node present, `disable-ssh` absent | ssh disabled | **ssh enabled** ✗ |
| MGT, node present, `disable-ssh` absent | ssh enabled | ssh enabled ✓ |

The failing row is the shape the **UI itself writes** — ticking one box produces
`<service><disable-ssh>no</disable-ssh></service>` — so it is not a corner case. A collector
applying the rule literally would report an aux interface as closed while the compiled ACL
lists `ssh, https, ping, icmp`. That is the under-reporting direction.

The formulation that fits every measurement to date keys on node presence as well as
interface type:

    service node ABSENT   ->  MGT: ssh, https, ping enabled   |  aux: all disabled
    service node PRESENT  ->  both: ssh, https, ping, icmp enabled, minus any disable-X: yes

Neither formulation is validated against traffic on an aux interface. Where the two disagree,
prefer the compiled ACL over either.

## An aux interface is not a small management interface

Its `service` defaults are the **opposite** of MGT's, and the node's mere existence flips them:

    aux service node absent          -> NO admin services
    aux service node present, EMPTY  -> ssh, https, ping, icmp
    aux node present + disable-X:yes -> that set, minus X

So never apply MGT's defaults to aux, and be aware that **writing any `service` subtree to an
aux interface enables four services as a side effect** — including a subtree whose only
content is a `disable-*: yes` intended to harden it. Read the compiled `services` from that
interface's ACL rather than reasoning from the config.

**The UI produces this too — it is not an API-only hazard.** Ticking SSH alone in the Aux-1
dialog writes exactly `<service><disable-ssh>no</disable-ssh></service>`, the commit leaves it
sparse, and the device then runs `ssh, https, ping, icmp`. Measured.

So never report an aux interface's exposure from its `service` keys. Read the compiled
`services` for that interface's ACL; the config is a sparse representation whose effective
meaning is larger than what it says.

## To reset a field, DELETE the right branch — but know which way the default points

Deleting a node returns it to its default rather than leaving a hole — `delete` on
`aux-1/service` restores "no admin services", and `delete` on `permitted-ip` restores
"unrestricted". Choosing the branch is the whole technique: deleting `aux-1` removes the
interface, deleting `aux-1/service` resets only its services. Prefer this to writing defaults
back by hand, which requires knowing them and re-introduces the empty-versus-absent problem.

**The reset is not always toward "closed".** Because MGT and aux default in opposite
directions, the same delete has opposite security effects — and that is not confined to the
service nodes: `server-verification` defaults ON while its neighbour
`enable-log-high-dp-load` defaults OFF, so "reset it" widens one and narrows the other. See
"Management-setting defaults are per key" below.

    delete aux-1/service   -> NO admin services      (closes)
    delete MGT service     -> ssh, https, icmp ON    (OPENS)

So deleting the MGT `service` node discards any hardening it encoded — `disable-telnet: yes`
and `disable-http: yes` disappear and the standard set returns. It cannot lock you out, since
https and ssh come back on, but it silently widens exposure and is the wrong instrument for
"undo my change" on MGT. Re-set the specific keys instead.

An absent MGT `service` node does **not** impair the UI: fw-core-tpa-a has had none for this
entire investigation and its Management Interface Settings dialog renders and edits normally.

But it does change what the **Services Enabled column** in Device > Setup > Interfaces shows.
With no `service` node that column is **blank**, on an interface serving SSH, HTTPS and Ping;
create the node and it lists all three. Never take that column — or an operator's report based
on it — as evidence that a management plane is closed. The detail dialog is trustworthy; the
list column is not.

## Read all three management planes, not just MGT

`deviceconfig/system/service` and `.../permitted-ip` describe the **management interface
only**. A PA-5220 has two more, each with its own copy of both:

    deviceconfig/system/{service,permitted-ip}          MGT
    deviceconfig/system/aux-1/{service,permitted-ip}    Aux-1
    deviceconfig/system/aux-2/{service,permitted-ip}    Aux-2

Same ten `disable-*` keys, different location. A control that reads only the first misses an
aux interface with SSH or HTTPS reachable — precisely the exposure it exists to catch.

`aux-1`/`aux-2` do not exist on every platform (the PA-VM has neither), so their absence does
not distinguish "not configured" from "not supported". Use `action=complete` on
`deviceconfig/system` to tell those apart.

## Management-setting defaults are per key, and two of them are opposite

*Measured 2026-09-01 against a PA-5220 (11.1.13-h3) with all three keys absent.*

| key | absent means | node |
|---|---|---|
| `server-verification` | **enabled** | `deviceconfig/system` |
| `ack-login-banner` | disabled | `deviceconfig/system` |
| `enable-log-high-dp-load` | disabled | `deviceconfig/setting/management` |

`server-verification` and `enable-log-high-dp-load` are neighbouring management settings with
**opposite** defaults. A reader that assumes one default for a subtree gets one of them
backwards, and for a control that inverts the finding set: absence satisfies the first and
violates the second.

## These keys do not vanish when written to their default

The `disable-*` service keys under `deviceconfig/system/service` are omitted when they match
the default, which is what makes "write it and see if it disappears" a way to discover the
default. **These keys are not.** Writing `yes`, committing and reading back leaves `yes`
stored; writing `no` leaves `no` stored. Absence therefore means "never written" and nothing
more, and the default has to come from somewhere else — the web interface checkbox on a device
with the key absent settled all three at once.

Do not assume the omit-on-default behaviour generalises across `deviceconfig`.

To get one of these keys back to its implicit state, **delete it** — see "To reset a field,
DELETE the right branch" above. Writing the default value back leaves the key present and set,
which is a different config from never having written it, and the two are distinguishable:
`FieldProvenance` gives a present-but-unmarked key a row typed `local`, and an absent key a row
saying which kind of absence it is — `pan_os_default` where we have measured what PAN-OS
supplies, `assumed_default` where the stored value is our inference, `not_configured` where
nothing was stored at all.

## `deviceconfig/setting/management` can be absent entirely

Not merely missing a key — the whole node. That is the state on both PA-5220s, which have
never had one of its settings written. A read has to survive two levels of absence
(`setting` then `management`), and a device where the node exists proves nothing about a
device where it does not.

## `ack-login-banner` is gated on the banner in the interface

The checkbox is greyed out until `login-banner` is non-empty, so acknowledgement cannot be
required without a banner to acknowledge. This shapes remediation ordering rather than the
read: set the banner first. Whether the API accepts `ack-login-banner: yes` on a device with
no banner is **unmeasured** — only the interface behaviour was observed.

## Limits

- The template-pushed form was measured 2026-09-02 and is no longer a limit: pushed values
  arrive as `{'@ptpl': ..., '#text': ...}`, an override strips the marker from that leaf alone,
  and a value already set locally survives a push of a different value. See
  `../read-template-provenance.md`.
- One PAN-OS version for the defaults. The PA-VM was enumerated for key sets but its checkbox
  states were not read.

## permitted-ip: absent and empty mean "any" — but `0.0.0.0/0` alongside anything does not

Absent and `<permitted-ip/>` both leave inbound management open. A populated list that
excludes the caller blocks it, which proves enforcement is live. So reporting empty and absent
identically is **correct for this field** — unlike `deviceconfig/setting`, where they are
genuinely different documents.

**Do not read `0.0.0.0/0` as "unrestricted".** PAN-OS **strips it when compiling the ACL**, so
it is never a member of the effective set. Alone it compiles to an empty `peers` list — which
*is* "unrestricted" — so it appears to work. Alongside anything else it vanishes and leaves
only the specific entries, so `[0.0.0.0/0, 10.99.99.99]` permits `10.99.99.99` and nobody else.

Palo Alto documents "any" as an **empty list** and never offers `0.0.0.0/0` for it.

So a control that flags `0.0.0.0/0` as wide-open is **wrong** whenever another entry is
present. Report the compiled `peers` from the ACL rather than reasoning about the config list —
an empty `peers` is the only thing that means unrestricted.

When reporting on management exposure, say so explicitly: `permitted-ip` restricts **direct**
management only. The firewall's connection to Panorama is device-initiated and unaffected, so
a fully locked-down `permitted-ip` still leaves Panorama-mediated management available. It is
also the reliable way back from a lockout.

## What a permitted-ip entry may hold

Driven against a live device, form by form, on both planes:

| form | this plane | interface profile |
|---|---|---|
| IPv4 host, CIDR, `/32`, `0.0.0.0/0` | accepted | accepted |
| IPv6 host and CIDR | **accepted** | **accepted** |
| IPv4 range `a-b` | rejected | rejected |
| address-object or group name | rejected | rejected |
| a `<description>` child | **accepted** | **rejected** |

So every entry is a literal — nothing needs resolving, unlike zone `user-acl` members which
genuinely do mix names in. IPv6 is first class, and any consumer treating the list as
IPv4-only mis-reads a v6-restricted device.

`description` is the single field the two planes do not share, which a shared model must
make nullable. **Unmeasured:** whether any deployment populates it; no lab capture has one.

A write containing one invalid entry rejects the whole element, so a stored list never holds
an entry PAN-OS considers invalid.

## Distinguish absent from empty, and pick your action deliberately

    action=get   missing node ->  status="success" code="7", empty result
    action=show  missing node ->  status="error", "No such node"

A collector treating `status="error"` as a failure will log one for a setting that is merely
unset. A collector using `action=get` cannot tell "unset" from "empty" at all.

Note also that `action=get` returns the **candidate**, so it shows another administrator's
uncommitted edits as though they were live — observed directly: `permitted-ip` read back
populated (with a `dirtyId` attribute) via `get` while `show` reported `No such node`.

The distinction is real on live devices, not a theoretical one: of the two HA peers, one has
no `deviceconfig/setting` node and the other has `<setting/>` — present and empty. That
parses to `None`, so a truthiness test reports them identically while the documents differ.
Test **key presence**, not truthiness, exactly as with a zone type subtree.

## Check where the value came from

No management-plane setting is template-pushed in this lab, but templates *can* carry
`deviceconfig`. Before reporting a management setting as local, confirm it is: read
`show config pushed-template` and look for a `deviceconfig` element. Pushed template content
carries `ptpl="<template-name>"` on every element, which both identifies the source and
inflates scalar types the way `@loc` does on pushed rules.

If it *is* template-pushed, it is also subject to the candidate problem — `show config merged`
includes template content, and reflects the candidate rather than what is enforced.

## An HA pair yields two profiles for one configuration

Non-HA fields are synchronised across peers, so a control targeting the profile produces two
identical findings for one real configuration. Deduplicate on the HA pair, not on the serial.

But do **not** assume the peers agree: the two lab firewalls differ in
`deviceconfig/system/service` and in `deviceconfig/setting` right now. Synchronisation covers
what it covers, and the management-plane subtree is evidently not all of it.


## What OptivEdgeIntegrations gives you — one model per control cluster

**`DeviceConfigurationProfile` was deleted on 2026-09-11.** It held one row per appliance spanning
three PAN-OS screens — Setup > Management, Setup > Services and High Availability — and it was
split along the CONTROL line rather than the screen, because Device > Setup is ten sub-tabs and
Management alone has thirteen sections:

| model | what it holds | screen |
|---|---|---|
| `PasswordComplexityPolicy` | the global minimum password complexity, 16 fields | Setup > Management > Minimum Password Complexity |
| `AuthenticationSettings` | idle timeout, admin lockout pair, API key lifetime | Setup > Management > Authentication Settings |
| `LoginBanner` | the banner text and whether it must be acknowledged | Setup > Management > General Settings |
| `ManagementTlsBinding` | the bound SSL/TLS profile, as a key to its row, and the certificate trust verdict | Setup > Management > General Settings |
| `MasterKey` | master key state, from `show masterkey properties` | Master Key and Diagnostics |
| `UpdateServerSettings` | whether the update server's identity is verified | Setup > Services |
| `LoggingSettings` | whether logging continues under high data-plane load | Setup > Management > Logging and Reporting |

Each reads the same parser the aggregate read, and each was compared with it field by field on the
lab before it was deleted — with one exception that is the reason the split was worth doing. The aggregate stored the bound TLS
profile's floor and certificate as RESOLVED COPIES, and they drifted from the profile rows they
were copied from. `ManagementTlsBinding` reads them through a foreign key instead; see the
discovery log, 2026-09-11.

**Management surfaces are not here.** The management planes — MGT, aux-1, aux-2 — and the data-plane
interfaces that carry a management profile are `ManagementInterface` rows, with their services and
permitted sources as rows of their own. The aggregate's `permitted_ip_count` counted the **MGT plane
only**: measured 2026-09-10, it read 0 on a firewall whose aux and data-plane surfaces held eight
permitted sources between them. Ask the surfaces.

**What went with it** — HA, NTP, hostname, time zone and that count — was read by no completed
control, so no model was cut for it and nothing stores it now. The values are still in the
merged-config snapshot; a control that needs one cuts its own model, as the seven above were.
