# Reading device configuration

> Management-plane configuration, without reporting a device clean when it is not.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-26. Re-verify after a PAN-OS upgrade.*

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
directions, the same delete has opposite security effects:

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


## What OptivEdgeIntegrations already gives you, and where it misleads

`DeviceConfigurationProfile` is the normalized model, and it is **correct on the six service
booleans** — `parse_yes_no_field(default_effective=...)` encodes the absent-key defaults and
all six match measurement. Do not re-derive them; read the model.

Two places it will mislead:

- **`has_unrestricted_permitted_ips` inverts on a hardened device.** It treats `0.0.0.0/0` as
  a wildcard, but PAN-OS strips it at compile time, so `[0.0.0.0/0, <jump host>]` is
  *restricted* and reports as open. Compute it yourself:

      effective = [e for e in permitted_ip if e != "0.0.0.0/0"]
      unrestricted = (absent) or (empty) or (effective == [])

- **`aux-1` and `aux-2` are not collected at all**, so a profile says nothing about two
  management planes — and their defaults are the *opposite* of MGT's.

The model also carries six of the ten service keys; the missing four are `disable-http-ocsp`,
`disable-userid-service` and the two User-ID syslog listeners.
