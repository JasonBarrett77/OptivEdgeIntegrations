# Identifying a vsys

> Keying, matching and re-matching a vsys across collections.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-25. Re-verify after a PAN-OS upgrade.*

## Operating stance: expect best practice, verify it, report the deviation

Assume the environment is well run. Do not build machinery to survive configurations a
competent administrator would not create - that machinery is expensive, it is exercised by
nothing, and it quietly launders a broken environment into a clean-looking report.

This is not optimism. For an assessment product a deviation **is the deliverable**. A
recycled vsys slot, an HA pair whose labels disagree, a device group pushed to a vsys
lacking its zones - each is something the client is paying to be told. Silently coping with
it destroys the value of finding it.

The stance only holds if all three parts are present:

1. **State the expectation** - in the code or the doc, where someone will read it.
2. **Check it** - an expectation nobody verifies is an undocumented assumption, and it
   produces confidently wrong output the first time it fails.
3. **Report the deviation** - loudly enough that nobody mistakes its absence for all-clear.

Two of three is worse than none. "Expect best practice" must never be used to justify
assuming and proceeding. Where a check cannot be built - and for vsys re-keying, no
conclusive check exists - the expectation becomes a **stated limit of the report**, not an
implicit one.

| Expectation | How it is checked | Reported as |
|---|---|---|
| A vsys slot is not recycled for a different firewall | no conclusive check; see the signals below | prompt for a human, never an automatic re-key |
| HA peers agree on which slot holds which label | compare the label-to-slot map per peer | finding: config sync is off, or was |
| `display-name` is stable between collections | compare per slot | finding, with both readings |
| A device group names the same firewall on every peer | compare the assigned slot sets | finding |
| A vsys carries the zones its device group's rules use | the push itself validates it | finding: the push half-fails |

## Configuration paths

Written out in full, because every one of these is easy to misremember. `localhost.localdomain`
is a PAN-OS constant, not a hostname - it is the same literal on every device and on Panorama.

Below, `$D` is `/config/devices/entry[@name='localhost.localdomain']`.

**On the firewall** (XML API `type=config` with `target=<serial>`, proxied through Panorama):

| What | Path |
|---|---|
| the vsys itself | `$D/vsys/entry[@name='vsysN']` |
| the **vsys name** - the key | the `@name` attribute of that entry, always `vsys<1..N>` |
| the label | `$D/vsys/entry[@name='vsysN']/display-name` |
| ... supplied by a template | that node carries `@src="tpl"` and cannot be deleted or replaced locally |
| ... which template | the `@ptpl` attribute on the **vsys entry**, e.g. `@ptpl="ptpl_fw-core-tpa"` |
| zones | `$D/vsys/entry[@name='vsysN']/zone/entry[@name='<zone>']` |
| imported interfaces | `$D/vsys/entry[@name='vsysN']/import/network/interface` |
| HA config sync flag | `$D/deviceconfig/high-availability/group/configuration-synchronization/enabled` |

**On Panorama** (no `target`):

| What | Path |
|---|---|
| device-group membership - binds the **slot** | `$D/device-group/entry[@name='<dg>']/devices/entry[@name='<serial>']/vsys/entry[@name='vsysN']` |
| template vsys - binds the **label** | `$D/template/entry[@name='<tpl>']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='<label>']` |
| template stack | `$D/template-stack/entry[@name='<stack>']` |

Note the template path contains `/config/devices/entry[@name='localhost.localdomain']/`
**a second time**, nested inside the template entry. That is not a typo.

**Operational commands:**

| What | Command |
|---|---|
| Panorama's view of every vsys | `<show><devices><all/></devices></show>` - display-name here is **synthesised** when the device has none |
| the device's resolved config | `<show><config><merged/></config></show>` with `target=<serial>` - shows `@ptpl` and `@src` |
| policy pushed to one vsys | `<show><config><pushed-shared-policy><vsys>vsysN</vsys></pushed-shared-policy></config></show>` with `target=<serial>` |

## Identifying a vsys from a log record

Logs use three field names for the three identifiers, and the vocabulary **inverts** the
configuration one:

> ### The log vocabulary inverts the config vocabulary
>
> | Log field | Actually holds | Config equivalent |
> |---|---|---|
> | `vsys` | the **name** — `vsys3` | `@name` |
> | `vsys_name` | the **display-name** — `vsys-corp` | `display-name` |
>
> Reading either with config intuition gets it backwards. `vsys_name` is the one that
> looks safe and is not: it is the mutable, optional, Panorama-forgeable label, frozen at
> write time.

| Log field | Holds | Config equivalent |
|---|---|---|
| `vsys` | `vsys3` | `@name` — the slot key |
| `vsys_id` | `3` | the numeric suffix of `@name` (measured equal) |
| `vsys_name` | `vsys-corp` | `display-name` |

Join on **`serial` + `vsys`**, but do not mistake that for a durable key — see below. Do
not join on `device_name` or `vsys_name`: a log record freezes those at write time, so an
old record names a host and a label that may since have moved. Measured: a record reading
`device_name='PA-5220'` / `vsys_name='vsys-corp'` on a device now configured as
`fw-core-tpa-b` with vsys3 labelled `application`.

**Serial is chassis-bound, not appliance-bound.** It changes on RMA or replacement, and is
not persistent at all on Cloud NGFW; the replacement chassis adopts the configuration, so
the *hostname* carries over while the serial does not — the exact inverse of a rename. No
log field survives both events, and there is no device UUID to fall back on. Appliance
identity must be **maintained** in the model, with a change to either identifier reported
and classified (rename vs replacement) rather than minting a new appliance.

The symmetry is worth holding onto: `@name` identifies a slot rather than a firewall, and
`serial` identifies a chassis rather than an appliance. Neither layer has a durable
vendor-supplied identity.

That staleness is useful rather than merely annoying — a `vsys_name` disagreeing with the
current display-name is evidence the slot changed hands. Expect agreement; report a
mismatch.

`dg_hier_level_1..4` carry **numeric device-group ids**, zero-filled when unused, and only
Panorama's `<show><dg-hierarchy/></show>` names them. An id can outlive its device group,
so resolution is best-effort.

Reading a device's logs requires a session to **that device's own API**. `type=log` accepts
Panorama's `target=` and ignores it, answering from Panorama's log database instead — check
`device_name`/`serial` on any record before believing it.

## Key on `@name`. There is no better option.

| Identifier | Where it lives | Usable as a key? |
|---|---|---|
| `@name` (`vsysN`) | every config source | **yes** - the only one always present and always unique |
| `display-name` | config; optional | no - optional, mutable, template-owned, and Panorama forges it |
| `vsys_id` | log records only | no - absent from every config source |

`@name` is `vsys<id>`; PAN-OS calls the suffix a vsys id in its own error text. Name and id
are one identifier, not two, and the id is bounded by licence (1-10 on the lab PA-5220).

## Which key, for which construct

Panorama does not use one vsys key. It uses two, and they can disagree.

| Construct | Binds by | Carries |
|---|---|---|
| device group | `@name` - the slot | security policy |
| template / template stack | `display-name` - the label | interfaces, zones, logging, mgmt |

Relabelling a vsys therefore moves its template configuration to a different slot and
leaves its policy where it was. The slot keeps rules referencing zones it no longer has.
Neither Panorama nor the device reports this as a conflict.

Corollary: `display-name` is often **not device-local state**. When a template supplies it
the device shows `@src="tpl"`, so a collector reading display-name off the device is
reading Panorama's output, not the administrator's input.

## What `@name` actually identifies

A **slot**, not a firewall. A vsys can be deleted and a different one created in the same
slot, and Panorama's device-group assignment follows the slot - so the new vsys inherits
the old one's policy. Anything keyed on the name will reattach history, scope flags and
normalized data to a different firewall, silently.

There is no vendor-supplied durable identity to use instead. Expect that slots are not
recycled; report it when the signals below suggest one was.

## Do not match on `display-name`

- **Optional** on the device, and Panorama **synthesises** it from `@name` when absent - so
  through Panorama, "named vsys6" and "unnamed" are indistinguishable.
- Uniqueness is enforced against *configured* names only, so another vsys may legally take
  the string Panorama invented, and Panorama then reports two vsys with the same
  display-name - a state the device itself would reject.
- It may equal a *different* vsys's `@name`.
- It can be cleared, but not set empty.
- A template vsys entry **cannot be renamed**; relabelling is delete-and-recreate.

Showing it to a user is right. Matching on it is not.

## On an HA pair, read the label map per peer

The pair is one unit for shared configuration. It is **not** one unit for vsys identity.
A label can sit on vsys7 of the active and vsys10 of the passive; one template push then
lands in two different vsys, and a device group bound to vsys7 succeeds on one peer and
fails validation on the other. Both peers report the same display-name to Panorama.

Expect this not to happen: HA configuration synchronization replicates a display-name to
the peer at the next commit, so a divergence means config sync is off or was off. Report it
on that basis rather than treating it as a naming choice.

Note the trap: authoring device-group membership per peer - vsys7 on one, vsys10 on the
other - **works**, pushes cleanly, and is therefore never noticed. A device group whose two
device entries name different slots for what is logically one firewall is the signature.

When collecting from the active and treating it as authoritative for the group, the
label-to-slot map is the one thing that must not be carried across.

## Detecting that a slot changed hands

No signal is conclusive. Report them; never re-key on them.

- `display-name` changed between collections - which now means either an administrator
  relabelled the slot or a template moved, two different events with one signal
- the imported interface set under `import/network/interface` changed
- the vsys's device-group assignment changed
- pushed-policy version or md5 reset rather than advanced

Surface it. Do not silently re-key, and do not silently carry on.

## Before assigning a device group to a vsys

The vsys must already carry zones matching the group's rules. The assignment is accepted at
the Panorama write and fails only at push, once per offending rule:

    In VSYS vsys7 from zone transit of type unknown and to zone app of type unknown
    are incompatible in security rule <name>

An assignment left in that state breaks **every** subsequent push of that device group, not
just the one vsys.
