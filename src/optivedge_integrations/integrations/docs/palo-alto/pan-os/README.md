# PAN-OS — NGFW and Panorama

One API surface, so Panorama and the firewalls it manages share these guides; Panorama
differences are stated inline where they occur, never split into a parallel document.

Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama
(11.2.5-h1). Each guide carries its own measurement date.

## Read these first — they apply whatever you are working on

| guide | what it is for |
|---|---|
| `read-config-sources.md` | Which source answers which question, and what each one silently omits. |
| `classify-an-api-failure.md` | Which layer failed, and whether the operation nevertheless took effect. |
| `identify-a-vsys.md` | Keying, matching and re-matching a vsys across collections. |
| `read-template-provenance.md` | Where a value came from, and how much of that an override destroys. |
| `discovery-log.md` | How these claims were arrived at — read it to calibrate trust. |

These are not a leftovers pile. The first two are about the **transport** — sources,
parameters, payload shapes, error envelopes — and touch no configuration subtree at all.
The third is about the **partitioning construct itself**: a vsys is how every plane below
is scoped, so `identify-a-vsys` reaches into `deviceconfig`, `network` *and* `vsys/entry`.
The fourth is about **where a value came from**, which a template can answer for any subtree
it pushes. Filing any of them under a plane would hide them from the others.

## By plane

`policy/` — rules and the objects they reference

| guide | what it is for |
|---|---|
| `read-a-security-rule.md` | Rules, without mis-typing a pushed field or losing a rename. |
| `resolve-object-name.md` | The value a firewall actually uses for a name, across competing scopes. |
| `enumerate-object-definitions.md` | Every definition of a name, in every scope that carries one. |
| `verify-object-reached-device.md` | Confirming an object or rule actually arrived on a device. |
| `assess-object-deletion-safety.md` | Whether an object can be removed, when reference counting cannot say. |
| `read-a-security-profile.md` | Anti-spyware and vulnerability profiles: whether a severity is really blocked, and which profiles anything uses. |

`network/` — interfaces, zones and what binds them

| guide | what it is for |
|---|---|
| `read-a-zone.md` | Zone data, without inverting a default or mistaking a group for an address. |
| `read-an-interface.md` | The four places an interface lives, and which question each one answers. |
| `read-an-interface-management-profile.md` | The second management plane: which data-plane interfaces are administrative surfaces, and who may reach them. |
| `read-a-layer3-interface-field-map.md` | Which element backs each field of the Ethernet Interface dialog, and what a blank one means. |

`management/` — how the device is administered

| guide | what it is for |
|---|---|
| `read-device-configuration.md` | Management-plane configuration, without reporting a device clean when it is not. |
| `read-an-administrator-account.md` | Who can log in, with what privilege, and against what credential. |
| `read-management-ssh.md` | What the CLI SSH server offers, the default it falls back to, and why configured is not in force. |

## By topic, and by what pushes it

The three planes above are PAN-OS's config structure. This is the same material on the axis a
reader actually arrives with — a UI tab and a question — and it names the one fact that decides
which provenance mechanism applies to a subtree. **Everything here is a reference.** Each guide
states its own measurements with its own dates; nothing is restated below, because a restatement
drifts from its source and becomes a second account to reconcile.

**The two Panorama push mechanisms partition along the plane boundary, and no guide says so.**
Templates push **Device** and **Network**; device groups push **Policies** and **Objects**. Every
measurement in these guides is consistent with it — `read-template-provenance.md` establishes
`@ptpl` on `deviceconfig/system`, `config/users` and `interface-management-profile`, while
`policy/resolve-object-name.md` and `policy/enumerate-object-definitions.md` establish `@loc` on
`vsys/entry/address` and `/config/shared`, and `read-config-sources.md` C4 establishes that `loc=`
appears **zero times outside `/config/panorama`**. It is stated here rather than in either guide
because it is a fact about the pair.

### 1. Configuration files — what each read contains

| question | where |
|---|---|
| which read returns what, and what each silently omits | `read-config-sources.md`, Part A |
| whether a source is Panorama, local, merged or predefined | same, A1 — the source table |
| precedence when they must be combined | same, B1 and B2 |
| which reads carry provenance markers | same, Part C — and the two guides named above |
| payload shapes to accept, and the bare-string trap | same, A4 and A5 |
| **what you read may not be what is enforced** | same, A2 — `merged` follows the CANDIDATE. Also `policy/read-a-security-rule.md`, on checking the config is committed |
| **a pushed object is in NO read of the device's own tree** | same, A10 — `action=get` merges the template limb and not the device-group limb, and all four reads succeed while omitting it |
| dead ends, so nobody re-walks them | same, A9 |
| why runtime is out of scope here | same, A7 — the oracle you cannot ship |

### 2. Device and Network — template values

| question | where |
|---|---|
| scope, locations, shared | `identify-a-vsys.md`; `read-config-sources.md` A6 and A8 |
| what a pushed value looks like, and what an override destroys | `read-template-provenance.md` |
| override boundaries by object shape | `read-config-sources.md` B3 |
| the merge rule | same, B2 |
| HA | same, B4 |
| the planes themselves | `management/` and `network/`, above |

Template **stacks** appear in `read-template-provenance.md` only as the lab's own stack and in
`@ptpl` naming a template or a stack. **Commit options are measured nowhere.**

### 3. Policies and Objects — device group values

| question | where |
|---|---|
| the four scopes, and which read returns each | `policy/enumerate-object-definitions.md` — three reads, minimum |
| why the merged tree holds none of it | `read-config-sources.md` A10 — and a clean absence there is not evidence |
| which definition a firewall actually uses | `policy/resolve-object-name.md` — Order, step 1 before step 2 |
| rule evaluation order across pushed and local | `policy/read-a-security-rule.md` — pushed-pre, local, pushed-post, plus the two implicit defaults |
| where rules live, and that levels CONCATENATE rather than replace | `read-config-sources.md` B5 — the one place the wholesale-replacement rule does not apply |
| device-group hierarchy | `identify-a-vsys.md`, on `show dg-hierarchy`; `policy/enumerate-object-definitions.md`, on `@loc` naming the AUTHORING group |
| whether an object arrived, and whether it can be removed | `policy/verify-object-reached-device.md`; `policy/assess-object-deletion-safety.md` |
| the plane itself | `policy/`, above |

**Open, and stated by the guides themselves:** tags and schedules have known namespaces and
unmeasured precedence; a shared-scope group containing a vsys-scope member is marked *never
tried*. Both in `policy/resolve-object-name.md`.

### 4. Default and implicit values — in code, not in prose

**This topic's authority is code, and that is deliberate.** `platforms/pan_os/normalization/
common.py` defines `Implicit`, whose citation travels beside the value it justifies *"rather than
in a database column that would copy a constant and then drift from it"*. Do not restate a default
in a guide.

| question | where |
|---|---|
| what PAN-OS does when a key is absent | `Implicit` in `normalization/common.py` |
| whether we measured it, inferred it, or store nothing | the three constructors — `measured` needs a checkable citation, `assumed` needs its reasoning, `not_assumed` stores null on purpose |
| what stops the three being mixed | `ImplicitDeclarationTests` in `integrations/tests.py` |
| predefined objects, including the ones named `default` | `read-config-sources.md` on the `/config/predefined` read; `policy/read-a-security-profile.md` on the predefined vulnerability `default` |

### 5. Provenance — reading it, and where it lands

| question | where |
|---|---|
| template provenance | `read-template-provenance.md` |
| device-group provenance — the markers | `read-config-sources.md` C4 — `loc=`, `overrides=`, `panorama="true"`, and why `src="tpl"` is not one |
| device-group provenance — classifying with them | `policy/enumerate-object-definitions.md` and `policy/resolve-object-name.md`, on classifying by `@loc` and never by which query returned it |
| one attribute, two meanings by position | `read-config-sources.md` B5 — `@panorama` is a routing flag on an entry and a provenance marker on a scalar |
| `@loc` decoration on every container and member | `policy/read-a-security-rule.md` — applies to every pushed object, not only rules |
| overrides | `read-config-sources.md` B3 and `read-template-provenance.md` |
| markers, and what they cannot tell you | `read-config-sources.md` C1, C2, C3 |
| where provenance is STORED, and what a missing row means | `read-config-sources.md` Part D; `models/provenance.py` |

### Not a topic above, and first-class anyway

`classify-an-api-failure.md`, `identify-a-vsys.md` and `discovery-log.md` are in **Read these
first** for the reasons that section gives. They are transport, partitioning and provenance-of-
claims — none of them is a subtree, and none belongs under a topic here.

## Where a new guide goes

**Ask which configuration subtree it reads.** The three planes are not an invented taxonomy —
they are PAN-OS's own top-level config structure, so the test is mechanical rather than a
matter of judgement:

    deviceconfig/…              -> management/
    network/…                   -> network/
    vsys/entry/… , shared/…     -> policy/
    several, or none            -> top level

"None" is the transport case and "several" is the cross-cutting case; both belong at the top
level, and both are rare. When the current guides were checked against this test they sorted
themselves — `read-device-configuration` reads `deviceconfig` eleven times and nothing else,
`read-a-security-rule` reads `rulebase` eight times, while `read-config-sources` and
`classify-an-api-failure` reference no subtree whatsoever.

## More planes, and topics that are not planes

Two different things will come up, and they want different handling.

**Another plane.** Monitor — logs, reports, log collection — is the evident one, and it is a
plane in its own right rather than a gap in the three above. It gets a directory when it
gets a guide.

**A topic that decomposes across planes.** Certificates, User-ID and decryption each have
parts in more than one plane: a certificate is a management-plane object, a network-plane
credential and a policy-plane input, and decryption sits across at least two. Split them.
The parts really are different enough to live apart, and the decomposition is not an argument
against the plane boundary — a certificate's management aspect has far more in common with
the rest of `management/` than with its own policy aspect.

So a topic spanning planes is **not** a reason to create a topic directory. The only thing
that earns a directory here is a plane. Where a split leaves the parts needing to find each
other, link between them; that is what links are for.

Nothing above has a guide, and there is deliberately no empty directory for any of it. An
empty directory claims someone looked; this section claims only that nobody has.
