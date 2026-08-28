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
| `discovery-log.md` | How these claims were arrived at — read it to calibrate trust. |

These are not a leftovers pile. The first two are about the **transport** — sources,
parameters, payload shapes, error envelopes — and touch no configuration subtree at all.
The third is about the **partitioning construct itself**: a vsys is how every plane below
is scoped, so `identify-a-vsys` reaches into `deviceconfig`, `network` *and* `vsys/entry`.
Filing any of them under a plane would hide them from the other two.

## By plane

`policy/` — rules and the objects they reference

| guide | what it is for |
|---|---|
| `read-a-security-rule.md` | Rules, without mis-typing a pushed field or losing a rename. |
| `resolve-object-name.md` | The value a firewall actually uses for a name, across competing scopes. |
| `enumerate-object-definitions.md` | Every definition of a name, in every scope that carries one. |
| `verify-object-reached-device.md` | Confirming an object or rule actually arrived on a device. |
| `assess-object-deletion-safety.md` | Whether an object can be removed, when reference counting cannot say. |

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
