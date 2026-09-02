# Reading template provenance

> Where a value came from, how much of that survives an override, and what an unmarked value
> does not tell you.

*Established against the lab — PA-5220 HA pair on 11.1.13-h3, pushed from template stack
`stack_fw-core-tpa`. Re-verify after a PAN-OS upgrade.*

## A pushed value carries `@ptpl`; an override removes it

`show config merged` marks pushed values with `@ptpl`, on the node that carries them:

    "disable-https": {"@ptpl": "stack_fw-core-tpa", "#text": "no"}

A locally defined value carries nothing and is a bare string. Overriding a pushed value on
the device makes it look locally defined — which is the whole difficulty below.

## Override granularity differs by object

| object | override granularity | what loses `@ptpl` |
|---|---|---|
| interface management profile | the whole **entry** | every attribute on the profile, and every leaf inside it |
| `deviceconfig/system` planes | the individual **leaf** | only the overridden leaf; its siblings keep theirs |

Measured side by side on one HA pair, same template stack, one peer overridden and one not:

    aux-2/service, NOT overridden          aux-2/service, disable-telnet overridden
      disable-https  {@ptpl, #text: no}      disable-https  {@ptpl, #text: no}
      disable-ssh    {@ptpl, #text: no}      disable-ssh    {@ptpl, #text: no}
      disable-telnet {@ptpl, #text: no}      disable-telnet "yes"        <- bare

    profile entry, NOT overridden          profile entry, one value overridden
      {@name, @ptpl,                         {@name,
       https {@ptpl, #text: yes},             https "yes",
       ping  {@ptpl, #text: yes}}             ping  "yes",
                                              http  "yes"}              <- all bare

So a profile has **one** provenance and a management plane has **one per field**. Code that
reads provenance at a fixed depth is right for one of them and wrong for the other, and the
depth has to be decided per object rather than once.

## An unmarked value means the device is authoritative

Provenance answers **where do I go to change this**, not what a value's history is.

    marked with @ptpl   the named template or stack decides it. Change it there, and the
                        change reaches every device that container serves.
    unmarked            the device decides it. Change it there.

An unmarked value may be locally configured, or pushed and then overridden, or actively
overriding a different value the template is pushing right now — measured 2026-09-02, a device
holding `server-verification: no` kept it when a template pushed `yes`, and the value stayed
unmarked. **All three are the same instruction:** go to the device. Merged config reports the
value in force, which is the value being assessed.

So there is nothing to resolve here, and comparing against the pushed template to separate
the three cases is not planned. It would produce a distinction with no action attached to it.

### What IS worth separating, and already is

**A key that was never written** is a different fact from one set locally to the same value:
one is the platform's default and the other is a decision. `FieldProvenance` already carries
it — an absent key gets no row at all, a present-but-unmarked key gets a row typed `local` —
because the remediation differs. Telling an engineer to change a setting nobody has ever
touched is different from telling them to change one somebody chose.

That distinction is stored today and not yet surfaced. It is the one worth surfacing; the
local-versus-overridden one is not.

## `@ptpl` names a template **or** a stack, and the difference does not matter

It names whichever container defined the value. On one device and one push,
`network/profiles/...` reported the template `ptpl_fw-core-tpa` while `deviceconfig/system`
reported the stack `stack_fw-core-tpa`.

Both push configuration, so treat them the same and carry the name through as given. Do not
parse it, and do not join it to the template list expecting a hit — a stack name will miss.

## Limits

- Both override cases were produced through the web interface. The XML API refused a plain
  `set` on a template-pushed profile entry ("may need to override template object ... first")
  and refused `action=override` on it ("Object cannot be overridden"), so the API path the
  web interface uses is **unmeasured**.
- Only `@ptpl` was exercised. `@src` was seen on a container (`src="tpl"`) but never on an
  overridden value, and device-group provenance for policy objects is untested here.
- Two objects were compared. Whether any other object overrides at some third granularity is
  **unmeasured** — the working assumption is entry-level for named entries and leaf-level for
  everything else, which is what these two show, and it is an assumption.
- One PAN-OS version, one template stack.
