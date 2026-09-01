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

## An unmarked value is ambiguous

Absent `@ptpl` means *either* locally defined *or* pushed-then-overridden-locally. The two
are byte identical in merged config, so this source cannot separate them.

Reporting an overridden value as locally defined is therefore **incomplete rather than
wrong** — it is true that the value is now local, and it omits that a template says something
different.

**Working decision:** report an unmarked value as local, which is what normalization already
produces. Resolving it properly belongs in normalization — decide provenance there, against
the pushed template, and store the result — rather than in each consumer. Comparing against
the pushed template is the established technique for this; `show config pushed-shared-policy`
is already used that way for policy scope. Not attempted, and not urgent.

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
