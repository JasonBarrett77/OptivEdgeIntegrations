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
| administrator account (`mgt-config/users/entry`) | the whole **entry** | every child — and a child the override did not touch is DROPPED, not inherited |

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

Measured 2026-09-10 on pan-fw-111 for an administrator: `jb` is pushed by `creds_tpl` with a role
and a password hash. Adding ONE setting on the device — `authentication-profile` — produced:

    pushed-template layer                  merged (the value in force)
      {@name: jb, @ptpl: creds_tpl,          {@name: jb,
       permissions {@ptpl ...},               permissions {role-based {superuser "yes"}},
       phash ...}                             authentication-profile "aegis_auth_prof"}

The local copy is the whole entry, and the untouched `phash` is not in it — the template still
pushes it, and it is not in force. An override does not layer one field over a pushed entry; it
replaces the entry with whatever the device-side form saved.

So a profile has **one** provenance and a management plane has **one per field**. Code that
reads provenance at a fixed depth is right for one of them and wrong for the other, and the
depth has to be decided per object rather than once.

## A marker on a CONTAINER partitions nothing inside it

The section above covers two granularities — a whole entry, or an individual leaf. There is a
third, and it is the one that misleads, because it looks like the first:

    "users": {"@ptpl": "shared-multi-vsys",
              "entry": [ … eight entries, none of them marked … ]}

That `@ptpl` says a template **contributes to this container**. It does not say the entries came
from it, and it does not say which ones did.

Measured on `mgt-config/users`, 2026-09-09, across three devices and two stacks:

| device | container marker | entries marked |
|---|---|---|
| PA-5220 ×2 | `shared-multi-vsys` | **none** of eight |
| PA-VM | `creds_tpl` | **two** of nine |

Both rows are the same rule seen from opposite ends. `shared-multi-vsys` carries
`mgt-config: {"users": null}` — an *empty* container — and pushing that is enough to mark the
merged one, over entries it contributed nothing to. `creds_tpl` genuinely contributes a user, and
its container marker is still silent about the other seven.

**So the container marker is never the answer to "where do I change this entry".** Read the
entry. Where an entry *is* pushed the marker repeats down every level under it, so a leaf inside
one arrives as `{"@ptpl": …, "#text": "yes"}` where a local one is the bare string `"yes"`.

### Why this is easy to get wrong

A container marker is present, plausible, and at the depth code tends to read. Reading it here
would report six device-local administrator accounts as template-managed — silently, and in the
direction that makes an estate look better governed than it is.

It also resists a single-device explanation. "A user was pushed and later deleted" and "some
entries are pushed and some are local" both produce the same container marker, and neither
changes what you must do about it.

*How this was settled: the template was renamed. It had been called `shared`, which read like the
shared-scope keyword and made the marker look like a scope rather than a name. Renaming it to
`shared-multi-vsys` moved the marker with it and left `shared-base` and `shared-single-vsys` —
which carry no `mgt-config` at all — marking nothing. A rename nobody performed as an experiment
turned out to be one.*

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
one is the platform's default and the other is a decision, and the remediation differs. Telling
an engineer to change a setting nobody has ever touched is not the same as telling them to
change one somebody chose.

`FieldProvenance` carries it, and since 2026-09-21 it carries what KIND of absence it was. A
present-but-unmarked key is a row typed `local`. An absent key is a row too:

| type | the key was absent and... |
|---|---|
| `pan_os_default` | PAN-OS supplies this value, and we have measured that it does |
| `assumed_default` | the stored value is our inference, not a vendor fact |
| `not_configured` | nothing was stored, because a guess would be worse than the null |

A missing row now means one thing only: nothing tracks that field. A `derived` answer, for a
column normalization computed rather than read, comes from `ProvenancedMixin.DERIVED_FIELDS`
and is never stored — derived-ness belongs to the field, not to each object.

Splitting the three mattered more than it looks. Skipping absent keys had made "PAN-OS supplies
it", "we guessed" and "nobody tracks it" share one blank, and a consumer resolving that blank
per MODEL gets it wrong per KEY: in `deviceconfig/system`, `disable-http` absent means the
service is ON while `enable-log-high-dp-load` absent means it is OFF.

It is surfaced now — `OptivEdgeProbe/scratch/provenance-for-artifacts.md` is the consumer
contract. The local-versus-overridden distinction still is not, and still should not be.

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
- Three objects were compared. Whether any other object overrides at some third granularity is
  **unmeasured** — the working assumption is entry-level for named entries and leaf-level for
  everything else. The administrator account fits it, which is one more instance and still an
  assumption.
- One PAN-OS version, one template stack.
