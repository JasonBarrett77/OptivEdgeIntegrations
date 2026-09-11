# Reading a security profile

> Anti-spyware and vulnerability profiles: whether a severity is really blocked, and which profiles anything uses.

*Established against the lab — PA-5220 (11.1.13-h3), PA-VM (11.2.3, Azure), Panorama — 2026-09-11. Re-verify after a PAN-OS upgrade or a content update.*

A security profile decides what the firewall DOES when a rule's traffic matches a threat
signature. The rule says "inspect this with profile X"; the profile says "reset critical and high,
alert on the rest". A permissive profile behind a strict-looking rule base is the commonest way a
device detects an attack and lets it proceed.

Four places carry one, and a reader needs all four:

    vsys/entry[@name]/profiles/{spyware,vulnerability}/entry[@name]   local, vsys scope
    shared/profiles/{spyware,vulnerability}/entry[@name]              local, shared scope
    the two pushed-shared-policy reads                                Panorama-pushed, by @loc
    /config/predefined/profiles/{spyware,vulnerability}               `default` and `strict`

And two things point at one, both by name:

    rulebase/security/rules/entry/profile-setting/profiles/<type>/member   a rule, directly
    profile-group/entry[@name]/<type>/member                               a Security Profile Group

## Profiles are policy objects

They live under `vsys/entry` and `shared`, so they scope like address objects: vsys scope on the
enforcement point, shared scope on the appliance group, vendor scope per point. See
`resolve-object-name.md` for the scope ladder; for profiles its order is ASSUMED, as it is for
policy objects - what a custom profile named `default` would do has not been measured.

## A rule's shape

    rules/entry[@name]
        threat-name     text; `any` for every signature
        category        one value; `any` for every category - the set is CONTENT-DEPENDENT
        severity        member list: critical high medium low informational any
        action          a CHOICE element, below
        packet-capture  disable | single-packet | extended-capture
        host            vulnerability only: any | client | server
        cve, vendor-id  vulnerability only: member lists, `any` for all

`action` is a choice: `<action><reset-both/></action>` parses to `{"reset-both": null}`, and a
pushed rule's carries `@loc` beside the choice. Eight values on both platforms: `default`, `allow`,
`alert`, `drop`, `reset-client`, `reset-server`, `reset-both`, `block-ip`.

`host` is **Invalid sequence** on a spyware rule - it exists on vulnerability rules only. The
spyware category set is 35 values on the PA-5220 and 24 on the PA-VM, because the DNS categories
arrive with content; enumerate it, never hard-code it.

A profile with no rules stores its description and nothing else - no `rules` node at all.

## What "blocked" means here

A severity is blocked when a **catch-all** rule covers it - any threat name, any category, and for
vulnerability any CVE and vendor ID - and **every** rule that can match it takes a blocking action:
`drop`, `reset-client`, `reset-server`, `reset-both` or `block-ip`.

`default` is not blocking. A signature's default action is "typically either Alert or Reset Both"
(Help p.272), so a rule set to `default` blocks only the signatures whose defaults happen to.

**The reading is order-independent.** No document says whether profile rules are first-match, and
this reading does not need to know: it cannot pass a weak profile. Its cost is that an `alert` rule
sitting BELOW a broad blocking rule still fails the severity, even though first-match would never
reach it. Both orders are subjects on the lab (`oep-spy-carveout`, `oep-spy-shadowed`).

**Vulnerability is judged per side.** A rule for `host client` covers no server-side exploit, so a
severity must pass for the client and the server separately.

## The predefined profiles are the ones that matter most

`default` and `strict` ship with the device and are not in `show config merged`. Read them with a
config get of `/config/predefined/profiles` - about 16 KB, every profile type at once.

    default   one rule per severity (critical, high, medium, low; per side for vulnerability),
              every one action `default`. No informational rule.
    strict    reset-both for critical, high and medium; `default` for low and informational.

Vulnerability `strict` stores **reset-both**, where Help p.289 says it applies "the block
response". The device is the authority.

A predefined profile matters only when something USES it. An unused `default` is on every vsys and
protects nothing; a rule protected by it is the finding. So count references before reporting one.

## Most rules reach a profile through a group

On the lab, no rule in 878 names a profile directly; rules name Security Profile Groups, and groups
name profiles. The Panorama-shared group `OutBound-Block` names the predefined vulnerability
`default`, which puts that profile in use on 8 of 9 vsys.

So a reference walk that reads only `profile-setting/profiles` misses nearly everything. Walk the
whole payload for a `spyware` or `vulnerability` key holding a MEMBER LIST, and skip the same keys
holding `entry` - those are the definitions.

## What Panorama pushes is decided per vsys view

A Panorama-shared profile that nothing referenced was in pan-fw-111's reads and in tpa's **vsys3**
per-vsys read, and absent from tpa's device-wide read and its vsys1 read. Panorama-shared profile
groups arrive in the per-vsys read with `@loc="shared"`. A vsys with no device group reads 35
characters of nothing.

It was first written up from the vsys1 view alone as "not pushed at all". Read every view before
calling a pushed object absent, and union them, as the address normalizer does.

## Reading it

1. Collect the merged config, both pushed reads for every in-scope vsys, and
   `/config/predefined/profiles` for every appliance.
2. Classify pushed entries by `@loc`, never by which read returned them.
3. For each profile, judge critical, high and medium over the whole rule list as above.
4. Walk every payload for member-list references; resolve each within its own scope first - vsys,
   then shared, then predefined.
5. Report a custom profile whether or not it is used; report a predefined one only when it is.

## Reproducing all of this

`OptivEdgeProbe/scratch/lab_security_profiles.py setup` builds every subject in one round:
passing, failing and never-configured variants on fw-core-tpa-b vsys1, a local-shared pair on
pan-fw-111, and a Panorama-shared profile pushed to both device groups. `read` reads them back,
including the tpa vsys3 view. `revert` removes them.

## Limits

- **Unmeasured:** the implicit value of `action`, `threat-name`, `category` and `host` when the
  element is absent. Every rule the devices and the predefined profiles store carries them.
  Normalization reads an absent action as non-blocking and the rest as `any`.
- **Unmeasured:** whether profile rules are first-match. The verdict above does not depend on it.
- **Unmeasured:** what a custom profile named `default` or `strict` does against the predefined
  one. Name collisions are per object type - see `resolve-object-name.md`.
- Threat exceptions (`threat-exception`) are counted, not assessed. They override a rule for one
  signature and belong to PAN-SPY-005 and PAN-VLN-004.
