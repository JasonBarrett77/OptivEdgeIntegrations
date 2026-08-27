# Reading a security rule

> Rules, without mis-typing a pushed field or losing a rename.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-26. Re-verify after a PAN-OS upgrade.*

## Normalise `@loc` decoration before touching a single field

A pushed rule carries `@loc` on the entry, on every container, and on every member. A local
rule carries none. The consequence is that the same field is a different Python type
depending on provenance:

    local   rule["action"]  == "allow"                                    -> True
    pushed  rule["action"]  == "allow"                                    -> False

    local   rule["source"]["member"]  == ["any"]
    pushed  rule["source"]["member"]  == [{"@loc": "...", "#text": "..."}]

This does not raise. It compares unequal and the rule is quietly mis-read. Strip attributes
and collapse `#text` **once, at the boundary**, before any field logic runs — the same
normalisation the rest of the pipeline already assumes.

Do not strip `@loc` itself without keeping it: it names the source device group, and it is
the only reliable way to attribute a pushed rule (see below).

## Read all three rulebases, per vsys

    local        vsys/entry[@name=V]/rulebase/security/rules
    pushed pre   /config/panorama/vsys/entry[@name=V]/pre-rulebase/security/rules
    pushed post  /config/panorama/vsys/entry[@name=V]/post-rulebase/security/rules

Pushed policy is stored **per vsys**, not once per device — vsys1 and vsys5 on the same
firewall held 74 and 158 pushed rules from different device groups. `show config
pushed-shared-policy` does not contain rules; do not use it to find them.

## Absence is a value, and PAN-OS will never spell it out

The device stores exactly what was written and materialises no defaults on commit, so an
absent element is never "not set yet":

    rule-type absent        -> universal
    negate-source absent    -> no
    negate-destination absent -> no
    disabled absent         -> no

Treat `<rule-type>universal</rule-type>` and an absent `rule-type` as identical; the
dataplane does.

**Unmeasured:** `log-start` / `log-end` defaults. If a consumer needs them, it needs to measure them, not assume.

## Key on `@uuid`, never on `@name`

A rename leaves `@uuid` untouched, so name-keyed correlation across two collections reports
a delete and an insert where a rename happened. `@uuid` survives edit, rename and a Panorama
push unchanged.

To attribute a device rule to the Panorama rule that produced it: take the device group from
the rule's own `@loc`, then match on `@uuid`. **Do not pick the device group by hand and
match on name** — rule names repeat across device groups, and doing exactly that produced a
confident, wrong conclusion (0/24 "uuid regenerated on push") where the correct comparison
gives 74/74 identical.

## Evaluation order is not rulebase order

Document order within a rulebase is the order the config returns, and candidate and running
agree. But the order the dataplane evaluates is pushed-pre, then local, then pushed-post,
plus the implicit `intrazone-default` and `interzone-default` that exist in no rulebase.
`show running security-policy` with `vsys=` gives that list with indices; unset, it answers
for vsys1 — which is a silent wrong answer on a multi-vsys box, not an error.

**Disabled rules are absent from it entirely.** A rule present in config and absent from
effective policy is normal, not a collection gap.

## Check the config is committed before trusting what you read

`action=get` returns the **candidate**; `action=show` returns the **running** config. Pick
one and use it consistently — the candidate's `admin`/`dirtyId`/`time` attributes make
otherwise identical documents differ.

Before treating a collection as fact, ask the device: `<check><pending-changes/></check>`.
`yes` means what was just read includes edits nobody has committed. Do not use the presence
of `dirtyId` attributes for this.

## When writing a rule

- `action=set` **merges** into a member list. To replace one, use `action=edit` on the
  container. A `set`-based correction that appears to succeed can leave the old members.
- A successful write is not a valid rule. Reference and schema errors come back at the
  write (`code=12`); semantic ones only fail the **commit** — negation with an `any`
  address is accepted on write and refused on commit. Always read the commit job result.
- `target` belongs to Panorama device-group rules and is refused on a local rulebase.
- `profile-setting` is a choice node: `group` XOR `profiles`, never both.
