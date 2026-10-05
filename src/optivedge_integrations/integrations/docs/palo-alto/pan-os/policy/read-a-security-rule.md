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

`service` is the exception and it is below: the device refuses to commit a rule without one.

The same holds for the two log flags, and they default OPPOSITE ways:

    log-end absent    -> yes   the session IS logged at end
    log-start absent  -> no

`[MEASURED 2026-09-22]` on pan-fw-111. A shared rule was pushed carrying NEITHER key, its
absence confirmed in Panorama's running and candidate configs, in the device's
`pushed-shared-policy` and in `effective-running`, and the rule then opened in the device's own
UI: "Log at Session End" renders TICKED and "Log at Session Start" unticked.

**The Help cannot settle this and says so twice.** p.134, on the security rule screen: "Log At
Session End (enabled by default)". p.142, on Applications and Usage: "cleared by default",
about the same field. One of them is describing a different screen's form; only the device
knows which.

**A rule created through the UI writes both keys explicitly** — `log-start: no`, `log-end:
yes` — so "enabled by default" describes the CHECKBOX, not what an absent key means. Those are
different claims and only the second one tells a collector what to store. On the lab, 873
rules carry the keys and 10 carry neither.

The direction matters for the control that rests on it: an unwritten `log-end` is COMPLIANT,
not a blind spot. Reading it as "no" would have reported ten correctly-logging rules as
unlogged.

## `service` is required, and `application-default` may not share the list

**Measured:** 2026-09-16 on fw-core-tpa-a (PA-5220, 11.1.13-h3), by writing each shape to the
vsys6 scratch rulebase and committing. `OptivEdgeProbe/scratch/lab_rule_service_probe.py`.
The same facts are in `OptivEdgeProbe/reference/panos-payload-contract.json` under
`security-rule-service`, and PAN-POL-004 rests on both.

Two rules, enforced at two different times. A probe that only writes, or only commits, sees one
of them and reads the other as permitted.

**`service` is REQUIRED — refused at the COMMIT.** A rule with no `service` element is accepted
by `action=set` with `status=success`, and the commit then fails validation:

    vsys -> vsys6 -> rulebase -> security -> rules -> svc-probe-absent  is missing 'service'
    vsys -> vsys6 -> rulebase -> security -> rules is invalid

So every committed rule carries a service list. For a consumer this settles what a rule with no
service MEANS: it is one of the two predefined defaults — `intrazone-default` and
`interzone-default`, which exist in no rulebase and carry no service — or the collection lost
it. It is never an author who left the field alone, which is the reading every other absent
field gets.

**`application-default` is EXCLUSIVE — refused at the WRITE.** Writing it beside another member
never reaches a commit:

    status=error code=12
    svc-probe-mixed -> service  is invalid. 'application-default' should not be used with
    another service

So "has an `application-default` member" and "the service IS application-default" are the same
question, and a consumer needs no shape test to tell them apart.

**The member node is where the schema lives.** `action=complete` on `.../service` returns
nothing — `<completions/>`, `code=19`, which reads exactly like an invalid path and is not one.
Completing `.../service/member` returns the service objects and groups in scope plus exactly two
specials, `any` and `application-default`. Anything else in the list is an object reference.

**Effective policy resolves all three states**, which is a second oracle when the stored config
is ambiguous — `show running security-policy`, on the rule's `application/service` line:

    service any            0:any/any/any/any
    application-default    0:any/any/any/app-default
    service-https          0:any/tcp/any/443

A disabled rule appears nowhere in that output, so it cannot be checked this way.

**Unmeasured:** a service GROUP. The lab has none, so whether a group whose members are exactly
an application's default ports is distinguishable from `application-default` in the resolved
view is unknown. Nothing in the corpus depends on it yet.

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
of `dirtyId` attributes for this: `show config merged` contains uncommitted content **and
carries no `dirtyId` markers at all**. Measured by staging one edit — it appears in `merged`,
is absent from `running`, and neither carries a marker. The attributes are real, and an
`action=get` against a dirty candidate shows them on the edited node and its ancestors, but
the source collection actually reads strips them. The marker exists and never reaches us.

## When writing a rule

- `action=set` **merges** into a member list. To replace one, use `action=edit` on the
  container. A `set`-based correction that appears to succeed can leave the old members.
- A successful write is not a valid rule. Reference and schema errors come back at the
  write (`code=12`); semantic ones only fail the **commit** — negation with an `any`
  address is accepted on write and refused on commit. Always read the commit job result.
- `target` belongs to Panorama device-group rules and is refused on a local rulebase.
- `profile-setting` is a choice node: `group` XOR `profiles`, never both.
