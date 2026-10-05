# Reading config sources safely

> Which source answers which question, what each one silently omits, and how PAN-OS combines
> them into the configuration a firewall actually enforces.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) —
through 2026-09-15. Re-verify after a PAN-OS upgrade.*

**The failure mode of every item here is a plausible wrong answer, not an error.**

## How to read this file

Written for someone who has to collect PAN-OS configuration and has never seen this estate.
**Part A is collection and is the part to read first.** Part B is how the sources combine. Part C
is provenance. **Part D is normalization and can wait** until collection works.

Every claim carries a tag:

| tag | means |
|---|---|
| `[MEASURED date]` | observed on lab hardware on that date; reproducible |
| `[VENDOR]` | stated in Palo Alto documentation |
| `[INFERRED]` | reasoned from measurements, not directly observed |
| `[UNVERIFIED]` | believed, never tested — treat as a question |
| `[TRAP]` | a wrong answer that looks right; the reason this file exists |


## Find it fast

| If you are asking | Go to |
|---|---|
| Which command returns what | A1 |
| Why my collection shows config the device is not enforcing | A2 |
| Why my read came back as vsys1 / the wrong device | A3 |
| Why my parser broke on the pushed response | A4, A5 |
| A vsys returned a string instead of XML | A5 |
| A vsys has no device group — do I skip shared objects? | A6 |
| How do I know my reconstruction is right | A7 |
| What should I actually collect | A8 |
| Can I diff the candidate against running | A9 |
| Why is there no single "give me the effective config" command | B1 |
| How do the sources combine into what the device enforces | B2 |
| A template value vanished after someone edited the object | B3 |
| Two identical findings for one configuration | B4 |
| Where did this value come from, and which template | C1 |
| A template value has no marker | C2 |
| The template reports a value the device does not use | C3 |
| How is provenance stored, and what does a blank mean | D1 |
| Does this belong to the appliance or the vsys | D2 |
| What is still unanswered | D3 |

Tag lines under each heading are keyword tags for searching; `[MEASURED]` / `[TRAP]` and friends
are reliability tags (see the table above).

---

# PART A — COLLECTION

## A1. The sources

`tags:` sources, commands, running, candidate, merged, pushed-template, pushed-shared-policy, effective-running, what-contains-what

All are `type=op` commands. Through Panorama add `&target=<serial>`.

| Source | Contains | Does **not** contain |
|---|---|---|
| `show config running` | firewall-local **committed** config | template config, any pushed policy object |
| `show config candidate` | firewall-local **uncommitted** config | template config, any pushed policy object |
| `show config pushed-template` | the **template contribution alone**, every value carrying `@ptpl` | local config, policy objects |
| `show config merged` | **candidate** + `pushed-template` | **any pushed policy object** |
| `show config pushed-shared-policy` | Panorama **Shared** policy/objects | local config |
| `show config pushed-shared-policy vsys <N>` | Panorama **device-group** policy/objects for that vsys | local config |
| `show config effective-running` | the **whole effective configuration** | — **superuser only**, see A7 |

`[VENDOR]` `[MEASURED 2026-08-05]` `merged` is a *template* merge view, not an effective-policy
view. Palo Alto documents the commands as separate, with no "include shared policy" option on
`merged`; the separation dates to at least PAN-OS 7.1. No inclusive variant exists.

## A2. `[TRAP]` `merged` follows the CANDIDATE

`tags:` merged, candidate, uncommitted, staleness, guard, pending-changes, list-changes, dirtyId, trap

`[MEASURED 2026-08-25, re-confirmed 2026-09-14]` `merged` reports what an administrator has
typed, not what the firewall enforces. Staging one address object and not committing it:

    merged      sees it          running   does not
    candidate   sees it          effective-running   does not

Three failures, in rising order of nastiness:

- **addition** — a collection contains an object that enforces nothing. Over-reports.
- **deletion** — an object that is actively enforcing is absent from the collection. Under-reports,
  and nothing downstream can notice: it simply is not there.
- **modification** — same object, same name, different value. **Nothing looks wrong at any layer.**

`[MEASURED 2026-08-26]` Do **not** try to detect this with `dirtyId`: `merged` carries uncommitted
content and **no `dirtyId` markers at all**. The attributes exist on `action=get` against a dirty
candidate, but the collection reads strip them.

### The guard

`[MEASURED 2026-08-26]` Ask the device: `<check><pending-changes/></check>`. It is journal-based,
so a net-zero edit still answers `yes` — it **over**-reports, which is the safe direction. It cannot
prove two configs are equal.

`[MEASURED 2026-09-14]` `show config list changes` returns a structured journal naming the **xpath**
of every staged change, and `null` on a clean device:

    {"journal": {"entry": [{"xpath": "...vsys/entry[vsys1]/address", "owner": "admin",
                            "action": "EDIT", "admin-history": "admin", "component-type": "vsys"}]}}

Use it to say *which subtrees* are contaminated. Note the xpath is the **container**, not the entry.

**Check pending-changes before AND after a collection.** A collection taken while the candidate is
dirty must be flagged, not silently normalized.

## A3. Required parameters

`tags:` parameters, vsys=, target=, panorama-proxy, logs, api

- **`vsys=`** on the per-vsys pushed query, or `[TRAP]` you get vsys1 silently.
- **`target=<serial>`** proxies through Panorama, for `type=config` and `type=op`.
  `[MEASURED 2026-08-25]` `type=log` accepts it and **silently ignores it**, answering from
  Panorama's own log database with plausible, well-formed, wrong records. `type=version` likewise
  returns Panorama's version. Check `device_name` / `serial` on any log record.
- `[MEASURED 2026-09-14]` `target=` also selects the **schema** for `action=complete`. A wrong
  target answers `Invalid sequence`, which reads as "this path is not real".

## A4. Payload shapes to accept

`tags:` payload-shape, pushed-shared-policy, multi-vsys, single-vsys, parsing

`[MEASURED 2026-08-05]` The non-vsys pushed response roots differently by device:

    result.shared             multi-vsys PA-5220
    result.policy.panorama    single-vsys PA-VM

Try one root, fall back to the other. Never branch on device type — the shape follows vsys mode.

`[MEASURED 2026-09-15]` On the single-vsys device the bare and `vsys1` responses are **byte-identical**
(82,454 chars) and carry BOTH `panorama` and `shared` children. On the multi-vsys device they are
different reads: bare = Shared (56,717 chars), per-vsys = device-group policy.

## A5. `[TRAP]` The bare string is expected on one form and not the other

`tags:` bare-string, no-device-group, error-handling, raise-vs-tolerate, parsing, trap

`[MEASURED 2026-08-05]` The **per-vsys** read returns a plain string when the vsys has no
device-group assignment:

    'No shared policy pushed to device'

An ordinary state. Tolerate it as an empty pushed-vsys scope. A parser that assumes a dict loses
those vsys **silently** — `[MEASURED 2026-09-15]` three of nine vsys on `fw-core-tpa-a` answer this way.

The **non-vsys** read is different and must not be made symmetric: a non-XML answer there has never
been observed. **Raise**, including the payload value in the message. Returning `{}` converts an
unexplained response into a confident "no shared objects".

An invalid vsys name is a third outcome: `status=error code=17 'vsys99 is invalid vsys...'`. Raise.

## A6. `[TRAP]` An empty pushed read does not mean an empty object set

`tags:` shared-scope, device-group, address-objects, per-vsys, union, trap

`[MEASURED 2026-08-05]` A device-group-less vsys still resolves **Panorama-Shared** objects; they
arrive in the device's shared scope, which device-group membership does not govern. Skipping
shared-scope collection because the per-vsys read was empty drops 182 address objects on the lab
PA-5220 alone.

`[OPEN, established from a production failure 2026-08-19]` Panorama may push a **different Shared
set to each vsys**. Deriving a device's shared scope from one representative vsys dropped objects in
a real deployment (`unresolved address reference`). **Read every vsys and union the result.** The lab
cannot currently reproduce this.

## A7. `effective-running` — the oracle you cannot ship

`tags:` effective-running, superuser, oracle, predefined, grading

`[MEASURED 2026-09-14]` `show config effective-running` returns the whole effective configuration,
correct on every point below. It **requires superuser**, so it is a discovery instrument for
grading a reconstruction, not a collection source.

`[MEASURED 2026-09-14]` It carries **no `/config/predefined`** node on either platform, and no
`default`/`strict` security profiles. Same for `merged` `[MEASURED 2026-09-02]`; read predefined
content with a `config get` of `/config/predefined/...` (~16 KB for every profile type).

## A8. What the collection set should be

`tags:` collection-set, design, what-to-collect, options, recommendation

`[MEASURED 2026-09-15]` Either of these reconstructs the effective configuration **exactly** —
graded against `effective-running` on three devices, 107k+ values, zero wrong:

**Option 1 — fewest moving parts.** `merged` + `pushed-shared-policy` (bare and per-vsys).
The device performs all override resolution itself. Requires the A2 candidate guard.

**Option 2 — candidate-immune.** `running` + `pushed-template` + `pushed-shared-policy`, combined
by the rule in B2. Reads no candidate-derived source, but needs the object-boundary knowledge in B3,
which is incomplete by construction.

Provenance needs `running` in either case — see C2.

## A9. Dead ends, so nobody re-walks them

`tags:` dead-ends, config-diff, synced-diff, jobs, do-not-retry

`[MEASURED 2026-09-15]`

| Attempt | Outcome |
|---|---|
| `show config diff` over the API | `invalid client cli` — CLI only |
| `diff config ...` (any variant) | enqueues a `Preview-Chg` job; output is a curly-brace temp file the API cannot fetch (`export` fails; `show config saved` rejects the 70-char path, 64 max) |
| `show config synced-diff` | works, but 837/837 lines of unified-diff text over set-format braces, no xpaths — HA peer sync, not candidate |
| `object-xpaths` argument | input scoping only; does not emit xpaths |

---

# PART B — HOW THE SOURCES COMBINE

## B1. No single command returns committed-local + template

`tags:` overlay, template, running, arithmetic, composition

`[MEASURED 2026-08-25]` Template configuration is **not** committed into the running config. It is
an overlay applied at read time:

    running          = local, COMMITTED only        - no template content, no @ptpl
    candidate        = local, UNCOMMITTED           - no template content, no @ptpl
    pushed-template  = the template contribution alone, every value marked
    merged           = candidate + pushed-template

`[MEASURED 2026-09-14]` Arithmetic confirms it: on `pan-fw-111`, merged 1,129,540 chars ≈ running
21,683 + pushed-template 1,108,684. `@loc` (the pushed-policy marker) appears **zero** times in
merged on either platform.

## B2. The merge rule

`tags:` merge-rule, reconstruction, path-transform, rulebase, pre-rulebase, post-rulebase, empty-containers

`[MEASURED 2026-09-14/15]` Applied in order, first writer wins per path. Scored 100% against the
oracle on all three devices:

    1. pushed-template          all values, minus those inside an overridden object (B3)
    2. running                  local committed config; local wins on any collision
    3. pushed-shared-policy     per vsys, transformed:
                                  /policy/panorama/X               -> /vsys/entry[N]/X
                                  /policy/panorama/pre-rulebase/X  -> /vsys/entry[N]/rulebase/X
                                  /policy/panorama/post-rulebase/X -> /vsys/entry[N]/rulebase/X
    4. pushed-shared-policy     bare = Panorama Shared -> /shared/X
    5. drop                     values serialising as <empty> or None

`[TRAP]` `[MEASURED 2026-09-15]` **The effective config has no pre/post-rulebase split.** PAN-OS folds
both into the vsys's single `rulebase` alongside local rules. Preserving the source skeleton cost
8,144 values and scored 77.6%.

## B3. Override boundaries differ by object type

`tags:` override, object-boundary, action=override, named-entry, container, schema, trap

`[MEASURED 2026-09-14/15]` **The element submitted with `action=override` BECOMES the object.**
Anything absent from it is gone from the effective config, even though `pushed-template` still
supplies it. Not "replace whole", not "merge child-by-child".

Three behaviours, and the path shape does **not** tell you which applies:

| Shape | Behaviour | Examples |
|---|---|---|
| **Named entry = object** | local entry replaces the template's whole entry | admin accounts, zones, LDAP/SSL-TLS profiles, certificates, interface-management profiles, loopback units, syslog profiles, QoS interface entries |
| **Nested named entry** | belongs to its OUTER object; not overridable alone | `ldap/entry/server/entry`, `syslog/entry/server/entry` |
| **Unnamed container = object** | any local content replaces the template's WHOLE container | `deviceconfig/system/route/service` |
| **Structural container** | always merges; children from both sides survive | `/shared`, `mgt-config/users`, `deviceconfig/system`, `entry[localhost.localdomain]`, `vsys/entry[vsysN]` |

`[MEASURED 2026-09-15]` The decisive contrast: `mgt-config/users` and `route/service` have the same
shape — a container of named entries. For users the object is each **entry**, so local and template
accounts coexist. For service routes the object is the **container**: a local `mdm` route made the
template's `netflow` route disappear entirely.

**Ask the device.** It names the boundary in its own error messages:

    leaf write inside a template object -> "set failed, may need to override template object <X> first"
    override of something that is not an object -> "Object cannot be overridden"

`[MEASURED 2026-09-15]` `action=override` mechanics: the **xpath names the parent container** and the
element carries `<entry name=…>`; the element is **schema-validated in full**, so a fragment naming
only the field to change is refused. Deleting the local entry and committing restores the template
value exactly (drift 0).

`[MEASURED 2026-09-15]` `[UNVERIFIED cause]` An **empty template container still locks local writes**
beneath it: local service routes stayed refused until the template's whole `route` node was removed.

## B4. HA

`tags:` ha, peers, duplicate-findings, dedupe, collect-both

`[MEASURED 2026-09-14]` `deviceconfig` non-HA fields are synchronised across peers, so a control
targeting a device-wide model yields two identical findings for one real configuration. Deduplicate
on the HA pair, not the serial. `[MEASURED 2026-09-15]` Collect from **both** peers: their configs
are not identical (40,468 vs 41,026 values in the lab).

---

# PART C — PROVENANCE

## C1. `[TRAP]` A value's own marker is right; walking up the tree is not

`tags:` provenance, @ptpl, markers, inheritance, template-name, trap

`[MEASURED 2026-09-15]` In `merged`, a pushed value carries `@ptpl` naming its source template, on
the node that carries it:

    "disable-https": {"@ptpl": "stack_fw-core-tpa", "#text": "no"}

A locally defined value is a bare string. Overriding a pushed value makes it look locally defined,
which is correct: it *is* local now.

Scored on three devices, content-preview excluded: every value carrying its own marker is
template-sourced, with the right template name (24/24, 49/49, 51/51), and **no local value carries
a marker**.

**Do not inherit a marker from an ancestor.** Markers sit at the *highest* node of a template
contribution, including containers that also hold local content (`/shared`, `/mgt-config`, every
`vsys/entry[N]`, the config root). Inheriting mislabels every local value beneath them. Worse, it
can name the **wrong template**: `template_admin_user` comes from `temp-stck-jb-rg` while its
containers `/mgt-config/users` and `/mgt-config` are marked `creds_tpl`.

## C2. What markers cannot tell you

`tags:` provenance, gaps, secrets, phash, private-key, display-name, content-preview, running-membership, @src

`[MEASURED 2026-09-15]` Template values with **no marker of their own**:

| Value | Where the marker is |
|---|---|
| `users/entry[X]/phash`, `certificate/entry[X]/private-key` | on the entry — these are redacted secrets |
| `vsys/entry[N]/display-name` | on the vsys entry, which is also marked when `display-name` is local |
| content-preview applications (~24,763 values) | on the container above their entries |

**So derive local-vs-template from `running` membership, not from markers.** A value present in
`running` is local; otherwise it came from the template.

`[MEASURED 2026-09-18]` For a container of ENTRIES there is a cheaper way to read that
membership than fetching `running`: `type=config&action=complete` on the container returns
exactly the entry names present in `running`, in one small response. **It is the LOCAL set, not
what the device is running** - the two differ, and the difference is the whole point of this
section. On fw-core-tpa-a:

| source | vsys | `vsys8` |
|---|---|---|
| `show config running` | 8 | no |
| `action=complete` | 8 | **no** |
| `action=get` (candidate) | 9 | yes |
| `show config merged` | 9 | yes |
| `show config effective-running` | 9 | yes |

`vsys8` comes from the pushed template and is OPERATING: `show config pushed-shared-policy vsys
vsys8` succeeds, while `vsys99` on the same command is refused with "vsys99 is invalid vsys", so
the device validates the name and accepts this one. **A collector enumerating vsys from
`running` or from `complete` therefore drops a live vsys and every pushed rule in it** - silently,
because the other eight still answer. Enumerate from `merged` or `effective-running` when the
question is what the device is running; `running` and `complete` answer only what it defines
itself.

**OptivEdgeIntegrations does not have that bug, and this is not a bug report.** Its enforcement
points come from Panorama's `show devices all`, which reports all nine vsys for each HA member,
and the lab database holds a `vsys8` enforcement point accordingly - with zero rules, because
that vsys's pushed policy is genuinely empty. Checked 2026-09-18 so that the caution above does
not send the next reader looking for a defect that is not there. The caution is about the two
sources, not about this pipeline. Measured on two containers -
the vsys list (8 completions against 9 in the candidate; `vsys8` is template-only) and the
interface-management profiles (3 against 4; `oep-tpl-bound` is template-only) - and on a third
holding no template-only entry, where all three sources agree. Template MARKING is not the
discriminator: five of the nine vsys carry template markers on their children and complete lists
them. Two containers on one device; it says nothing about completing a leaf, where the values
returned are an enum rather than a membership list. Take the template *name* from the value's
own marker, or failing that its named entry's marker — never a container's.

`[MEASURED 2026-09-15, CORRECTED 2026-09-18]` `@src="tpl"` **does exist on this hardware** - the
2026-09-15 sentence here said it did not, and it was measured over four sources that genuinely
carry none rather than over all of them.

Where it appears, counted over the whole config on fw-core-tpa-a:

| read | `@src="tpl"` | `@ptpl` |
|---|---|---|
| `type=config&action=get` (candidate) | **29,859** | 221 |
| `type=config&action=show` (running) | 0 | 0 |
| `show config merged` | 0 | 108 |
| `show config pushed-template` | 0 | 113 |
| `show config effective-running` | 0 | 92 |

So the marker belongs to the CANDIDATE read, and every op-command source uses `@ptpl` instead.
The original claim was drawn from the op sources and from submitting `src='tpl'` on an override,
which still changes nothing. `identify-a-vsys.md` in OptivEdgeIntegrations said `@src="tpl"` all
along and was right; this draft contradicted it.

**What does not change:** derive local-vs-template from `running` membership. `@src` marks
template-supplied nodes in the candidate, but override detection was measured at 100% from
`running` membership and at 99.98% from markers, and that comparison stands.

## C3. After an override, `pushed-template` is not evidence

`tags:` provenance, override, pushed-template, credentials, collector-trap

`[MEASURED 2026-09-14/15]` The template keeps reporting every value it supplies for an overridden
object, and the device uses none of them. A reader of `pushed-template` alone reports values that
are not in effect — including credentials, which are dropped like any other unrestated value.

---

# PART D — NORMALIZATION (read after collection works)

## D1. Provenance storage

`tags:` normalization, FieldProvenance, ProvenancedMixin, absence, coverage

`ProvenancedMixin` + `FieldProvenance` rows, never a bespoke column. One row per tracked field per
object, generic FK, with `provenance_type` ∈ `local | template | device_group | panorama | unknown`,
plus `raw_key` and `raw_value`.

`[TRAP]` **Absence of a row is not "local".** A missing row means the key was absent from the source
payload and nothing should be inferred. A local value HAS a row, typed `local`, with an empty
`raw_value`. `field_name="__entry__"` is the entry's own provenance.

`[MEASURED 2026-09-14]` Coverage in the lab: 6,912 rows — 4,889 `device_group`, 1,974 `local`,
49 `template`. Three subject models carry **none at all** (`MasterKey`, `LoggingSettings`,
`SnmpSettings`), so a blank provenance column is data, not an error.

## D2. Scoping

`tags:` normalization, scoping, EnforcementPoint, Appliance, vsys, multi-vsys

vsys-scoped content → `EnforcementPoint`; everything else → `Appliance`. Scope follows the config
subtree the value came from, never which read returned it.

`[MEASURED 2026-08-24]` `vsys1` exists on single-vsys platforms too, so its presence proves nothing
about multi-vsys mode — check the `multi-vsys` flag separately. Enumerate vsys from the **device's
own config**, not from Panorama's assignment records.

## D3. `[UNVERIFIED]` Open questions for whoever normalizes next

`tags:` normalization, open-questions, devicegroups, shared-policy-md5sum, todo

- Do the OEI normalizers inherit structural-entry markers, or mis-read container-marked subtrees,
  for the objects they actually normalize? Not checked.
- `show devicegroups` is an **unconsumed** Panorama source carrying device-group membership and a
  per-device `shared-policy-md5sum` — the only observed signal for whether a device's pushed policy
  is current. `[MEASURED]` It does not exist on a firewall, and `shared-policy-md5sum` was seen twice
  under one device entry, so it needs `force_list`.

---

# APPENDIX

## Quick reference

    <show><config><running/></config></show>
    <show><config><candidate/></config></show>
    <show><config><merged/></config></show>
    <show><config><pushed-template/></config></show>
    <show><config><pushed-shared-policy/></config></show>
    <show><config><pushed-shared-policy><vsys>vsysN</vsys></pushed-shared-policy></config></show>
    <show><config><effective-running/></config></show>          superuser only
    <check><pending-changes></pending-changes></check>
    <show><config><list><changes/></list></config></show>

    type=config&action=show    the ACTIVE (running) config        [VENDOR, API guide p.22]
    type=config&action=get     the CANDIDATE config               [VENDOR, API guide p.22]
    type=config&action=override&xpath=<parent>&element=<entry …>  [VENDOR, API guide p.30]

`[MEASURED 2026-09-15]` `[UNVERIFIED by vendor doc]` `action=get` returns template content **with**
`@ptpl` markers, which the guide's two-line table does not mention. `action=show` returns local
committed content only, with no markers.

## A successful read is not necessarily a read

`status="success"` with `code="7"` and an empty result means *no matches* — and a malformed xpath
returns exactly the same thing, as does a `config get` with no xpath. See `classify-an-api-failure`.

## Runtime instruments

`show running security-policy-addresses` reports compiled addresses per rule index — the only way to
see which definition *won*, since configuration reads never name a winner. Requires `vsys=`.

`test <security-policy-match>` works over the XML API with `target=`/`vsys=` and numeric protocol,
but is weaker: `any` is not a valid zone, and an earlier terminal `allow` ends evaluation.

## Where the evidence lives

    OptivEdgeProbe/archive/catalog/findings/    merged-config-is-candidate-based, merged-excludes-pushed-objects,
                                               config-write-and-read-semantics, pushed-shared-policy-payload-shapes,
                                               vsys-without-device-group, per-vsys-shared-set-divergence,
                                               address-object-sources, local-override-precedence, object-resolution-model
    OptivEdgeProbe/scratch/                     merge-behavior-validation.md (every 2026-09-14/15 measurement),
                                               merge-behaviour-SUMMARY.md, merge_rule.py (the rule, executable),
                                               merge_harness.py, classify_override_units.py, compare_merged_vs_rule.py
    OEI docs/palo-alto/pan-os/                  read-template-provenance.md, read-a-security-rule.md,
                                               management/read-device-configuration.md, identify-a-vsys.md
    OEI platforms/pan_os/collectors/            merged_config.py, pushed_shared_policy.py, predefined.py

---

## Draft notes — not part of the doc

For Jason's review before this replaces
`OEI/src/optivedge_integrations/integrations/docs/palo-alto/pan-os/read-config-sources.md`.

**What is new relative to the current file:** `effective-running` and the whole of Part B (the merge
rule, override boundaries, the pre/post-rulebase collapse); Part C (own-marker provenance, the
walking-up trap, what markers cannot say); the candidate guard via `show config list changes`; the
dead ends in A9; the collection-set recommendation in A8; and Part D.

**What was kept verbatim in substance:** the source table, the candidate warning, required
parameters, both payload shapes, the bare-string asymmetry, the empty-pushed-read trap, the
success-is-not-a-read note, and the runtime instruments.

**Overlap to settle:** Part C duplicates ground now covered by `read-template-provenance.md`, whose
granularity table is contradicted by the 2026-09-15 measurements (see
`scratch/doc-drafts/merge-behaviour/read-template-provenance-corrections.md`). Either that file is
corrected and Part C points at it, or Part C absorbs it and that file shrinks. Worth deciding before
promotion rather than leaving two accounts.
