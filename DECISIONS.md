# DECISIONS

Decisions about code that LOOKS dead and is not, and about shapes that look wrong and are
deliberate. **This exists because `CLAUDE.md` correctly excludes them and excluding them loses
something real.**

Jason's standard for the instruction file is that every claim be checkable against code in one
step, with nothing about history. That standard is right, and it drops the recorded decisions about
code that LOOKS dead and is not. Those are the most dangerous things to lose: a competent session
finds an unlinked route or a model whose generic foreign key dangles and cleans it up — which is
exactly what each quote was recorded to prevent.

So they belong in a file of their own, with a different standard: **every entry names who decided,
when, and what a session would otherwise do.** The instruction file points here in one line.

---

## Routes left in place with no page linking them

**Decided by Jason, 2026-09-25:** *"Leave them, but record the decision so I can revisit later. I
might create a hidden view for some of these options."*

The UI rework took their buttons away. Each still works as a POST/GET and each still has a passing
test:

    management_station_bulk_in_scope_sync        "Refresh All In Scope", was on the station list
    management_station_refresh_dynamic_content   EDL/FQDN refresh alone, now folded into step 3
    appliance_group_snapshots                    only linked from the removed Appliance Groups tab
    enforcement_point_addresses                  only linked from the removed EP "Actions" column

**What a session would otherwise do:** find four routes nothing links to, with tests that pass, and
delete them as dead code. The tests passing is what makes them look safe to remove.

## Notes are off the menu, and knowingly broken

**Decided by Jason, 2026-10-15:** *"for now, I think we just break notes and remove it from the
menu."*

A `Note` attaches to its object by content type and DATABASE ID, with no cascade. Normalization
deletes and recreates security rules, so every note on a rule lost its target the first time the
configuration was re-normalized — silently, because a generic foreign key to a missing row is not
an error. Notes on objects updated in place survived, which made the failure look selective rather
than total.

The routes, views, model and data are left as they are. **Bringing notes back needs a key that
survives normalization** — the object's type, scope and name rather than its id — and nothing short
of that is worth re-linking.

**What a session would otherwise do:** see a model with dangling generic foreign keys and either
"fix" the cascade (which does not address the cause) or re-link the menu item (which re-exposes a
broken feature).

## There is no enforcement-point list page

**Decided 2026-09-25.** `/integrations/enforcement-points/` and its sidebar item were folded into
the station's Enforcement Points tab, which carries the All / In Scope / Out of Scope filter and
links each row to `enforcement_point_detail`.

The filter defaults to **All** where the old list defaulted to in-scope, and that is deliberate:
the tab is where scope is chosen, so hiding out-of-scope points would hide the rows an operator
came to change.

**Revisit when** a hidden page on the `/developer/` pattern is built for them, or delete them then.

## There is no CI, by decision

github.com does not support server-side hooks, and **by decision this project does not run GitHub
Actions.** The `.githooks/` hooks are therefore the ONLY enforcement.

**What a session would otherwise do:** treat `--no-verify` as deferring a check to CI. There is no
CI. Bypassing a hook is not deferring a check, it is removing it.

This one is a hair's breadth from belonging in the instruction file rather than here — the
*instruction* ("never `--no-verify`") is in the rebuilt file already; what is here is the REASON,
which is a fact about a decision rather than about code.

## `/developer/` is deliberately absent from the navigation

`DeveloperView` renders the live census, captures labelled snapshots and compares any two. It is
deliberately not in `app_meta.py`'s `SIDEBAR_SECTION`, reachable only by typing the URL, **and a
test asserts that** so it does not drift into the navigation.

It is not access-controlled by this package, which has no auth model at all. A downstream project
exposing it publicly must gate it in its own middleware or URL conf.

**What a session would otherwise do:** add it to the sidebar as an oversight-looking omission, and
publish an ungated page in whatever deployment picks the package up.

## `establish-a-fact.md` is frozen

`OptivEdgeProbe/archive/catalog/procedures/establish-a-fact.md` consolidates this project's method
lessons and is worth reading before measuring anything — **but it is frozen.** New lessons go beside
the code they bear on, not there.

**What a session would otherwise do:** add a lesson to it, where nobody will read it, instead of
next to the thing it is about.

---

## Two method lessons with nowhere else to live

The rebuild excluded these for having no line to cite, and they are true, cheap and repeatedly
costly. They are facts about Django and about testing rather than about this codebase, which is
why they anchor to nothing in it.

- **Test a page by RENDERING it, not by calling the function.** The address explainer's own tests
  all called `explain_address_reference()` directly, so the template was never exercised with an
  explanation present and it 500'd on first real use. A view's `try/except` cannot help: a template
  error happens after the view returns.
- **Django resolves a `default:` filter argument eagerly**, so `{{ a|default:b }}` raises when `b`
  is absent. Prefer building a single display string in Python.

## Principles without a citation - DECIDED

**Decided by Jason, 2026-10-21:** allow them, marked as such, capped at a handful. `CLAUDE.md`
now carries a "Principles, which cite nothing" section holding the one this question was about -
"failure must be proportionate to what is unknown".

**What a session would otherwise do:** delete an uncited line from `CLAUDE.md` for breaking the
file's own standard, or refuse to write a principle down at all because it anchors to no line.
## Report provenance at the layer where an override can occur

> **The override boundary is the coarsest level that is never wrong.**

**Decided by Jason, 2026-10-21:** *"We'll generally report at the logical layer, which likely
aligns with where an override can occur."* And on the scale of it: *"We decide at what level to
report provenance at the presentation layer, its not a matter of supporting all 47000 different
settings, its dozens."*

Two things are true together. The level is **ours to choose, in the presentation layer, per place
we report** — a bounded set, dozens of decisions, not a universal mechanism over every setting a
device holds. And the rule we choose by is **the override boundary**, which the device defines.

Those agree because they answer the same question. A reported provenance tells an engineer where to
go to change the value. An override boundary is the smallest unit that can be changed locally. Same
question, same answer.

It is also the safe choice, which is what the rule at the top of this entry states. Measured on
pan-fw-111, 2026-10-21:

- A **named entry** overrides **wholesale**. `aegis_ldap_prof_2` sits in `running` with every leaf —
  `server`, `ssl`, `bind-password` — though only `bind-dn` was changed, and under `action=get` the
  entry is mark-free and identical to running. Its template sibling `aegis_ldap_svr_prof` carries
  `@ptpl` on all eight of its nodes, naming one template. So every level inside the entry agrees,
  and `field_name="__entry__"` says all there is to say. Reporting at the container of entries
  would be wrong — that container is marked while holding an unmarked override.
- A **settings container** overrides **per leaf**. `<wildfire ptpl="ptpl-pan-fw-111" src="tpl">`
  holds `report-benign-file` unmarked beside `report-grayware-file` marked. So the leaf is the
  override boundary and the reporting level. Reporting at the container is not merely coarse, it is
  wrong: the container's mark does not describe the leaf overridden out from under it. This is what
  the `FieldProvenance` docstring already says about the `deviceconfig/system` models carrying
  provenance per field.

Jason's own examples land on the same rule: a security rule reports at the whole rule, an antivirus
profile's weak setting reports at the profile, a management setting leaf reports at the leaf. Each
is that object's override boundary.

The store already holds both levels — a row per field, plus `__entry__`. `presentation.py`'s
`entry_provenance_label()` is this choice made in this layer.

**What a session would otherwise do:** propose a universal leaf-level provenance scheme, or a JSON
column keyed by field name, to replace rows it believes are the wrong shape. Both are the shape
already built, and neither is needed. Or pick the reporting level by what reads tidily, rather than
by where an override can occur, and report a container's origin for a leaf that no longer shares it.

## The ten `ProvenanceType` members span two questions and still belong in one column

**Decided by Jason, 2026-10-21**, who drew the distinction: a `@ptpl` mark answers *where does
remediation occur*; `ciphers_default` answers *was this set or defaulted*. Different questions.

They cannot collide in one column. Every absent-type requires the **key absent** — the three
docstrings each say so — and every origin type requires the key or entry **present**, `predefined`
explicitly so. A field is therefore either configured somewhere and has an origin, or is not
configured and has no origin to lose.

Jason's accompanying rule: PAN-OS default and implicit values are **normalized into explicit values
in the database**. A customer told a value is weak is expected to reason from it, and some drift
between finding text and PAN-OS versions is acceptable as long as it is not egregious. So
explicitness is a **discovery** concern — reading a runtime value without knowing it was inferred is
the trap — and not a remediation-text concern.

**What a session would otherwise do:** split the enum across two columns to separate the axes, and
migrate `ABSENT_TYPES`/`DEFAULTED_TYPES` and their four reference sites for no gain.

## Provenance marks never inherit downward

**Measured 2026-10-21**, not decided. PAN-OS marks every node a template contributes, at every
depth — but a marked parent can hold an unmarked child. `<ldap ptpl="temp-stck-jb-rg" src="tpl">`
holds the overridden `aegis_ldap_prof_2` with no marks anywhere inside it.

So reading a container's origin and applying it to a leaf inside it reports the wrong place to
remediate. This is the one remaining way to get the remediation locus wrong, and the XML's shape
invites it: the parent looks authoritative for everything under it.

**What a session would otherwise do:** write exactly that inheritance, because it reads as a
sensible default and is wrong only in the overridden case — which is the case that matters.

**Pass 2 made this worse, and it strengthens the reporting rule rather than weakening it.**
Measured 2026-10-21: a CONTAINER's `@ptpl` names the **lowest-priority layer that contributed
anything to it**, which can be a layer that supplied nothing visible. A losing
`report-grayware-file=no` was added to the `shared-base` template; `<wildfire
ptpl="ptpl-pan-fw-111">` on pan-fw-111 became `<wildfire ptpl="shared-base">` while the winning
leaf kept its value `yes` and its own correct mark `ptpl-pan-fw-111`. Verified independently after
the run:

    pan-fw-111   <wildfire ptpl="shared-base" src="tpl">
                   <report-grayware-file ptpl="ptpl-pan-fw-111" src="tpl">yes

So a container's mark is not a stale ancestor value to be ignored — **it is a live value that moves
when an unrelated template is edited, and it names the loser.** Reporting at the container would
not be coarse, it would be a confident wrong answer that changes under configuration a reader never
looked at.

That is the override boundary rule earning its keep: for a settings container the boundary is the
leaf, the leaf's mark is correct, and the only wrong answer available is the coarser one.
