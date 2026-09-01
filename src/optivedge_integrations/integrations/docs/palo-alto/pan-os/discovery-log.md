# Discovery log — PAN-OS

How the claims in these guides were arrived at. Newest first.

**This is a log, not a document.** The distinction is what keeps it cheap, and the rules are
short enough to follow without thinking about them:

- **Append. Never re-file.** Entries go on top, in date order. There are no ids, no
  categories and no index, so there is never a decision about where something goes.
- **Never edit an old entry.** If it later proves wrong, write a *new* entry saying so and
  naming the date it corrects. A log that gets rewritten cannot settle "did the device change,
  or was the original reading wrong?", which is the only argument this file exists to win.
- **The log records the activity; the guide records the conclusion.** A fact that appears here
  and in no guide has not landed. Do not read this file to learn how PAN-OS behaves — read the
  guides, and come here when you want to know how much to trust one.
- **Short.** Four lines is a normal entry. It is a lab notebook, not a report.
- **Worth an entry:** anything ambiguous, anything that took more than one attempt, anything
  that contradicted an expectation, and any `**Unmeasured:**` / `**Inferred:**` /
  `**Working decision:**` marker added to a guide — those especially, since a reader who hits
  one will want to know what was tried.

Entry shape:

```
## YYYY-MM-DD — what was asked

**Did:**    what was actually run, clicked or configured
**Found:**  what came back
**Landed:** which guide changed, or "nothing yet"
**Open:**   what is still unsettled  (omit when nothing is)
```

---

## 2026-09-01 — what an override does to provenance

**Did:** Pushed an interface management profile from a template stack to an HA pair, had one
peer overridden through the web interface and left the other alone, then compared both
against `deviceconfig/system/aux-2` where one service leaf had been overridden and its
siblings had not. Attempted the same override through the XML API on the untouched peer.

**Found:** Override granularity differs by object. A profile loses `@ptpl` from the entire
entry — every attribute and every leaf — while a management plane loses it from only the
overridden leaf, its siblings keeping theirs. So a profile has one provenance and a
management plane has one per field. `@ptpl` names whichever container defined the value,
which was the template for `network/profiles` and the STACK for `deviceconfig/system` on the
same push; both push configuration and the distinction does not matter to a consumer.

**Landed:** `read-template-provenance.md`, at the top level rather than under a plane, since
template values reach `deviceconfig`, `network` and the policy subtrees alike. README gains
a row. OptivEdgeAssessments shows the source name alone on the profiles tab.

**Corrected mid-flight:** the first reading of this generalised from a single override to
"an override always strips the whole entry", which the management plane immediately
contradicted. The write-up now marks entry-level-for-named-entries as an assumption drawn
from two objects rather than a rule, because that is what it is.

**Open:** an unmarked value is either locally defined or pushed-then-overridden-locally, and
merged config cannot separate them — resolving it means comparing against the pushed
template, the way `show config pushed-shared-policy` is already used for policy scope. The
working decision is to report unmarked as local, which is what normalization already
produces; deciding provenance at normalization time and storing it is the fix, deferred. The
XML API path the web interface uses for an override is unmeasured: a plain `set` is refused
("may need to override template object ... first") and `action=override` on a profile entry
is refused ("Object cannot be overridden").

## 2026-08-27/28 — interface management profiles, from schema to connection

**Did:** Enumerated interface-management-profile attachment in the CLI corpus, then probed
every candidate node with action=complete on a PA-5220 and an Azure PA-VM. Drove every
permitted-ip form against both management planes on the candidate config and reverted.
Enumerated the field sets of all ten layer-3 attachment points. Then committed for real:
bound a profile to ethernet1/1 and attempted IPv4 connections across five permitted-ip
states. Cross-checked against Palo Alto's Interface Mgmt web-interface help.

**Found:** Nine attachment points, layer 3 only; vlan, loopback and tunnel carry the profile
with no layer3 node in the path. IPv6 accepted on both planes, ranges and object names
rejected on both, `description` accepted only under deviceconfig/system. An empty profile
stores as a bare entry, so all eleven services default absent — the opposite polarity to
deviceconfig's `disable-*` keys. By connection: no list means any routable source; a
non-empty list restricts whatever family its entries are; an IPv6-only list denies IPv4
outright, and adding a matching v4 range reopens it. There is no runtime witness for a
data-plane surface — `cfg.net` holds management-plane ports only.

**Landed:** `network/read-an-interface-management-profile.md` and
`network/read-a-layer3-interface-field-map.md`; edits to
`management/read-device-configuration.md`, `policy/read-a-security-rule.md` and the
repository `CLAUDE.md`. OptivEdgeProbe gained `reference/panos-payload-contract.json`, and
per-command payload facts went onto the commands' own records in `cli-commands.jsonl`.
OptivEdgeIntegrations gained ManagementInterface, PermittedSource and their normalizer;
OptivEdgeAssessments gained the management-surface control target and its `exposure` field.
MGMT-002 runs end to end.

**Corrected mid-flight:** three claims that did not survive re-checking — `cellular` marked
unmeasured without being probed, `ha` reported as absent when it is present but childless,
and an IPv6-only list predicted to leave IPv4 open when it denies it. All three were
negatives taken from an instrument nobody had characterised, which is now a technique note
rather than three separate accidents.

**Open:** whether `0.0.0.0/0` alongside populated entries is ignored here as it is on MGT.
No connection was ever attempted over IPv6 — the v6 rows establish what a v6 entry does to
IPv4 reachability and nothing about v6 reachability itself. The v6 mechanism is inferred:
the compiled ACL is legible only on the management plane, and reading it there would have
meant setting MGT to IPv6-only.

## 2026-08-27 — provenance of everything above this line

**Did:** Migrated eleven vendor reading guides into this directory from OptivEdgeProbe's
retired findings catalog, dropping their `derives_from` links to archived findings.

**Found:** The guides are conclusions drawn from 31 measured findings established against the
lab between 2026-07-30 and 2026-08-26. Each guide's header carries its own measurement date.
The underlying findings, their method sections, and the raw captures cited as evidence remain
in OptivEdgeProbe under `archive/catalog/findings/` and `captures/` — frozen, and the record
of record for anything predating this entry. Git history in both repositories has the rest.

**Landed:** All eleven guides, plus `../README.md`'s account of the lab hardware.

**Open:** No guide yet carries a `## Limits` section; they expressed limits inline, in six
inconsistent phrasings that the marker vocabulary now replaces. Both get fixed per guide as
each is next touched, not in a backfill pass — writing limits for a measurement you did not
take is how a corpus acquires confident-sounding fiction.
