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

## 2026-09-02 — does a profile drop 0.0.0.0/0 too?

**Did:** Four permitted-ip states on a scratch profile bound to ethernet1/1 on fw-core-tpa-a,
each committed and then probed by TCP: one non-matching entry, the wildcard alone, the
wildcard beside a non-matching entry, the wildcard beside a matching one. Re-ran the third
from a re-closed baseline. Restored oep-lab-mgmt and deleted the scratch profile afterwards.

**Found:** The profile KEEPS the wildcard — closed with `[10.99.99.99]`, OPEN the moment
`0.0.0.0/0` joined it. The opposite of the deviceconfig planes, which drop it. Port 22 stayed
closed throughout, the profile carrying https and ping only.

**Landed:** `network/read-an-interface-management-profile.md`; `exposure.classify()` in
OptivEdgeAssessments now returns `unrestricted` rather than `undetermined` for that
combination, with the two tests that encoded the hedge rewritten to assert the two planes
disagree. The open question is out of `in-flight.json`. Also OptivEdgeProbe's
`reference/panos-payload-contract.json`, whose `mgt-permitted-ip` node claimed the
deviceconfig list has "same semantics as the interface-profile list" - false as of today in
exactly the field that matters, and now stated in both directions.

**Where to look for it:** that payload-contract edit is in OptivEdgeProbe commit `7faf84f`,
whose message is about SSL/TLS profile name shadowing and does not mention the wildcard at
all. Two sessions were working the same tree and a broad `git add` swept it into an
unrelated commit. Nothing was lost or altered, but `git log` on that node points at the
wrong investigation, so this entry is the archaeology instead.

**Worth keeping:** the first pass ran the decisive state straight after the wildcard-alone
state, so OPEN followed OPEN and the surface was never seen to change into it. That is not
the same evidence as a surface that opened, and it was only visible because the sequence was
written down. A state that must come back different is what makes the others readable — the
same instrument problem as the negatives taken from action=complete on 2026-08-27.

**Also:** loopback.20, the lab's other profile-bound interface and the obvious subject, is
10.253.20.1/32 and is not routable from the probe host. Every state on it would have read
closed. On a plane whose only oracle is a connection, "can this host reach the interface at
all" is the first thing to measure, not an assumption.

---

## 2026-09-02 — a refused DELETE, and whether walking up the tree helps

**Did:** Tried to delete a shared `ssl-tls-service-profile` while `deviceconfig/system` still
referenced it, during ordinary scaffolding cleanup rather than as an experiment.

**Found:** It errors, loudly and usefully: `status=error code=10`, "oep-tls-control cannot be
deleted because of references from: deviceconfig -> system -> ssl-tls-service-profile". It
names the referring path. Walking UP the tree does **not** help — the refusal is *referential*,
not structural, so the parent container is held by the same reference and every level refuses
identically. Clearing the REFERENCE is what works, and integrity is evaluated against the
CANDIDATE, so re-pointing the referrer earlier in the same commit is enough.

**Landed:** the DELETE item in OptivEdgeAssessments' `building-a-control.md`, which until now
told the reader to walk up.

**Open:** whether a *structurally* undeletable leaf exists at all, and whether walking up
helps for that case. Nothing here covers it.

## 2026-09-02 — `show config merged` does not carry `/config/predefined`

**Did:** Looked for the predefined `ssl-tls-service-profile` in the payload everything else
normalizes from, then tried `show predefined` as the alternative.

**Found:** The merged config's top level is `devices`, `mgt-config`, `shared` — no
`predefined` node, though a commit's own summary describes the merged size as "(local,
panorama pushed, predefined)". That describes what PAN-OS merges internally, not what the
command returns. `show predefined` does not fill the gap: it addresses a different namespace
with a similar name — the content/App-ID catalog — and returns "No data found. Verify xpath
and retry". Only a direct `type=config&action=get` on `/config/predefined/...` reaches it.
Two adjacent facts: an xpath matching nothing returns `<result/>`, which parses to `None` and
hits persistence as a null payload (the PA-VM genuinely has no predefined SSL/TLS profile);
and `show predefined ip-block-list-v2` raises on both PA-5220s while succeeding on the PA-VM,
which had been discarding every predefined catalog for those two appliances on the strength of
one unrelated failure.

**Landed:** OptivEdgeIntegrations gains its first `type=config` collector; the payload
contract in OptivEdgeProbe.

## 2026-09-02 — can a custom object shadow a predefined one of the same name?

**Did:** Wrote a custom `ssl-tls-service-profile` to `/config/shared` under the shipped name
`TLSv1.3_Default`, deliberately weaker and with its own certificate, bound it, committed, and
read the result off the wire by TLS negotiation. Then bound a second profile with a UNIQUE
name and the same custom certificate, as the state that had to come back different.

**Found:** The predefined definition wins outright. The custom entry was discarded whole —
protocol settings *and* certificate:

    nothing bound                              1.1, 1.2, 1.3 (1.0 refused), factory cert
    shared TLSv1.3_Default, min tls1-0 max 1-2 1.3 ONLY, factory cert
    shared oep-tls-control, unique name        1.2 only, CN=oep-tls-test.lab

The third row is what makes the second admissible: it proves a custom profile IS honoured on
that device, so "nothing changed" is a real null rather than a binding never wired up. The
predefined entry reads `min tls1-3 / max tls1-3`, so config and wire agree independently.

**Landed:** `read-template-provenance.md` is untouched; the resolution rule lives in
OptivEdgeIntegrations' device-configuration normalizer and the payload contract, and
PAN-MGT-010/014 in OptivEdgeAssessments.

**Open:** the policy-object ladder. `models/policy/base.py` encodes `PREDEFINED = 95`, the
weakest rank, and says outright the position was never measured. Two object types are now
measured and **neither** matches it — a custom `region` *extends* its predefined namesake
(`policy/resolve-object-name.md`), and this one is *beaten* by it. So name-collision behaviour
is per object type, and the ladder's value remains an unmeasured guess for policy objects
proper. Deliberately not changed on the strength of a measurement of something else.

---

## 2026-09-01 — defaults behind the management settings controls

**Did:** Enumerated `deviceconfig/system` and `deviceconfig/setting/management` with
`action=complete` on a PA-5220 and a PA-VM. Wrote `yes` then `no` to `server-verification`,
`ack-login-banner` and `enable-log-high-dp-load`, committing and reading back each time, then
deleted all three. Read the corresponding checkboxes in the web interface on a device with all
three absent.

**Found:** These keys persist whatever is written, so the omit-on-default technique that
settled the service defaults does not work here and absence only means "never written". The
interface answered it instead: `server-verification` absent is ENABLED, the other two DISABLED.
Two neighbouring settings with opposite defaults. `deviceconfig/setting/management` is absent
as a whole node on both PA-5220s, and `ack-login-banner` is greyed out until a banner exists.

**Landed:** `read-device-configuration.md`; the payload contract in OptivEdgeProbe;
PAN-MGT-007/008/009/011 in OptivEdgeAssessments.

**Open:** the template-pushed form of all four keys. Every instance observed is locally set,
so nothing is known about how they arrive from a stack or whether an override strips the
marker as it does for profiles and service leaves.

## 2026-09-01 — checking provenance against raw config, and a wildcard regression

**Did:** Verified every provenance value the Management Interfaces tab renders against the
merged config it came from. Then, prompted by one of those rows, looked at how
`0.0.0.0/0` is classified.

**Found:** The provenance values are correct, including the case most likely to be wrong -
both peers of an HA pair report telnet On on aux-2, one from the template stack and one from
a local override, and the two are distinguished. The PAN-MGT-002 finding on the PA-VM is a
Panorama push (`disable-http: no` carries `@ptpl`), so its remediation is in the stack rather
than on the device.

The wildcard was being classified wrongly in both directions within a day. A surface
permitting only `0.0.0.0/0` was reported Restricted - a false clean result. Fixing that by
treating any list containing the wildcard as undetermined then contradicted a measured
finding already in this corpus, and would have flagged a hardened management interface
carrying `[0.0.0.0/0, jump host]` - which `read-device-configuration.md` says in terms is
wrong. The rule is one behaviour, not two: PAN-OS **drops** the entry, and the outcomes
differ only in what is left over.

**Landed:** `read-an-interface-management-profile.md` gains a section scoping the question to
profiles, where it really is open, and its Limits bullet now points there. OptivEdge-
Assessments' exposure classifier takes the plane.

**Open:** whether a profile drops the wildcard the way the management plane does, when other
entries are present. Alone is unrestricted either way and needs no measurement. There is no
compiled-ACL shortcut on this plane, so connection is the only oracle.

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
