# Vendor reading guides

How to read a vendor's configuration without getting a **plausible wrong answer** — which
is the failure mode almost everything here guards against. Not architecture (that is
`CLAUDE.md`) and not how one module works (that is its docstring).

These exist because the knowledge cuts across modules. `read-config-sources` bears on
`addresses.py`, `security_rules.py`, `zones.py`, `device_configuration.py` and
`snapshots.py` at once, so no docstring can own it, and it is too long and too specific for
`CLAUDE.md`.

    docs/<vendor>/<api-surface>/<guide>.md

## Partition by API surface, not by product role

A directory exists per **API**, not per product and not per management role. That is the
line that decides whether knowledge transfers: two products speaking one API share nearly
every reading trap, two on different APIs share none but concepts.

So Panorama is **not** a separate partition from the firewalls it manages — same XML API,
same session handling, same `code=17` — and its differences are written inline in the guide
they belong to. `show system services` not existing on Panorama is only legible next to
what it does on a firewall.

Two consequences worth keeping:

- **The manages-relationship is not in the tree.** Which manager drives which platform is
  many-to-many, it changes with vendor releases, and the code already models it
  (`ManagementStation.station_type` — see the topology section in `CLAUDE.md`, which is
  explicit that inferring it structurally was a latent bug). A directory hierarchy encoding
  the same relationship would be that bug in filesystem form. It lives in each vendor's
  `README.md` as a table.
- **Hoist shared material on the second occurrence, never the first.** When a second
  platform under one vendor makes you write the same paragraph twice, that is the moment to
  move it up to the vendor directory — you then know exactly what is shared and at what
  altitude. Guessing beforehand produces a shared layer subtly wrong for both occupants.

## Keeping it honest

Everything here is consumed by people who did not measure it, so a claim stated more broadly
than its evidence is the failure mode that matters. The retired corpus this content came from
recorded that **every mistake it ever made was an omission** — a limit that went unwritten,
never an outright false statement. Two mechanisms, both deliberately cheap, because the
elaborate version of this was tried and abandoned.

### Mark anything that is not measured

The default is **measured**: unmarked prose means observed on real hardware, and each guide's
header names the devices and versions it was established against. Anything short of that says
so, inline, at the claim — using one of three markers and no others:

| marker | means |
|---|---|
| `**Unmeasured:**` | nobody has looked. Not a defect — an unrecorded gap is the defect |
| `**Inferred:**` | reasoned from something measured, not observed directly. Say what it rests on |
| `**Working decision:**` | a choice made *because* the fact is unavailable. Name who decided and when |

A fixed vocabulary rather than free-form hedging, so a reader can find every soft claim in a
guide with one grep. It replaces six different phrasings that had grown up organically
("Untested.", "is unmeasured", "not established", "Do not assume") and meant slightly
different things or nothing at all.

### End each guide with what it does not establish

A `## Limits` section, last. This is the one rule worth carrying over from the retired
standard, which enforced it per finding with a word floor because it was the only check that
ever caught anything. Per guide is far cheaper and catches the same class.

Not every guide has one yet — they were migrated from a corpus that expressed limits inline.
Add one when you next touch a guide; do not backfill by guessing what a measurement you did
not take failed to cover.

### Every guide states what it is for, in its own file

Two lines, immediately after the `# ` title and before the provenance line:

```markdown
# Reading a zone

> Zone data, without inverting a default or mistaking a group for an address.
```

One sentence, blockquoted, roughly a dozen words, saying **when to reach for this** rather
than restating the title. A guide is usually opened directly — from a grep hit, from a
pointer in a docstring, from a link in another guide — and without it the reader goes from a
title straight into a section heading, learning what the guide is for only by reading it.

Parent `README.md` tables quote that sentence **verbatim**, so the description has one
source and a mismatch is greppable. Adding a guide means writing the sentence once and
copying it up.

Deliberately not frontmatter. Frontmatter is invisible to the reader, needs a parser, and is
the shape the retired corpus took — its schema started at two fields and reached eleven. A
lead sentence is visible where it is useful and costs nothing to maintain. If the guide count
ever makes copying up genuinely tedious — well past thirty, not eleven — generate the tables
from the files rather than adding metadata to them.

### Log the discovery, not just the conclusion

`<vendor>/<api-surface>/discovery-log.md` records how facts were arrived at, especially the
ambiguous ones. Its own rules are in its header. The division that keeps the two from
competing:

> **The log records the activity. The guide records the conclusion.**

A fact living only in the log has not landed. That is the inverse of the arrangement that
failed before, where the finding was the artifact and the consumer merely cited it.

## Vendors

| vendor | directory |
|---|---|
| Palo Alto Networks | `palo-alto/` |

There is deliberately no empty scaffolding for vendors or platforms not yet reached. An
empty directory asserts that someone looked and found nothing, which is a different claim
from "not reached yet" — that distinction belongs in a vendor `README.md`, where it can be
stated in words.

## A note on the code layout

`platforms/pan_os/` has no vendor level, because `pan_os` is already vendor-identifying.
These docs have one. The mismatch is intentional, not an oversight to tidy: a second vendor
is the moment to revisit it, and `platforms/` is already the right seam. Docs use hyphens
(`pan-os`), code uses an importable identifier (`pan_os`) — different constraints.
