# Palo Alto Networks

## What is covered

| product | API surface | status |
|---|---|---|
| PAN-OS NGFW (hardware and VM) | XML API | measured — `pan-os/` |
| Panorama | the same XML API | measured — `pan-os/`, differences written inline |

`pan-os/` covers both because they speak one API. Panorama-specific behaviour is stated as
an exception inside whichever guide it belongs to, so a difference reads as a difference
rather than as two documents you have to already know to compare.

Everything there was established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3),
Panorama (11.2.5-h1). Each guide carries its own measurement date. Re-verify after a PAN-OS
upgrade; the guides say what each claim rests on.

## Guides

`pan-os/` is organised by **plane** — `policy/`, `network/`, `management/` — with the
transport and cross-cutting guides at its top level. `pan-os/README.md` lists them and
carries the filing test for adding one.

## Other Palo Alto platforms exist, and are not reached

Palo Alto is not one API. At least two more product families are known to exist and have
never been looked at:

- **Prisma SD-WAN**, which includes an NGFW similar in capability to the appliances above
  but managed differently, through Strata Cloud Manager.
- **Strata Cloud Manager (SCM/CSM) itself**, which also offers a Panorama-like management
  capability that is reportedly quite different from the Panorama modelled here.

**Nothing here has been measured, including whether those two are one API or two.** SCM
managing Prisma SD-WAN and SCM-as-Panorama-replacement may be one surface wearing two hats
or two surfaces sharing a brand — that is a guess either way today.

Which is fine, because the shape follows the answer and the answer is cheap to get:

- **one API** → one directory beside `pan-os/`, product differences inline, exactly as
  Panorama sits inside `pan-os/` now
- **two APIs** → two directories, named for whatever the products turn out to be

Either way nothing above this level moves, and the fork costs one look at either product.
Note that the decision stays cheap precisely as long as it is unmeasured: a directory name
with nothing under it renames for free, and it only gets expensive once there is content —
which is the same moment the question becomes answerable. Do not pre-create either
directory to hedge.

Expect the concepts to carry and the mechanics not to. A security rule is still a security
rule; nothing about xpaths, `code=17`, `@loc`, pushed-shared-policy or the candidate-versus-
running distinction should be assumed to survive the trip.
