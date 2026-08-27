# Enumerate every definition of a name

> Every definition of a name, in every scope that carries one.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-05. Re-verify after a PAN-OS upgrade.*

Distinct from resolution: this returns **all** definitions, not the winner. A name may
legally have two — one per scope.

## Three reads, minimum

| Read | Yields |
|---|---|
| `merged` | firewall-local **shared** (`/config/shared`) and firewall-local **vsys** |
| `pushed-shared-policy` (no vsys) | Panorama **Shared**, `@loc=shared` |
| `pushed-shared-policy vsys=N` | Panorama **device-group**, `@loc=<dg-name>` |

`merged` covers both local scopes in one call; the two pushed scopes need their own.

## Rules

- **At most two definitions** can exist for one name at one enforcement point — one per
  scope. A third means you are looking at a different vsys.
- `@loc` names the **authoring** device group, which may be an ancestor of the one the
  vsys belongs to. It identifies origin, not assignment.
- `running` is interchangeable with `merged` for objects; `merged` is the better default.

## Do not

- **Do not treat a missing `@loc` on a pushed entry as impossible.** Vendor plugins inject
  objects with no provenance marker at all. Their scope is genuinely unknown, so pick a
  conservative default and report it - but do not discard the whole read over one entry.
- **Do not enumerate a device's shared scope from one vsys.** The Shared set is not
  guaranteed identical for every vsys - a deployment where it differed silently dropped
  objects downstream (`per-vsys-shared-set-divergence`). Read every vsys and union the
  result. The lab cannot currently demonstrate this, which is precisely why it is written
  down rather than left to be rediscovered.
- **Do not use `merged` to enumerate.** It contains no Panorama-pushed objects at all —
  178 Shared addresses were invisible to it on the lab PA-5220. The failure is silent and
  produces false negatives only, so nothing trips over it.
