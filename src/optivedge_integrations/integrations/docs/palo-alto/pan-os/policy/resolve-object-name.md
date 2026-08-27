# Resolve an object name

> The value a firewall actually uses for a name, across competing scopes.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-26. Re-verify after a PAN-OS upgrade.*

## An IP-shaped member is still a name

Resolve **every** rule member as a name first, including ones that look like addresses.
An address object may be named for an IP and hold an unrelated value, and the name wins:
measured, a member `172.200.255.254` compiled to `10.99.99.99` because an object of that
name held it. Only when no object owns the name is the member an inline literal.

Reading an IP-shaped member as an address is silent and total when it is wrong — the rule
is reported as matching traffic the firewall never matches. Never short-circuit the lookup
on the shape of the string.

Given an object name and an enforcement point (device serial + vsys), return the single
value that firewall uses.

## Order

**Step 1 — vsys scope.** First hit wins; stop.

| | Source |
|---|---|
| 1a local | `merged` → `config.devices.entry[0].vsys.entry[@name=VSYS].address.entry[@name=N]` |
| 1b pushed | `pushed-shared-policy vsys=VSYS` → `policy.panorama.address.entry[@name=N]`, **only where `@loc != "shared"`** |

**Step 2 — shared scope.** Only if step 1 found nothing.

| | Source |
|---|---|
| 2a local | `merged` → `config.shared.address.entry[@name=N]` |
| 2b pushed | `pushed-shared-policy` (no vsys) → `shared.address…` or `policy.panorama.address…`, **only where `@loc == "shared"`** |

Within a step the two sources are mutually exclusive — PAN-OS rejects that collision — so
their relative order is immaterial. Only **step 1 before step 2** matters.

## Rules

- Classify pushed objects by **`@loc`**, never by which query returned them. On a
  single-vsys firewall both pushed queries return identical payloads and every object is
  `@loc=shared`; query-position classification misclassifies all of them.
- Local objects carry no `@loc`. Use read position to separate local-vsys from
  local-shared. Neither signal works alone.
- Do not branch on `multi-vsys: yes/no`. The `@loc` guard makes one path correct for both.
- Address **groups recurse** — members are names needing this same resolution, from the
  same enforcement point. A shared-scope group may contain a vsys-scope member. **Unmeasured:** never tried.

## Which object type the name means

The steps above resolve *within* the address namespace. Deciding which namespace a name
belongs to comes first, and the two possibilities behave differently:

| Name is both … | Possible? | Do |
|---|---|---|
| address object **and** address group | **No** — rejected at the candidate write, every scope | nothing; the state cannot reach you |
| address object/group **and** an EDL | **No** — but only rejected at *commit*, since EDLs are a separate config node | nothing; the state cannot reach you |
| address object/group/EDL **and** a region | **Yes** — legal, committed on a real device | **prefer the region** |

A multi-namespace hit is therefore **not** a fault to raise on. PAN-OS resolves it and
says so at commit (`Warning: <name> is used as a region, not an address object`); code
treating it as ambiguous fails on a configuration the firewall accepted.

Predefined region names are **not reserved**. `US` may simultaneously be an address
object, an address group, a custom region, and the predefined region.

## Regions union, they do not override

A custom region sharing a predefined region's name **extends** it — both sets of
addresses are live under the one name. Computing a region reference's extent means
unioning the custom definition with the predefined ranges; either alone under-reports.

`show running security-policy-addresses` cannot answer region questions — it renders a
region-sourced rule as `source 0.0.0.0` rather than expanding it. Use
`test security-policy-match`.

## Services resolve like addresses; applications do not

A **service** name follows the same `vsys > shared` model as an address object, measured:
with the name defined in both scopes, a vsys rule compiled to the vsys definition's port,
and a name defined only in shared compiled to the shared one. Resolve services with the
address-object procedure above.

A **custom application** name does not. PAN-OS refuses a vsys application whose name is
already used in shared (`'X' is already in use`), so a name has exactly one definition
device-wide and there is no precedence step. Resolve applications from a single global map;
building a per-scope one implies a shadowing that cannot occur.

**Tags and schedules are unresolved.** Their namespaces are known, their precedence is not,
because no compiled view for them exists. Do not assume they follow the service result.

## Namespaces are several, not one

Keying on `(scope, name)` is not enough — the type's namespace is part of the key:

    {service, service-group}                one namespace
    {address, address-group, EDL}           one namespace
    tag                                     its own
    schedule                                its own
    custom application                      its own, and device-wide
    region                                  separate, and unions rather than overriding

A service and an address object may share a name and be entirely unrelated objects.

## Do not

- Do not resolve from `merged` alone. It holds no pushed objects, so a name with a local
  and a pushed definition will appear unambiguous when it is not.
- Do not infer resolution from a source that never held the competing value.
- Do not treat a name matching several object namespaces as an error. Object-vs-group
  cannot occur; object-vs-region can, is legal, and resolves to the region.
