# Verify arrival on a device

> Confirming an object or rule actually arrived on a device.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-05. Re-verify after a PAN-OS upgrade.*

## Match the command to the object's scope

    Panorama Shared object   ->  show config pushed-shared-policy          (no vsys)
    device-group object      ->  show config pushed-shared-policy vsys N

Checking a device-group object against the **non-vsys** command returns a convincing
**false negative**: the push succeeded, the object is on the device, and the check says
absent. This was hit in practice while verifying a scoped push and briefly read as a
failed push.

## Rules

- **`vsys=` is mandatory** on the per-vsys query. Without it PAN-OS answers for vsys1
  with no error — measured 107 rules versus 195 for vsys3 on the same device.
- **A job reporting success is not arrival.** Read the config back. A `CommitAll` can
  report `OK` while a device push fails.
- **A successful config write is not a legal configuration.** Same-scope collisions are
  rejected at *candidate write* in one case and only at *commit validation* in another.
  Only a successful commit confirms legality.

## Rules will be missing if disabled

A **disabled** device-group rule is not pushed at all — not present-and-disabled, simply
absent. Its referenced objects still arrive. Any rule enumeration from pushed policy
silently omits every disabled Panorama rule, with no placeholder or count discrepancy.
