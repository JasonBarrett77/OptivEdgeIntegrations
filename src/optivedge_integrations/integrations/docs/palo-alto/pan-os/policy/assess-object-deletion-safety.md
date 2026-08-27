# Is this object safe to delete?

> Whether an object can be removed, when reference counting cannot say.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-05. Re-verify after a PAN-OS upgrade.*

## Reference counting does not answer this

An object present on a firewall with no rule referencing it may be:

- genuinely unused, **or**
- referenced only by a **disabled** Panorama rule, which is never pushed.

**Both look identical from the device.** Deleting on that basis breaks the rule the moment
someone enables it.

Presence also implies nothing about use: unused objects are pushed exactly like used ones,
so `is it on the device?` and `is anything using it?` are unrelated questions.

## Before concluding "unused"

1. Check the Panorama device-group rulebase directly, including **disabled** rules — not
   the pushed policy, which omits them.
2. Check every vsys the object reaches. A container-device-group object is instantiated in
   every descendant vsys.
3. Remember address **groups** reference objects too.

## Deletion order is constrained

PAN-OS enforces referential integrity: an object cannot be deleted while a rule references
it.

    v5-t2 cannot be deleted because of references from:
      vsys -> vsys3 -> rulebase -> security -> rules -> v5-rule-2 -> source

Remove rules before objects. In a lab, a **restore point** avoids the ordering problem
entirely; OptivEdgeProbe's `probe.snapshot` provides them for the lab.
