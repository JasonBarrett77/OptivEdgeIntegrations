# Reading config sources safely

> Which source answers which question, and what each one silently omits.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-25. Re-verify after a PAN-OS upgrade.*

The failure mode of every item here is a **plausible wrong answer**, not an error.

## What each source contains

| Source | Contains | Does **not** contain |
|---|---|---|
| `show config running` | firewall-local **committed** config | **template config**, any pushed policy object |
| `show config candidate` | firewall-local **uncommitted** config | **template config**, any pushed policy object |
| `show config pushed-template` | the **template contribution alone**, carrying every `@ptpl` | local config, policy objects |
| `show config merged` | **candidate** + `pushed-template` | **any pushed policy object** |
| `show config pushed-shared-policy` | Panorama **Shared** policy/objects | local config |
| `show config pushed-shared-policy vsys N` | Panorama **device-group** policy/objects for that vsys | local config |

`merged` is a *template* merge view, not an effective-policy view. Documented by Palo Alto
and confirmed by measurement; no command variant makes it inclusive.

**`merged` follows the CANDIDATE, not the running config** — measured. It reports what an
administrator has typed, not what the firewall enforces. A staged-but-uncommitted deletion
makes an actively enforcing object vanish from it; a staged modification reports the new
value while the old one is in force, with nothing anywhere looking wrong. If the question
is "what does this firewall do", `merged` is the wrong source unless the candidate is known
clean.

**`running` is not a substitute.** Template configuration is *not* committed into the
running config — it is an overlay applied at read time, and `running` carries none of it
and no `@ptpl` markers. So **no single command returns committed-local + template**: the
two properties a collector wants are split across sources that do not overlap.

What works instead is detection. `running` and `candidate` are the same shape and are
byte-identical when nothing is staged, so hashing both answers "is `merged` trustworthy
right now" with an equality test and no diffing. Expect a clean candidate, check it, and
report a dirty one rather than silently normalizing someone's unsaved work.

## A successful read is not necessarily a read

`status="success"` with `code="7"` and an empty result means *no matches* — and a malformed
xpath returns exactly the same thing. So does a `config get` with no xpath at all. Before
concluding a node is empty, be sure the request was well-formed; see
`classify-an-api-failure`.

## Required parameters

- **`vsys=`** on the per-vsys pushed query, or you get vsys1 silently.
- **`target=<serial>`** to proxy through Panorama to a managed device — for `type=config`
  and `type=op` **only**. `type=log` accepts the parameter and **silently ignores it**,
  answering from Panorama's own log database with plausible, well-formed, wrong records.
  Check `device_name` / `serial` on any log record before believing it came from the device
  you asked about.

## Accept two payload shapes

The non-vsys pushed response roots differently by device:

    result.shared             multi-vsys PA-5220
    result.policy.panorama    single-vsys PA-VM

Try one root, fall back to the other. Never branch on device type — the shape follows
vsys mode, and the `@loc` guard makes the distinction unnecessary anyway.

## The bare string is expected on one form and not the other

The **per-vsys** read returns a plain string when the vsys has no device-group assignment:

    'No shared policy pushed to device'

That is an ordinary state with a clear meaning, measured directly — tolerate it and treat
it as an empty pushed-vsys scope.

The **non-vsys** read is different, and the two must not be made symmetric. Asking a
Panorama-managed device for its shared policy and getting back something that is not XML
config data has never been observed. Treat it as a fault and **raise**: returning `{}`
would convert an unexplained response into a confident "no shared objects", which is the
precise failure this catalog exists to document — see `merged-excludes-pushed-objects` for
the same shape.

If it ever does fire, the exception is the observation. Include the payload value in the
message, not just its type, so the next person has something to design against.

An invalid vsys name is a third outcome, and must not be swallowed either:

    vsys99  ->  status=error code=17  'vsys99 is invalid vsys...'

So on the per-vsys form the string means *this vsys exists and has nothing pushed*, while
a typo raises. Both behaviours are correct as they stand.

## An empty pushed read does not mean an empty object set

A device-group-less vsys still resolves **Panorama-Shared** objects — they arrive in the
device's shared scope, which device-group membership does not govern. Never skip
shared-scope collection because the per-vsys pushed read came back empty; on the lab
PA-5220 that would drop 182 address objects the vsys genuinely resolves.

## Runtime instruments

`show running security-policy-addresses` reports compiled addresses per rule index — the
only way to see which definition *won*, since configuration reads never name a winner.
Requires `vsys=`.

`test <security-policy-match>` works over the XML API with `target=`/`vsys=` and numeric
protocol, but is the weaker instrument: `any` is **not** a valid zone, and an earlier
terminal `allow` ends evaluation, so it cannot reach rules low in the order.
