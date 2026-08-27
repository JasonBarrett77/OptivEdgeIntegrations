# Classifying a PAN-OS API failure

> Which layer failed, and whether the operation nevertheless took effect.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3), Panorama (11.2.5-h1) — through 2026-08-26. Re-verify after a PAN-OS upgrade.*

## Check things in this order

There is no single correct parse, and the request type does not tell you how far down this
list you must go.

1. **Content type.** `text/html` with HTTP 200 is the management web UI, not an answer — a
   wrong `Content-Type` header or a base-URL typo both produce 20 KB of it.
2. **Root element.** `<response>` is not guaranteed. `type=export&category=configuration`
   returns a bare `<config>` — 625 KB of real data with no envelope at all.
3. **Envelope** `@status` — and see below, there are three values, not two.
4. **`@code`** — on reads this is the outcome, not `@status`.
5. **The job**, if one was returned. `export&category=tech-support` returns a job; the
   sibling categories do not.
6. **Per-device results**, if it was a push.

## Parse the body. Always.

Not "check HTTP status, then parse if it looks bad" — an auth failure is HTTP 403 **with a
usable body**, and stopping at the status discards `Invalid Credential` versus
`Not Authenticated`, which are different problems with different fixes.

Use the HTTP status to decide **which envelope to expect**, then read the matching path:

| HTTP | Envelope | Message at | Layer |
|---|---|---|---|
| 403 | `status = 'error' code = '403'` | `result/msg` | authentication |
| 400 | `status = 'error' code = '400'` | `result/msg` | caller bug, web layer |
| 200 | `status="error" code="<n>"` | `msg/line` | PAN-OS rejected it |
| 200 | `status="unauth" code="16"` | `msg/line` | request refused — e.g. an xpath not rooted at `/config` |
| 200 | `status="success"` | — | see below, this is not an outcome |

**Match on `status != "success"`, not on `status == "error"`.** `unauth` is a third value,
not a variant of `error`, and a classifier testing for `error` treats it as success.

## `status="success"` is not an outcome

Three separate traps, all measured:

1. **On reads, `code` is the outcome, not `status`.** `19` means data was returned; `7`
   means **nothing matched**. And `7` cannot tell an absent node from a malformed xpath —
   `/config/[[[broken`, an unclosed predicate and an invalid axis all return a bare
   `<result/>` with **no message at all**, identical to a node that simply is not there.

   PAN-OS only emits a message when it refuses the xpath outright (`unauth`/`16`, for a
   path not rooted at `/config`). Anything under `/config` is evaluated as a path
   expression that matched nothing. So validate xpaths before sending, or treat `7` as
   "no answer" rather than "no data" — the distinction the response will not make for you.
2. **A job submission returns `success` because the job was *queued*.** The outcome is not
   in that response.
3. **A finished job's envelope is still `success`.** The outcome is `job/result`, and the
   per-device outcomes are below that again.

So "did it work" is three checks for anything asynchronous: envelope, `job/result`, then
every `devices/entry/result`.

## A device can be PEND when the job is FIN

Measured: job `FIN` with `result=FAIL`, one device `FAIL`, the other still `PEND` at
"config sent to device". **Only `OK` and `FAIL` are terminal.** Anything else at job
completion means that device's outcome is *unknown*, not fine — treat it as unresolved and
say so, rather than counting it as a success because it did not fail.

## Do not classify on `@code` alone

`13` spans a caller bug (schema node not found), device state (not connected), a timing
condition (commit pending) and a template-ownership rule. `12` spans several unrelated
validation failures. The code narrows the search; the message text discriminates. Since
message text is version-specific, anything matching on it needs re-checking when PAN-OS
changes — which is what `about: panos` in a finding is for.

**Palo Alto publishes an error-code table. Do not classify from it.** Five of its meanings
were checked against a live device and four disagreed — an unknown command returned `17`
where the table says `1`, a malformed xpath returned `7` (with `status="success"`) where it
says `6`, a delete of a nonexistent node returned `7` where it says `13`. The table is a
reliable guide to the code *space* and an unreliable one to any device's behaviour.

Use it to know a code exists; use measurement to know what it means. Treat an unseen code
as **unclassified**, not impossible — the default branch is the one that runs on every
failure nobody anticipated, so it should show the human everything rather than guess.

## Do not generalise `target=`

Support is per request type and there is **no error when it is ignored** — the request
succeeds against the wrong appliance:

| Type | `target=` |
|---|---|
| `op`, `config`, `export` | honoured |
| `log` | **ignored** — answers from Panorama's own log database |
| `version` | **ignored** — returns Panorama's version |

`target=""` is treated as absent, and a duplicated `target` is accepted with one winning.
Establish support per type by measurement, and check `device_name`/`serial` in the response
where the payload carries them.

## When you need the valid values, ask for them wrongly

An illegal parameter value is answered with the permitted set — `action`, `log-type`,
`export` and `import` categories all enumerate this way. `type` does not. The `import` list
contains empty entries, so parse it defensively. This is faster and more current than the
documentation, because it comes from the device you are actually talking to.

## Self-limit concurrency; nothing will stop you

Palo Alto recommends five concurrent requests. Fifteen were run against Panorama with no
throttling, no queuing and no rejection. The limit is guidance about management-plane load
that the API does not enforce, so exceeding it degrades the appliance an administrator is
also using rather than producing an error you can react to.

## "not connected" needs a second call

`code=13 "<serial> not connected"` is returned identically for a managed device that is
powered off and for a serial Panorama has never seen. They need opposite handling — retry
versus fix your inventory — and the error cannot tell them apart.

`show devices all` can: a managed device appears with `connected=no`, an unknown serial is
absent entirely. Make that call before deciding, and never default an unknown serial to
"transient", which hides a real inventory error indefinitely.


## Parse the error before you read it

`<msg><line>` is the field every failure path reads, and it is **the** element that changes
type with the data: one line parses as a `str`, several as a `list`. So

    for line in response["msg"]["line"]:

iterates the *characters* of a one-line error and the *lines* of a six-line one. It fails
only on the failure path, which is the worst place for it.

**Do not fix this by naming `line` in `force_list`.** It is overloaded - PAN-OS also emits
`<line>1</line>` as a source line number in IPS Signature Converter output - so forcing it
globally wraps those legitimate scalars in lists. Normalise defensively at the point of use:

    lines = node.get("line")
    lines = lines if isinstance(lines, list) else ([] if lines is None else [lines])

OptivEdgeProbe's `probe/framework/jobs.py` takes that route and is correct either way. The same applies to
`job`, which is a scalar id on async submission and a collection under `show jobs all`.

The same applies to `completion` from `action=complete` — a node with one valid child returns
a dict, several return a list. `("entry", "member")` is sufficient for configuration payloads
and is **not** sufficient for op and response payloads, where the overloaded keys have to be
surveyed one at a time. Normalise at the use site rather than widening the global force-list.
