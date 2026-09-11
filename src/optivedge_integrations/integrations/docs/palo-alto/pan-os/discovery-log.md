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




## 2026-09-11 — the SSH default on 11.2, and PAN-MCR-001/003 against the wire

**Did:** Read pan-fw-111's SSH offer at its public address (11.2.3, PA-VM). Built
`ManagementSshSettings` and generated PAN-MCR-001 and 003, printing the model's offer beside a
client's reading of every server. Added `aes128-cbc` to tpa-a's profile so 001 had a subject.

**Found:** pan-fw-111's default is identical to the PA-5220s' on every list — two releases, two
platforms, one offer — and it is the full OpenSSH 8.0 set, not the four KEX values a profile can
choose. Model and wire agreed on all three devices. tpa-a fails both controls on one row, for two
reasons: a CBC cipher from its profile, and weak MACs from the default its unset MAC list falls
back to.

**Landed:** OEI 0055, OEA 0024; payload contract `ssh-service-profile`. No guide yet.

**Open:** PAN-MCR-002/004/005 — preferred-state only at the corpus minimum; Jason's ruling pending.

---
## 2026-09-11 — what does a firewall's SSH server offer, and when does a profile change it?

**Did:** Completed the SSH service-profile schema on 11.1 and 11.2. Read each PA-5220's KEXINIT
proposal with an SSH client that never authenticates. Bound a strict profile on tpa-b and a
ciphers-only one on tpa-a, committed, read the offer, ran `set ssh service-restart mgmt` over the
API, read it again. Then changed one cipher on tpa-b and repeated.

**Found:** No device had a profile, so all of them offer the built-in default — which includes
`diffie-hellman-group14-sha1`, `hmac-sha1`, `umac-64` and `ssh-rsa`, and several algorithms a
profile cannot even select (chacha20, curve25519, every `-etm` MAC). A commit changes NOTHING
until the SSH service restarts; the restart works over the API. A profile that sets only ciphers
leaves KEX and MACs at the default offer, so an unset list is the default, not empty.

**Landed:** payload contract, new `ssh-service-profile` node. No guide yet.

**Open:** The 11.2 / PA-VM default offer — pan-fw-111 is not reachable over SSH from the probe
host. Whether any operational command reports the ACTIVE profile, which is the only way an
assessment could tell configured from in force.

---
## 2026-09-11 — authentication sequences, and what they broke in controls already built

**Did:** Three sequences committed on fw-core-tpa-b — RADIUS then local-database bound to an
administrator, RADIUS then TACACS+ bound to another, and the first one's members again behind an
authentication object. Jason read the flags off the form. Built `AuthenticationSequence`, then ran
the flow's normalizers and generated PAN-AAA-012, 019, 021 and 022.

**Found:** The device stores none of the three flags unless the form sets them: exit-on-failure
renders NO, use-domain YES, User-ID-domain NO. Before the model, the administrator bound to
RADIUS-then-TACACS+ read as "profile not found" and fired PAN-AUTH-019, and every profile used
through a sequence was missing that reference — `authentication-profiles/member` is a member list
under a key the walk did not visit, the second such key after `multi-factor-auth/factors`.

**Landed:** OEI 0054, OEA 0023. PAN-AAA-012 fires on the administrator's local fallback only;
019 is clear on the all-external sequence; `oep-auth-radius-lab` counts 5 referrers, 3 of them
sequences. `management/read-an-administrator-account.md` gained the sequence-binding paragraphs.

---
## 2026-09-11 — deleting the aggregate

**Did:** Deleted `DeviceConfigurationProfile` and `DeviceConfigurationFinding` (integrations 0053;
assessments 0022 runs first, since the finding held a key to the profile). On the probe DB, pressed
the configuration button and rendered every page the explorer and device tabs serve.

**Found:** The button's generator list had never held the administrator or AAA-server generators,
nor any of the seven split models, and no test noticed. Now all sixteen write: 49 controls, 161
findings. 104 pages render; the two report downloads need an ApplicationEnvironment the probe DB
has never had.

**Landed:** the two docs that called the aggregate "being retired" are staged. Closes the Open
above.

**Open:** HA, NTP, hostname and time zone are stored nowhere now. No completed control reads them.

---

## 2026-09-11 — what does a stored RADIUS secret give away, and can an administrator bind a sequence?

**Did:** Wrote RADIUS secrets of 1 to 64 characters into fw-core-tpa-b's candidate, read them back
and deleted them; read every committed RADIUS/TACACS+ secret on all three devices. Wrote one
authentication sequence into the candidate and asked each administrator binding's completion
whether it was offered.

**Found:** A stored secret is `-AQ==`, an unsalted SHA-1 of the plaintext, then the ciphertext.
The stored length steps every 16 characters, so "shorter than 16" reads as length 57; identical
secrets store identically, and the hash matches across devices. A sequence is offered at every
administrative binding, including both device-wide ones — which refuse a local-database profile
but accept a sequence containing one. Found on the way: fw-core-tpa-a still carried the
device-wide RADIUS test from 2026-09-10; a push made while the template was live had reached it,
and the revert had been scoped to tpa-b. Pushed the reverted stack to tpa-a and re-read it.

**Landed:** payload contract (`aaa-server-profile`, `admin-user`). No guide yet — both feed
PAN-AAA-005 and 012, which are not built.

**Open:** Whether other `-AQ==` fields — the LDAP bind password, the MFA vendor secrets — use the
same form. Not read.

---

## 2026-09-11 — the device-configuration aggregate, split, and the copies that had drifted

**Did:** Split `DeviceConfigurationProfile` into seven models along the CONTROL line - password
complexity, authentication settings, login banner, master key, update server, logging, management
TLS - after reading screenshots of all four Setup sub-tabs: Device > Setup is ten tabs and
Management alone has thirteen sections, so a model per screen would have been nearly as coarse.
Re-collected all three appliances and compared every moved field against the aggregate.

**Found:** Six clusters moved with no disagreement, because each new model calls the SAME parser
the aggregate calls - three readers were extracted to make that true. The seventh had already
drifted: on 2026-09-10 the aggregate said the bound management profile's certificate was
`oep-tls-test` while the SslTlsServiceProfile row for the same profile said `oep-mgmt-server`.
Both normalizers were right at the moment they ran. The copies were the defect.

**Landed:** `ManagementTlsBinding` keeps only what the device owns - the bound name and the
scope it resolved to - and a foreign key to the profile row; the floor and certificate name are
read through it. Resolution (predefined beats shared, never a vsys) now runs over rows, so it
must follow the certificate-objects normalizer. Predefined certificates are not rows, so the
certificate is a stored trust verdict rather than a key. Guides not yet updated - staged.

**Open:** Deleting the aggregate itself. It still carries HA, NTP, the mgt-plane permitted-IP
count and the general settings, none read by a completed control, and its finding model is one
of the two the client report enumerates.

## 2026-09-10 — RADIUS for administrators, against a live server

**Did:** FreeRADIUS 3.2.5 on 192.168.250.5 (built in a separate session: `fwadmin`, `fwmfa` with an
Access-Challenge OTP, `fwreader` returning `superreader`, `fwnorole` returning no role). On
fw-core-tpa-b: `fwadmin` and `fwmfa` created locally, both bound per-account to one RADIUS profile.
Then both device-wide leaves pushed from template `ptpl_fw-core-tpa` at the same server, for
`fwreader` and `fwnorole`, which do not exist on the device. Web logins by Jason; `type=keygen` by
instrument; system log read direct to the device.

**Found:** Identically configured `fwadmin` and `fwmfa` — only `fwmfa` got the OTP prompt. `fwmfa`
cannot mint an API key (refused in 0.3s). With the device-wide binding live, `fwreader` got in as
`superreader`, a role set nowhere on the firewall; before the push it was refused with
*"Authentication profile not found for the user"*. `fwnorole` was refused after an `auth-success` —
the matching *"Authorization failed ... Invalid user"* is in the `general` subtype. Every PAP login
also logs the device's own advice to migrate to PEAP or EAP-TTLS. `test authentication` is not an
API command.

**Landed:** `management/read-an-administrator-account.md` — the absent-account row measured, the
RADIUS-MFA and authorization-failure sections, a Limits line on `test authentication`.

---

## 2026-09-10 — what does overriding one field do to a template-pushed administrator?

**Did:** Jason added `authentication-profile aegis_auth_prof` to `jb` on pan-fw-111 — pushed by
`creds_tpl` with a role and a phash — through the web interface, and committed. Read jb from
merged config, running config and the pushed-template layer; re-normalized.

**Found:** Entry granularity, like an interface management profile. No `@ptpl` survives anywhere
on jb in merged config, and running config holds the whole entry. The pushed-template layer still
carries jb with `@ptpl` and a phash; the merged entry has no phash — an untouched child is
dropped, not inherited. The normalizer records jb as device-authoritative, `has_password` false.

**Landed:** `read-template-provenance.md` — a third row in the override-granularity table, and the
Limits entry now counts three objects. Handling unchanged.

---

## 2026-09-10 — is an administrator actually challenged by an MFA server profile factor?

**Did:** Jason logged in to fw-core-tpa-b's web interface as `oep-mfa-admin`, bound to
`oep-auth-hardened` (local-database, one factor `oep-mfa-duo`, whose Duo host does not resolve).
Then read the system log and `show admins`.

**Found:** Instant success, no second prompt — the factor was never invoked, as Guide p.221,
Help p.941 and Help p.839 (*"Although you can configure additional factors, they will not be
enforced for these use cases"*) all say. The device log has `auth-success` through
`oep-auth-hardened` and the Web login in the same second, nothing between; `show admins` held the
session. A first log read found nothing — it went through Panorama with `target=`, which the
precedence section of the same guide already says Panorama ignores. Read direct, it was all there.

**Landed:** `management/read-an-administrator-account.md` — the MFA section's Unmeasured marker
became a measurement.

---

## 2026-09-09 — does an MFA server profile challenge an administrator, and who references one?

**Did:** Read Help p.941 and Guide p.221/230 for the MFA server profile. Enumerated
`mfa-server-profile/entry[@name='x']` on all three devices. Wrote an MFA profile with no
`mfa-cert-profile`, and an authentication profile with `factors` and no `mfa-enable`; committed
both. Then searched every device's merged payload for the 22 known server-profile NAMES and
listed every path whose value was one.

**Found:** Three children — `mfa-cert-profile`, `mfa-config`, `mfa-vendor-type` — on all three
devices. Both writes were refused at commit, one per key: *"Invalid MFA vendor config"* and
*"multi-factor-auth is missing 'mfa-enable'"*. So both keys are REQUIRED, and the second means
`mfa-enable` has no implicit value to measure. The name search found ONE reference shape the
reference walk did not know: `multi-factor-auth/factors/member`, a member list rather than the
scalar `server-profile` leaf every authentication method uses. The walk matched the key and
extracted nothing, silently, so the lab's one in-use MFA profile reported as an orphan.

**Landed:** `management/read-an-administrator-account.md` — the pairing rule in both directions,
and a new section on vendor-API MFA not applying to administrator login. `find_references` reads
member lists; the server-profile walk adds `factors`; two regression tests, both confirmed to
fail when reverted.

**Cost note:** `mfa-cert-profile` being required was already in the payload contract from
2026-09-08. It was re-measured from scratch, for two commits and one failure, because the contract
entry for the object was not read first.

---

## 2026-09-08 — what does an administrator account look like, and how is its role shaped?

**Did:** `action=complete` across `mgt-config/users/entry[@name='zzz']` and every child of
`permissions/role-based` on fw-core-tpa-a, plus a merged-config read of all three devices.
Then created three subjects and committed them: `shared/admin-role/oep-role-readonly` and an
account pointing at it on pan-fw-111, and an account with `vsysadmin` plus
`client-certificate-only` on fw-core-tpa-a.

**Found:** Eight children. The ROLE has three wire shapes, not one — `superuser`/`superreader`
are yes/no leaves, `deviceadmin`/`devicereader` are member lists of device names, and
`vsysadmin`/`vsysreader` are an entry per device carrying a vsys member list. The member-list
pair returns nothing on the leaf, which had previously been recorded as "takes no text"; it is
`<leaf>/member` that answers. `custom/profile` returned `auditadmin`, `securityadmin`,
`cryptoadmin` on a device where `shared/admin-role` is NULL — those are `predefined/admin-role`
entries, so the field takes a predefined role too. `phash` comes back redacted and `public-key`
does not. `client-certificate-only` is the first leaf seen to answer `code=2 "complete for this
type not implemented yet"`.

**The trap worth the entry:** both PA-5220s report a `@ptpl` on the users CONTAINER over entries
that carry no marker at all. Reading provenance there would have labelled six device-local
accounts as template-managed. The container marker names A template that contributes to the
container - an empty `users` node is enough - and partitions nothing inside it. pan-fw-111 shows
the other shape: container marked `creds_tpl`, and exactly two of nine entries marked. Both
readings fail the same way, so read the ENTRY. This is a template-provenance rule and belongs in
`read-template-provenance.md`, which covers entry-level and leaf-level granularity and not this.

**Landed:** draft `management/read-an-administrator-account.md`. OptivEdgeProbe's payload
contract gained the `admin-user` node. OptivEdgeIntegrations gained `AdminUser` and its
normalizer; OptivEdgeAssessments gained the Administrators tab and PAN-AUTH-019/020/021/022,
which report 52 findings across the lab.

**Also found, unrelated to the question:** `renormalize_in_scope_configuration` called none of
the certificate-object, authentication-profile or password-profile normalizers. All three
shipped with controls, tabs and passing tests; the only thing that ever ran them was a test.
Now wired, with admin users, through one `APPLIANCE_OBJECT_NORMALIZERS` loop.

**Then, on Jason's ruling the same day:** PAN-AUTH-020 moved off AuthenticationProfile onto
AdminUser — "we generate findings per user, not per profile", which he scoped the next day to
that control and 019 only, with everything asserting a property OF a profile staying where it is.
And PAN-AUTH-021's severity was restored to the corpus `critical` after being lowered to `high`:
the assessor downgrades with context we do not have, and an understated finding is the one nobody
re-reads.

Building a PASSING subject for 020 cost three failed commits on fw-core-tpa-b: an `mfa-server-profile` is accepted at write and refused at commit as
"Invalid MFA vendor config" for both okta-adaptive-v1 and duo-security-v2, with every key
`action=complete` offers populated. `mfa-cert-profile` completed to nothing, which was read as
"no eligible certificate profile" and written up as an unclosable gap; that was wrong. The
device had six certificates and ZERO certificate profiles. Creating one made the identical MFA
profile commit first try, and `oep-mfa-admin` is now the estate's only MFA-protected
administrator. An empty completion set meant the object type was absent, not that the reference
was unsatisfiable — which an item three phases up the checklist already said.

**Every support object built for this was INOPERATIVE on purpose** - Jason, 2026-09-08: "We can
build fake server and authentication profiles that are inoperative just for config validation."
The Duo tenant does not exist, the RADIUS and TACACS+ servers are TEST-NET addresses that never
answer. These controls read configuration, so a working back end would have proved nothing extra
and would have put a real credential in the lab. The device-wide binding was pushed from PANORAMA
and reverted from Panorama, because it applies to every account and nobody could have logged in to
remove it.

**Worth keeping from the failure:** `mfa-config` completes DIFFERENTLY depending on the sibling
`mfa-vendor-type`, and setting the vendor makes the device write that vendor's defaults for you.
A `set` on a member list APPENDS rather than replaces, so re-pointing the MFA factor left both
members and the delete of the first was correctly refused. And validation names one invalid
object at a time: with two bad profiles the commit named only the first, which read as the
second having passed.

**Answered, withdrawn, and answered again the same day:** `oep-fallback-test` on fw-core-tpa-b
held a local password AND a profile pointing at RADIUS on 192.0.2.1. Jason's login failed and
the log read "Reason: Authentication request is timed out. auth profile 'oep-auth-deadend' ...",
which was written up as proof the profile takes precedence. Jason then found his console copy
procedure had been appending a trailing period to the password, so what had been sent was
unknown - and that log line does not discriminate anyway, because a wrong password goes to
RADIUS and times out identically.

Retaken over `type=keygen` with the instrument setting the passwords - and that was still not
enough. Its controls were two OTHER accounts, so it rested on an absent second log entry meaning
"no fallback was attempted". Jason again: "If I pasted the correct password, it might have tried
local authentication after radius timed out." Right, and no evidence about other accounts
answers it. Settled by an A/B on the account itself: profile unbound -> authenticated in 0.32s; same
account, same password, profile bound back a minute later -> refused after 6.89s, logging the
profile and its dead server. The CLOCK is what rules out a fallback - a local check answers in
0.2-0.4s, so the device waited out RADIUS and declined rather than trying the password it had
just been shown to hold. Repeated by hand on the web UI, both accounts sharing one password so a
bad paste would fail the control: control in, bound account out after ~8s. Both access paths
agree. Conclusion unchanged across four attempts; the evidence was inadmissible three times, once
because this script's own cleanup retired the credential twenty minutes before the person used
it - the device's "Password changed for user ..." event is what found that.

**The ordering, settled on both paths:** per-account profile > local password > device-wide
profile.

**And the device-wide binding is a different mechanism - though the first attempt at showing
that proved nothing.** It pushed only the UI leaf, tested it over the API, and had no
credential-less account, so its one observation - a web login with a stored password succeeding -
was equally consistent with the binding being INERT. Jason asked whether the difference had been
tested directly. It had not.

Retested with both leaves pushed and an account holding NO credential as the live-binding
control: that account was sent to the profile and timed out, naming it, two seconds before an
account with a stored password authenticated locally with no profile named. The device-wide
binding covers exactly the accounts that have no local credential. `non-ui-authentication-
profile` governs the API path; it is documented nowhere in the Help's 1,230 pages.

**Found by Jason reading the control description, not by a test:** PAN-AUTH-019 asserted
external authentication and only ever checked whether a profile was BOUND. Three of the four
lab accounts passing it authenticate against the firewall's own local user database through a
profile - `local-database` and `none` are methods too. The control now resolves the reference
and reads the method, and also reports a stored credential on an externally-authenticated
account, which was Jason's second half: "mfa/external=yes and local phash=no". Nothing in the
estate passed afterwards, so `oep-external-admin` was built on a TACACS+ profile as the one
passing row.

**Small things worth keeping:** `protocol` on a radius server profile stores `{"PAP": null}` and
`protocol` on the tacplus profile beside it stores the string `"PAP"`. Both complete to the same
value list; the radius form is refused outright in tacplus. And `action=complete` answers for the
schema of whatever `target` names, so a Panorama-side path asked of a FIREWALL returns `code=6
Invalid sequence` - which reads as "this path is not real" and means "not on the device you
asked". That is the fourth way a negative from this oracle has misled.

**Not built, and why:** PAN-AUTH-023 asks for "least-privilege custom admin roles". The roles and
their assignments are readable; the fit between a role and its holder is not, and that is the
assertion. Even the narrow reading fails - a role entry records only the features explicitly set,
so judging breadth needs the implicit value of every webui, restapi and xmlapi feature. Deferred,
with the decidable neighbour named: whether a defined custom role is assigned to nobody.
PAN-AUTH-024 is deferred for the reason under Open below.

**Open:** last login appears in no configuration field and in no operational command on these
devices, so PAN-AUTH-024 still has no oracle. Whether a template push of `mgt-config/users`
overrides an account that already exists locally is untested — the template case was only ever
read, never written from this side.

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
