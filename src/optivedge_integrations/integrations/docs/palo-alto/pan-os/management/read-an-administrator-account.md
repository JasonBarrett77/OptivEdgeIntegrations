# Reading an administrator account

> Who can log in to a device, with what privilege, and against what credential.

*Established against the lab — PA-5220 ×2 (11.1.13-h3), PA-VM (11.2.3, Azure), Panorama (11.2.5-h1) — 2026-09-08 and 2026-09-09. Re-verify after a PAN-OS upgrade.*

Administrator accounts live at:

    /config/mgt-config/users/entry[@name]

`mgt-config` sits at the **top** of the merged config beside `devices` and `shared`. It is not
under a device entry, it has no shared or per-vsys form, and completing it under a vsys is
rejected. So an account is anchored to the **appliance** and carries no scope — the same
placement as `mgt-config/password-complexity` and `mgt-config/password-profile`, and the same
trap: the obvious xpath, under `devices/entry/…`, is wrong.

Inside a Panorama **template**, `mgt-config` is a SIBLING of `devices`:

    /config/devices/entry[@name='localhost.localdomain']/template/entry[@name='<tpl>']/config/mgt-config/users

> **Every negative below is a negative ON A PARTICULAR DEVICE.** `action=complete` returns the
> schema of whatever `target` names, and a wrong one answers `code=6 Invalid sequence` — which
> reads as "this path is not real". A firewall has no `template` or `device-group` node, so every
> Panorama-side path asked of a firewall fails that way. Ask the device you mean.

## The eight children

Measured with `action=complete` on `entry[@name='zzz']` — a name nothing uses, which answers
anyway, because completion reports the schema rather than the configuration:

| key | holds |
|---|---|
| `phash` | the local password hash |
| `public-key` | an SSH public key |
| `authentication-profile` | reference to an authentication profile |
| `client-certificate-only` | `yes`/`no` |
| `password-profile` | reference to a password profile |
| `permissions` | `role-based` only |
| `description` | free text |
| `preferences` | `saved-log-query`, `disable-dns`, `enable-scp-server` |

## `phash` is redacted; `public-key` is not

`show config merged` returns `phash` as `********`. Its **presence** is readable and its value is
not — exactly enough to ask "does this account hold a local password", and not enough to ask
"was the default password changed".

`public-key` comes back in full, base64. It is a **second local credential**: an account with a
key and no `phash` still authenticates against the device and against nothing else. Four lab
accounts hold both, and `azureuser` on pan-fw-111 holds only a key while being a superuser.

## The role is not one shape, it is three

`permissions/role-based` offers seven children. The UI presents one dropdown; the payload does
not. Completing each child separately is the only way to see this, and a parser written for one
shape reports the others as *no role at all* — the safest-looking wrong answer available.

| children | `action=complete` returns | wire shape |
|---|---|---|
| `superuser`, `superreader` | `['yes']` | `"yes"`, or `{"@ptpl": …, "#text": "yes"}` when pushed |
| `deviceadmin`, `devicereader` | *nothing* — but `<leaf>/member` returns `localhost.localdomain` | `{"member": ["localhost.localdomain"]}` **or** `None` |
| `vsysadmin`, `vsysreader` | `['localhost.localdomain']` | `{"entry": [{"@name": "localhost.localdomain", "vsys": {"member": [...]}}]}` |
| `custom` | `['vsys', 'profile']` | `{"vsys": {"member": [...]}, "profile": "<role name>"}` |

The member-list pair is the one that misleads. An empty completion set on a leaf usually means
"takes no text", and `<devicereader/>` is indeed accepted — `oep-authtest` on fw-core-tpa-b
carries exactly that, parsing to `None`. But `__telemetryuser`, on all three devices, carries the
populated form. **Complete `<leaf>/member` before concluding a leaf is bare.**

`custom/profile` is eligibility-filtered like any reference field. On a device where
`shared/admin-role` is NULL it still returned `auditadmin`, `securityadmin`, `cryptoadmin` —
entries of `/config/predefined/admin-role`. So the field accepts a **predefined** role as well as
a shared one, and an empty result would not have meant the field takes no reference.

**What a custom role GRANTS is only partly readable.** A role entry records the features
explicitly set and nothing else — the lab's `oep-role-readonly` stores a CLI level, one dashboard
grant and one log tab. Every unstated feature takes an implicit value, so judging whether a role
is broad needs the implicit value of every webui, restapi and xmlapi feature PAN-OS has. Enumerate
roles and their assignments; do not try to judge their breadth from the entry.

## Provenance is on the ENTRY, not the container

Both PA-5220s report:

    "users": {"@ptpl": "shared-multi-vsys", "entry": [ … ]}

over eight entries, none of which carries a marker. pan-fw-111 reports `{"@ptpl": "creds_tpl"}`
over nine, of which exactly two are marked. The container marker names *a* template that
contributes to the container and partitions nothing inside it — `shared-multi-vsys` holds an
empty `users` node, and that is enough to mark it.

Read entry provenance from the entry. Where an entry *is* pushed the markers repeat down every
level, so a role leaf arrives as `{"@ptpl": "creds_tpl", "#text": "yes"}` where a local one is the
bare string `"yes"`.

This is a general template-provenance rule, not one about administrators — see
`../read-template-provenance.md`.

## Two bindings decide how an administrator authenticates

    mgt-config/users/entry[@name]/authentication-profile   per account
    deviceconfig/system/authentication-profile             device-wide

The device-wide one is NULL on all three lab devices and is read anyway: it covers every account
naming no profile of its own.

**Set the device-wide binding from PANORAMA, and take it off from Panorama.** It applies to every
account on the device, so if it does bite, nobody can log in to remove it. Panorama's push channel
does not use administrator authentication, so a revert works whatever the device is doing to
logins — and a device-LOCAL write would become an override that survives the revert push. Scope
the `commit-all` to the one serial; the template is shared with its HA peer. There is a second device-wide leaf,
`non-ui-authentication-profile`, which governs the API path — a `type=keygen` attempt went through
the profile with both set. Which leaf governs SSH is untested, and neither appears anywhere in the
Help's 1,230 pages.

## A bound profile is not external authentication

`authentication-profile` says a profile is bound. The profile's `method` says what it
authenticates against, and two of the eight values are the firewall itself:

    external   radius, tacplus, ldap, kerberos, saml-idp, cloud
    local      local-database, none

Seven of the eight authentication profiles on the lab are `local-database` or `none`. Anything
asserting *central* or *external* authentication has to resolve the reference and read the method;
the binding alone does not carry it.

## Precedence: a per-account profile wins, a device-wide one does not

> **This is behaviour, and an assessment reads CONFIGURATION.** What a control asks is whether an
> account is *configured* for external authentication and MFA. The precedence below is why a
> stored credential on a profile-bound account is LATENT rather than live — it does not decide
> whether the credential is worth reporting.

    per-account profile  >  local password  >  device-wide profile

|  | web UI | API / non-UI |
|---|---|---|
| **per-account profile** | displaces the password, no fallback (~8s) | displaces the password, no fallback (6.89s) |
| **device-wide profile** | password wins | password wins, profile never consulted |

**Per account**, measured 2026-09-08 as an A/B on ONE account over `type=keygen`, password set by
the instrument, nobody typing anything:

| state | outcome | took | logged |
|---|---|---|---|
| `oep-fallback-test`, profile UNBOUND | authenticated | 0.32s | `auth-success`, no profile named |
| same account, same password, profile BOUND | refused | 6.89s | `Authentication request is timed out. auth profile 'oep-auth-deadend' ... server address '192.0.2.1'` |

A failure with a password the previous step just proved correct is not a wrong password and not a
broken account. **The clock is what rules out a fallback**: a local check answers in 0.2–0.4s, so
the device waited out the RADIUS timeout and declined rather than spending a further fifth of a
second on the password it had just been shown to hold. Repeated by hand on the web UI with both
accounts sharing one password, so a bad paste would fail the control rather than fake a result:
the unbound account logged in, the bound one failed after about 8 seconds with the same entry.

So a `phash` on a profile-bound account is dead weight for authentication — still a secret in the
configuration, but not a way in.

**Device-wide**, measured 2026-09-09 with BOTH leaves pushed at an unreachable RADIUS server, two
attempts two seconds apart:

| account | outcome | logged |
|---|---|---|
| no credential at all | refused | `Authentication request is timed out. auth profile 'oep-auth-devwide' ... server address '192.0.2.2'` |
| stored password | **authenticated** | `auth-success`, no profile named, 2s after the entry above |

The first row is what makes the second mean anything: that account cannot authenticate any other
way, so the binding had to be consulted for it — proving it live rather than inert. The second
bypassed it, and 2s cannot fit a 5–7s RADIUS attempt, so it was not consulted at all rather than
consulted and fallen back from.

The two bindings sit on opposite sides of the stored credential, which is why one replaces it and
the other only fills the gap where there is none.

**Who the device-wide binding covers**, then, is every administrator with no way to authenticate
on the box:

| the account | device-wide profile used? | how we know |
|---|---|---|
| does not exist in `mgt-config/users` at all | yes — it is the only way such an administrator exists | measured 2026-09-10, below |
| exists, no password, no profile of its own | yes | measured above — refused after the RADIUS timeout |
| exists, stored password, no profile of its own | no — the password wins | measured above — 2s, no profile named |
| exists, with its own profile | no — its own profile wins | measured above — no fallback |

"Local" here means `mgt-config/users`, the administrator accounts. It is not
`shared/local-user-database`, which is the store a `local-database` authentication profile checks
passwords against — a different object that happens to share the word.

**The device-wide bindings only accept external methods**, measured by `action=complete`, which
offers only the profiles valid at that field:

| binding | accepts | refuses |
|---|---|---|
| per-account | radius, tacplus, saml-idp, local-database, none | — |
| device-wide `authentication-profile` | radius, tacplus, saml-idp | local-database, none |
| device-wide `non-ui-authentication-profile` | radius, tacplus | saml-idp, local-database, none |

**An account that does not exist is admitted — as whatever role the server returns.** Measured
2026-09-10 on fw-core-tpa-b, both device-wide leaves pushed from a template at a live FreeRADIUS
server, two usernames that appear nowhere in `mgt-config/users`:

| account | RADIUS returns | before the push | after the push, web and API |
|---|---|---|---|
| `fwreader` | Accept + `PaloAlto-Admin-Role = superreader` | refused — *"Authentication profile not found for the user"* | **admitted**, read-only screens; log: `admin role 'superreader'` |
| `fwnorole` | Accept, no role attribute | refused, same reason | **refused** |

The role is configured nowhere on the firewall. It arrives with the RADIUS answer (vendor 25461,
attribute 1), and an assessment reading the configuration cannot see who holds it.

**`auth-success` is not "logged in".** `fwnorole` produced an `auth-success` event on every
attempt, and in the same second a `general` event: *"Authorization failed for user fwnorole via
Web ... : Invalid user"*. Authentication succeeded and authorization had nothing to grant. A reader
filtering the system log on subtype `auth` sees only the success.

So whoever the device-wide binding covers is authenticated by an external server, and SAML
cannot cover the CLI or API. `ldap`, `kerberos` and `cloud` are unmeasured — no lab device has
such a profile.

**Either binding can name an authentication SEQUENCE instead of a profile** — measured
2026-09-11: completion offers a sequence at the per-account binding, both device-wide leaves and
captive portal. The device-wide leaves refuse a `local-database` profile and accept a sequence
containing one, so a sequence is how the device-wide binding can end in a local check.

`AdminUser` resolves a sequence the way it resolves a profile, shared first. An account bound to
one counts as external only when EVERY member resolves and is external: a local member is a way in
with a password the device stores. `authentication_sequence` says which kind the binding named.
Before this, an account bound to a sequence read as "profile not found" — and PAN-AUTH-019 fired on
one whose sequence was RADIUS then TACACS+.

**The other edge:** if the AAA server is down, nobody bound to it per-account can log in. Worth
saying in a report — it is the case *for* a documented break-glass account.

Auth events land in the SYSTEM log, subtype `auth`; `opaque` carries the reason, the profile, the
server profile and the server address. **`type=log` must go direct to the device** — Panorama
accepts `target=` on a log query, ignores it, and answers from its own database. A timed-out
attempt is logged when the timeout expires, *after* the API call returns, so a log query fired
immediately shows every case but the one under test.

## `client-certificate-only` governs the web interface only

Web Interface Help p.825: *"Use only client certificate authentication (web)."* It does not make a
local password or SSH key unreachable — the CLI still accepts them. An account with this set and a
`phash` present is still a locally-authenticating account.

`action=complete` on this leaf answers `code=2, "complete for this type not implemented yet"` — a
fourth outcome beyond the three the schema oracle normally gives, and evidence about the tool
rather than about the field.

## MFA is a fact about the account, reached through the binding

The value is resolved along the binding above rather than read off a profile: two accounts on one
appliance can sit behind different profiles, so a profile row cannot say which people are exposed.

The profile side is `multi-factor-auth/mfa-enable` plus `multi-factor-auth/factors`. The device
enforces the pairing in BOTH directions — `mfa-enable` is refused unless a factor is already
referenced, and a `multi-factor-auth` node carrying only `factors` is refused at commit with
*"multi-factor-auth is missing 'mfa-enable'"*. So neither key can appear without the other on a
committed configuration, no consumer need check for the pair, and there is no implicit value for
`mfa-enable`: a normalizer reading its absence as NO has no shape where it can be wrong.

**No profile at all means no second factor.** That is a finding, not a gap in the data.

## An MFA server profile is not a second factor for an ADMINISTRATOR

`multi-factor-auth/factors` names **MFA server profiles** — the firewall's direct integration with
a vendor's API (Duo v2, Okta Adaptive, PingID, RSA SecurID). PAN-OS invokes those through
**Authentication Policy, for end-user authentication only**. Not for web-interface administrator
login, and not for GlobalProtect.

> *"For remote user authentication to GlobalProtect portals and gateways and for administrator
> authentication to the Panorama and PAN-OS web interface, the firewall integrates with MFA
> vendors using RADIUS and SAML only."* — PAN-OS Administrator's Guide 11.2, p.221. The Web
> Interface Help p.941 says the same, and p.839 says it of the Factors tab itself: *"Although you
> can configure additional factors, they will not be enforced for these use cases."*

So `admin_mfa_enabled` on an `AdminUser` means *the profile this account is bound to declares a
factor*, not *this administrator is challenged for one*. An administrator's second factor has to
arrive through the FIRST factor — a RADIUS server profile pointing at the vendor's RADIUS
endpoint, or a SAML IdP that enforces MFA — and neither is distinguishable from a plain RADIUS or
SAML backend by reading the configuration. **The delivery lives on the other system.**

**RADIUS-delivered MFA is invisible to the configuration — measured.** Two administrators on
fw-core-tpa-b, `fwadmin` and `fwmfa`, each bound per-account to the SAME authentication profile
and the SAME RADIUS server profile, neither with a local password: identical configuration but for
the name. At the web interface `fwmfa` was prompted for an OTP after its password and `fwadmin`
was not. The difference is a policy on the RADIUS server, which is why no control reading the
firewall can say whether an administrator has MFA (PAN-AUTH-020, deferred). Over the XML API,
`type=keygen` as `fwmfa` was refused in 0.3s — the API cannot answer a RADIUS challenge, so an
administrator whose MFA is a challenge cannot mint a key with a password.

**The Factors tab, measured 2026-09-10** on fw-core-tpa-b (11.1.13-h3), because the same Help was measured wrong
twice that month on the lockout fields. `oep-mfa-admin` authenticates through `oep-auth-hardened`,
whose one factor points at a Duo host that does not resolve, with a 30-second timeout — so an
invoked factor could only hang and fail. The web login succeeded instantly with the password
alone. The device's system log has `auth-success` for the account naming *"auth profile
'oep-auth-hardened'"*, the Web login in the same second, and no MFA event between them; `show
admins` held the session.

### The server profile side

An `mfa-server-profile` needs an `mfa-cert-profile` before PAN-OS will COMMIT it. Without one it
writes cleanly and the commit says only *"Invalid MFA vendor config"*, naming no missing key.
Completing `mfa-cert-profile` on a device with no certificate profiles returns nothing — the object
type is absent, not the reference unsatisfiable.

## Reading it

    normalize_appliance_admin_users(appliance)   -> {"admin_users": n, "superusers": n}

One row per account on `AdminUser`, appliance-anchored, no scope column. `role_type` names the
branch and `role_scope` carries whatever the branch was qualified by. It runs AFTER
`normalize_authentication_profiles`, because it resolves each account's profile to read the method
and the MFA flag.

## Limits

- **Last login is in no configuration field and no operational command on these devices.** The
  system log carries `auth-success` events but they age out, so an absent event says nothing about
  an account last used before the retention window.
- **Whether a password is the factory default cannot be read.** `phash` is a hash.
- **A custom role's breadth cannot be judged from its entry** — see the role section above.
- `superreader`, and a populated `deviceadmin`/`devicereader` member list naming a device other
  than `localhost.localdomain`, have never been seen on hardware.
- The **template** case for `mgt-config/users` was read (creds_tpl, temp-stck-jb-rg) but never
  written from this side, so what a template push does to an account that already exists locally is
  untested here. `../read-template-provenance.md` covers the general rule.
- Which device-wide leaf governs **SSH** is untested.
- **An administrator defined only on the RADIUS, TACACS+ or SAML side has no entry here.** When a
  device-wide binding is set, `AdminUser` is not the whole administrator population — the rest
  exist only in the external server's policy, returned as a role at login (RADIUS vendor code
  25461, `PaloAlto-Admin-Role`). A set device-wide binding is the one signal in the configuration
  that such accounts may exist.
- `<test><authentication>` — the CLI's `test authentication` — is not an XML API command:
  HTTP 400 *"Unsupported command"* through Panorama and direct to the device alike.
