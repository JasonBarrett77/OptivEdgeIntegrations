# Reading the management SSH server

> What a firewall's CLI SSH server offers, and why the configuration alone cannot say it.

*Established 2026-09-11 against fw-core-tpa-a and -b (PA-5220, 11.1.13-h3) and pan-fw-111 (PA-VM,
11.2.3-h3), by `action=complete` and by reading each server's SSH KEXINIT proposal with a client
that never authenticates. Re-verify after a PAN-OS upgrade.*

## Where it lives

    deviceconfig/system/ssh/mgmt/server-profile                    the binding - a name
    deviceconfig/system/ssh/profiles/mgmt-profiles/server-profiles/entry[@name]
        ciphers / kex / mac        member lists
        default-hostkey/key-type   ECDSA 256|384|521, RSA 2048|3072|4096, or all
        session-rekey              interval (s), data (MB), packets (2^n)

`ha/ha-profile` and `profiles/ha-profiles` are the same shape for HA1. The key set is identical on
11.1 and 11.2. `ciphers`, `kex` and `mac` complete to nothing on the leaf — they are member lists;
complete `<leaf>/member` for the values:

| list | selectable in a profile |
|---|---|
| ciphers | aes128/192/256-cbc, aes128/192/256-ctr, aes128/256-gcm |
| kex | diffie-hellman-group14-sha1, ecdh-sha2-nistp256/384/521 |
| mac | hmac-sha1, hmac-sha2-256, hmac-sha2-512 |

## With nothing bound, the device offers its default — and it is not in the configuration

None of the three lab devices binds a profile, and all three offer the same set — the full
OpenSSH 8.0 default, not the values a profile can choose:

| list | default offer |
|---|---|
| KEX | curve25519-sha256(@libssh.org), ecdh-sha2-nistp256/384/521, diffie-hellman-group-exchange-sha256, group16-sha512, group14-sha256, **group14-sha1** |
| host key | rsa-sha2-512, rsa-sha2-256, **ssh-rsa** — an RSA 2048 key |
| ciphers | chacha20-poly1305, aes128/192/256-ctr, aes128/256-gcm — no CBC |
| MACs | umac-64-etm, umac-128-etm, hmac-sha2-256-etm, hmac-sha2-512-etm, **hmac-sha1-etm**, **umac-64**, umac-128, hmac-sha2-256, hmac-sha2-512, **hmac-sha1** |

It contains nothing below the usual floors — no group1-sha1, no group-exchange-sha1, no CBC, no
MD5 — and it contains several algorithms a profile cannot select (chacha20, curve25519, every
`-etm` MAC). **Binding a profile can only narrow the offer to the configurable subset.** The table
is measured per release; `ManagementSshSettings.defaults_measured` says whether this appliance's
release is one of them.

## An unset list is the default, not empty

A bound profile that sets only `ciphers` narrowed the ciphers and left KEX, MACs and the host key
exactly at the default offer. An EXPLICITLY EMPTY list is the same state: `<kex/>` with no members is
accepted, commits, and after the restart the device offers its whole default KEX set. So each list is resolved on its own: the profile's where it sets
one, the default where it does not — which is what `ManagementSshSettings` stores, with a
`*_default` flag per list.

## Configured is not in force

**A bound profile changes nothing until the SSH service restarts.** Dropping one cipher from a
bound profile and committing left it offered 10 s and 20 s later; `set ssh service-restart mgmt`
applied it. The restart is an ordinary op command and works over the XML API:

    <set><ssh><service-restart><mgmt/></service-restart></ssh></set>
    -> "Successfully restarted SSH service"

Nothing in the configuration records whether the restart has happened, so a control reading it
describes the CONFIGURED offer. The findings say so.

## Reading it

    normalize_management_ssh(appliance)   -> {"management_ssh_settings": 1}

One row per appliance. The flags — `offers_cbc_cipher`, `offers_weak_mac` (anything outside
HMAC-SHA2), `offers_sha1_kex`, `offers_weak_kex`, `offers_sha2_256_mac` — and the per-list
`*_default` flags are what controls query; the lists are for display. PAN-MCR-002 reads
`kex_default`: an unrestricted KEX list is the finding, because nothing weaker than
group14-sha1 exists to find. The release comes from `Appliance.software_version`, which the
Panorama device-list normalizer fills.

## Limits

- Two releases, two platforms measured, one server build (OpenSSH_8.0). A release with a
  different build may offer a different default; until measured, the 11.1 table stands in and
  `defaults_measured` is false.
- Whether any operational command reports the ACTIVE profile is untested — that is the only way
  an assessment could tell configured from in force.
- HA1 SSH (`ha-profiles`), Panorama's own management SSH and Log Collector SSH are not modelled.
