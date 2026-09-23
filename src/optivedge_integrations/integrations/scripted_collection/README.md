# Scripted collection

For an estate this tool cannot reach directly. The customer runs a PowerShell script on their
own machine; it collects the same PAN-OS responses the live path collects, writes them to
files, and archives them. We ingest the archive.

`Collect-OptivEdgeConfiguration.ps1` is the script, `Collect-OptivEdgeConfiguration.cmd` the
launcher, and `Instructions.txt` the page that ships with them.

## Why it is written the way it is

**Windows PowerShell 5.1**, because that is what ships with Windows 11 - PowerShell 7 is an
optional install and a locked-down estate will not have it. So: no ternaries, no
null-coalescing, no `-SkipCertificateCheck`, no `AesGcm`, no `ImportSubjectPublicKeyInfo`.
It runs unmodified on 7 as well.

**The TLS version is left to Windows.** Measured 2026-09-23 against a Panorama that offers
**TLS 1.3 only**: the usual 5.1 incantation - pinning `SecurityProtocol` to `Tls12 -bor Tls11`
- EXCLUDES 1.3, and every request fails with "Could not create SSL/TLS secure channel". The
script sets `SecurityProtocol = 0` (system default) and falls back to an explicit TLS 1.2/1.3
set only if the handshake is actually refused. That probe sits in `Get-PresentedCertificate`,
at connect time, because a failure there is unambiguous - around a request it could equally be
a certificate the script deliberately refused.

**The certificate is shown before a password is typed**, and then pinned by thumbprint for
every later request. Most management interfaces present something untrusted, so the point is
not to refuse it - it is that accepting an unknown certificate should not happen with a
credential already in flight. Pinning uses `HttpWebRequest.ServerCertificateValidationCallback`,
which is per request, so nothing global is mutated.

**`HttpWebRequest`, not `Invoke-WebRequest`**: a per-request certificate callback, a response
streamed straight to disk (a merged config runs to tens of megabytes), and the device's exact
bytes with no encoding conversion and no byte-order mark.

**A disconnected device is skipped, not attempted.** `show devices all` reports `connected`,
and a device that is not connected answers all seventeen of its commands with "not connected".
Nothing is written to the state file, so a later run collects it if it comes back.

**PAN-OS answers a failed command with HTTP 200 and `status="error"`**, so the HTTP status code
says nothing. `Test-PanSuccess` reads the first 512 bytes of the file rather than loading it.

## The bundle

```
manifest.json                 schema version, stations, one record per item, ok or not
state.json                    resume state; also the source of the manifest's item records
stations/<host>/station/show_devices_all.xml
stations/<host>/station/show_dg_hierarchy.xml
stations/<host>/appliance/<serial>/show_config_merged.xml
stations/<host>/appliance/<serial>/show_masterkey_properties.xml
stations/<host>/appliance/<serial>/show_pushed_shared_policy.xml
stations/<host>/appliance/<serial>/{show,config}_predefined_*.xml
stations/<host>/appliance/<serial>/vsys/<vsys>/show_pushed_shared_policy_vsys.xml
```

Keyed by station because an appliance is keyed by serial PER STATION - the same device managed
by two Panoramas does not collide.

**`show pushed-shared-policy` is collected per serial, not per HA pair.** The script has no
concept of an appliance group, so it asks every device rather than picking one node. One extra
call per pair, and the bundle stays independent of our topology model: ingest decides which
copy belongs to which group.

**An item that FAILED is in the manifest too, with its reason.** A gap that is described is a
different thing from a gap that is silent.

## Running the tests

Offline, no device, on Windows:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-CollectorTests.ps1
```

From WSL, against the real Windows PowerShell:

```
/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass \
    -File 'C:\path\to\tests\Invoke-CollectorTests.ps1'
```

The script guards its entry point with `$MyInvocation.InvocationName -eq '.'`, so dot-sourcing
loads the functions without running a mode.

## Not built yet

* **Encryption.** The archive is plaintext. The plan: a per-environment RSA keypair generated in
  the app, the public key baked into the generated script, AES-256-CBC with encrypt-then-HMAC
  for the archive and RSA-OAEP-SHA256 for the AES key. `AesGcm` and PEM import are both absent
  from .NET Framework, which is what picks those primitives.
* **Ingest.** Replaying a bundle through the same persistence and normalization the live flow
  uses. The manifest is the contract; read only items whose status is `ok`.
* **Generation.** The script is static here. It becomes a template with the public key and the
  client's name substituted in.
* **Signing.** Unsigned, so the `.cmd` launcher is what makes it start. Group Policy can set the
  execution policy such that nothing but a signed script runs, and no launcher can work around
  that.
