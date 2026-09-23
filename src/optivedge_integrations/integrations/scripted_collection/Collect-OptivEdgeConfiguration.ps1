<#
.SYNOPSIS
    Collects Palo Alto Networks configuration for an OptivEdge assessment.

.DESCRIPTION
    Read-only. Every command this script issues is a `show` or a config `get`; nothing is
    written to any device at any point.

    Two modes:

      Scope    Connect to a management station, list the devices it manages, and let you
               choose which are in scope. Writes a small text file naming them.

      Collect  Read that file and collect the configuration of the chosen devices, writing
               one file per response and then a single .zip to send back.

    Run it with no arguments for a menu.

.PARAMETER Mode
    Scope or Collect. Omit for the menu.

.PARAMETER ScopeFile
    The scope file to write (Scope) or read (Collect). Defaults to OptivEdgeScope.txt in the
    current directory.

.PARAMETER OutputPath
    Where the collected files are written. Defaults to a timestamped folder here.

.PARAMETER NoArchive
    Skip the .zip at the end and leave the folder as it is.

.NOTES
    Windows PowerShell 5.1 and PowerShell 7 both run this unmodified. It deliberately avoids
    anything newer than 5.1 - no ternaries, no -SkipCertificateCheck, no null-coalescing -
    because 5.1 is what ships with Windows and 7 is an optional install.

    The collected files are your own configuration in your own folder. Nothing is deleted or
    hidden: after the archive is written, the plain files stay where they are so you can see
    exactly what is being sent.
#>
[CmdletBinding()]
param(
    [ValidateSet('Scope', 'Collect')]
    [string] $Mode,

    [string] $ScopeFile = 'OptivEdgeScope.txt',

    [string] $OutputPath,

    [switch] $NoArchive
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ScriptVersion = '1.0.0'
$script:BundleSchemaVersion = 1

# Substituted when this script is GENERATED for an engagement. They are left as tokens in the
# source so the committed script still runs and still tests: the banner checks for the token
# rather than for emptiness, so an ungenerated copy simply says nothing about a client.
$script:ClientName = '__OPTIVEDGE_CLIENT_NAME__'
$script:GeneratedOn = '__OPTIVEDGE_GENERATED_ON__'

function Test-Substituted {
    param([string] $Value)
    return ($Value -and $Value -notlike '__OPTIVEDGE_*')
}

# Let Windows choose the TLS version. MEASURED 2026-09-23 against a Panorama that offers
# TLS 1.3 ONLY: the usual PowerShell 5.1 incantation - pinning SecurityProtocol to
# Tls12 -bor Tls11 - excludes 1.3 and every request fails with "Could not create SSL/TLS
# secure channel". SecurityProtocol = 0 means "system default", which on a current Windows
# negotiates 1.3 happily. `Invoke-PanRequest` falls back to an explicit modern set if the
# system default turns out to be too old to be accepted.
[System.Net.ServicePointManager]::SecurityProtocol = 0
$script:ExplicitTlsApplied = $false

# ------------------------------------------------------------------------------------------
# Output. Deliberately plain: this runs on someone else's machine, in their console, and its
# only job there is to show that it is alive and what it is doing.
# ------------------------------------------------------------------------------------------

function Write-Plain { param([string] $Text) Write-Host $Text }

function Write-Step {
    param([string] $Text)
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Text)
}

function Write-Good { param([string] $Text) Write-Host ("        " + $Text) -ForegroundColor Green }
function Write-Note { param([string] $Text) Write-Host ("        " + $Text) -ForegroundColor Yellow }
function Write-Bad  { param([string] $Text) Write-Host ("        " + $Text) -ForegroundColor Red }

function Write-Banner {
    Write-Plain ''
    Write-Plain '  OptivEdge configuration collection'
    if (Test-Substituted $script:ClientName) {
        if (Test-Substituted $script:GeneratedOn) {
            Write-Plain ('  prepared for {0}, {1}' -f $script:ClientName, $script:GeneratedOn)
        }
        else {
            Write-Plain ('  prepared for {0}' -f $script:ClientName)
        }
    }
    Write-Plain ('  version {0}   read-only: this script issues only show and get commands' -f $script:ScriptVersion)
    Write-Plain ''
}

function Format-Size {
    param([long] $Bytes)
    if ($Bytes -ge 1048576) { return ('{0:N1} MB' -f ($Bytes / 1048576)) }
    if ($Bytes -ge 1024) { return ('{0:N0} KB' -f ($Bytes / 1024)) }
    return ('{0} bytes' -f $Bytes)
}

# ------------------------------------------------------------------------------------------
# The certificate, shown before any credential is typed
# ------------------------------------------------------------------------------------------

function Get-ModernSslProtocols {
    <#
        Tls12 and Tls13 as an SslProtocols value, from whatever this .NET knows: Tls13 only
        exists from .NET Framework 4.8, so it is looked up rather than named outright.
    #>
    $protocols = 0
    foreach ($name in @('Tls12', 'Tls13')) {
        if ([System.Enum]::GetNames([System.Security.Authentication.SslProtocols]) -contains $name) {
            $protocols = $protocols -bor [int][System.Security.Authentication.SslProtocols]::$name
        }
    }
    return [System.Security.Authentication.SslProtocols] $protocols
}

function Set-ModernSecurityProtocol {
    $protocols = 0
    foreach ($name in @('Tls12', 'Tls13')) {
        if ([System.Enum]::GetNames([System.Net.SecurityProtocolType]) -contains $name) {
            $protocols = $protocols -bor [int][System.Net.SecurityProtocolType]::$name
        }
    }
    if ($protocols -eq 0) { return $false }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType] $protocols
    $script:ExplicitTlsApplied = $true
    return $true
}

function Get-PresentedCertificate {
    <#
        Opens a TLS connection purely to look at what the far end presents, and closes it.

        The validation callback returns $true unconditionally HERE so the handshake completes
        and the certificate can be shown - the trust decision is made afterwards, by the
        person reading it, and enforced on every later request by thumbprint.
    #>
    param([string] $HostName, [int] $Port)

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect($HostName, $Port)
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] { param($a, $b, $c, $d) return $true }
        $stream = New-Object System.Net.Security.SslStream($client.GetStream(), $false, $callback)
        try {
            $negotiated = ''
            try {
                $stream.AuthenticateAsClient($HostName)
            }
            catch {
                # This machine's defaults were refused. Retry with an explicit modern set and,
                # if that works, tell HttpWebRequest to use the same - otherwise every later
                # request would fail the same way. The probe lives here rather than around
                # each request because a handshake failure is unambiguous here, whereas a
                # failed request could equally be a certificate this script chose to refuse.
                $explicit = Get-ModernSslProtocols
                if ($explicit -eq 0) { throw }
                Write-Note 'This computer''s default TLS settings were refused; trying TLS 1.2/1.3.'
                $stream.AuthenticateAsClient($HostName, $null, $explicit, $false)
                Set-ModernSecurityProtocol | Out-Null
            }
            $negotiated = $stream.SslProtocol.ToString()
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($stream.RemoteCertificate)
        }
        finally { $stream.Dispose() }
    }
    finally { $client.Close() }

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $trusted = $chain.Build($certificate)

    $statuses = @()
    foreach ($status in $chain.ChainStatus) { $statuses += $status.StatusInformation.Trim() }

    return [PSCustomObject]@{
        Certificate  = $certificate
        Subject      = $certificate.Subject
        Issuer       = $certificate.Issuer
        Thumbprint   = $certificate.Thumbprint
        NotBefore    = $certificate.NotBefore
        NotAfter     = $certificate.NotAfter
        SubjectAltNames = (Get-SubjectAltNames -Certificate $certificate)
        IsTrusted    = $trusted
        ChainStatus  = $statuses
        Protocol     = $negotiated
    }
}

function Get-SubjectAltNames {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    foreach ($extension in $Certificate.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.17') {
            return ($extension.Format($false))
        }
    }
    return ''
}

function Confirm-Certificate {
    <#
        Most management interfaces present a certificate nothing trusts, so this is expected
        rather than alarming - but it is shown in full and confirmed BEFORE a password is
        typed, because accepting an unknown certificate is exactly when a password should not
        already be in flight.
    #>
    param([string] $HostName, $Presented)

    if ($Presented.IsTrusted) {
        Write-Good ("{0}, certificate trusted by this machine - {1}" -f $Presented.Protocol, $Presented.Subject)
        return $true
    }

    Write-Plain ''
    Write-Note 'This certificate is NOT trusted by this computer.'
    Write-Note 'That is normal for a firewall management interface, and worth reading anyway:'
    Write-Plain ''
    Write-Plain ('          Host          {0}' -f $HostName)
    Write-Plain ('          Protocol      {0}' -f $Presented.Protocol)
    Write-Plain ('          Subject       {0}' -f $Presented.Subject)
    Write-Plain ('          Issuer        {0}' -f $Presented.Issuer)
    Write-Plain ('          Valid         {0:yyyy-MM-dd} to {1:yyyy-MM-dd}' -f $Presented.NotBefore, $Presented.NotAfter)
    if ($Presented.SubjectAltNames) {
        Write-Plain ('          Alt names     {0}' -f $Presented.SubjectAltNames)
    }
    Write-Plain ('          SHA1 thumbprint {0}' -f $Presented.Thumbprint)
    foreach ($status in $Presented.ChainStatus) {
        Write-Plain ('          Why untrusted {0}' -f $status)
    }
    Write-Plain ''
    Write-Note 'Compare the thumbprint with the one on the device before continuing.'
    $answer = Read-Host '        Continue with this certificate? (y/N)'
    return ($answer -eq 'y' -or $answer -eq 'Y')
}

# ------------------------------------------------------------------------------------------
# The PAN-OS XML API
# ------------------------------------------------------------------------------------------

function Invoke-PanRequest {
    <#
        One POST to /api/, with the response either returned as text or streamed to a file.

        HttpWebRequest rather than Invoke-WebRequest for three reasons that all matter here:
        it takes a PER-REQUEST certificate callback, so nothing global is mutated and the
        pinned thumbprint applies to exactly this connection; it streams a large response
        straight to disk, and a merged configuration can be tens of megabytes; and it writes
        the bytes the device sent, with no encoding conversion and no byte-order mark.

        POST rather than GET so the API key and command never land in a proxy or server log.
    #>
    param(
        [string] $HostName,
        [int] $Port = 443,
        [hashtable] $Body,
        [string] $PinnedThumbprint,
        [string] $OutFile,
        [int] $TimeoutSeconds = 600
    )

    $pairs = @()
    foreach ($key in $Body.Keys) {
        $pairs += ('{0}={1}' -f [System.Uri]::EscapeDataString($key), [System.Uri]::EscapeDataString([string]$Body[$key]))
    }
    $payload = [System.Text.Encoding]::UTF8.GetBytes(($pairs -join '&'))

    $uri = ('https://{0}:{1}/api/' -f $HostName, $Port)
    $request = [System.Net.HttpWebRequest]::Create($uri)
    $request.Method = 'POST'
    $request.ContentType = 'application/x-www-form-urlencoded'
    $request.ContentLength = $payload.Length
    $request.Timeout = $TimeoutSeconds * 1000
    $request.ReadWriteTimeout = $TimeoutSeconds * 1000
    $request.UserAgent = ('OptivEdge-Collector/{0}' -f $script:ScriptVersion)
    $request.KeepAlive = $true

    if ($PinnedThumbprint) {
        $pinned = $PinnedThumbprint
        $request.ServerCertificateValidationCallback = {
            param($sender, $certificate, $chain, $errors)
            if ($null -eq $certificate) { return $false }
            $seen = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate)).Thumbprint
            return ($seen -eq $pinned)
        }.GetNewClosure()
    }

    $stream = $request.GetRequestStream()
    try { $stream.Write($payload, 0, $payload.Length) } finally { $stream.Dispose() }

    $response = $request.GetResponse()
    try {
        $responseStream = $response.GetResponseStream()
        if ($OutFile) {
            $file = [System.IO.File]::Create($OutFile)
            try { $responseStream.CopyTo($file) } finally { $file.Dispose() }
            return $null
        }
        $reader = New-Object System.IO.StreamReader($responseStream, [System.Text.Encoding]::UTF8)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    }
    finally { $response.Close() }
}

function Test-PanSuccess {
    <#
        PAN-OS answers a failed command with HTTP 200 and status="error", so the HTTP status
        code says nothing. The first bytes of the body do.

        Read as bytes and decoded here rather than loading the whole file: a merged config is
        large, and its verdict is in the first line.
    #>
    param([string] $Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $buffer = New-Object byte[] 512
        $read = $stream.Read($buffer, 0, $buffer.Length)
    }
    finally { $stream.Dispose() }

    $head = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
    if ($head -match 'status\s*=\s*"success"') { return $true }
    return $false
}

function Get-PanErrorText {
    param([string] $Path)
    try {
        $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ($text.Length -gt 400) { $text = $text.Substring(0, 400) }
        return ($text -replace '\s+', ' ').Trim()
    }
    catch { return 'unreadable response' }
}

function Get-PanApiKey {
    param([string] $HostName, [int] $Port, [string] $UserName, [string] $Password, [string] $PinnedThumbprint)

    $text = Invoke-PanRequest -HostName $HostName -Port $Port -PinnedThumbprint $PinnedThumbprint -Body @{
        type     = 'keygen'
        user     = $UserName
        password = $Password
    }

    $xml = [xml] $text
    if ($xml.response.status -ne 'success') {
        throw 'Authentication failed. Check the username and password.'
    }
    return $xml.response.result.key
}

function Connect-Station {
    <#
        Certificate first, then credentials, then an API key. The password is held only long
        enough to exchange it for a key, and never reaches disk.
    #>
    param([string] $HostName, [int] $Port = 443)

    Write-Step ("Connecting to {0}" -f $HostName)
    $presented = Get-PresentedCertificate -HostName $HostName -Port $Port
    if (-not (Confirm-Certificate -HostName $HostName -Presented $presented)) {
        throw ('Certificate for {0} was not accepted.' -f $HostName)
    }

    Write-Plain ''
    $userName = Read-Host '        Username'
    $secure = Read-Host '        Password' -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $apiKey = Get-PanApiKey -HostName $HostName -Port $Port -UserName $userName -Password $plain -PinnedThumbprint $presented.Thumbprint
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $plain = $null
    }

    Write-Good 'Authenticated.'
    return [PSCustomObject]@{
        HostName   = $HostName
        Port       = $Port
        ApiKey     = $apiKey
        Thumbprint = $presented.Thumbprint
        Trusted    = $presented.IsTrusted
        UserName   = $userName
    }
}

# ------------------------------------------------------------------------------------------
# Inventory
# ------------------------------------------------------------------------------------------

function Get-ManagedDevices {
    <#
        `show devices all`, parsed just far enough to offer a choice. The response is also
        written verbatim during a collection - this parse is for the menu, not for the data.
    #>
    param($Session)

    $text = Invoke-PanRequest -HostName $Session.HostName -Port $Session.Port -PinnedThumbprint $Session.Thumbprint -Body @{
        type = 'op'
        cmd  = '<show><devices><all></all></devices></show>'
        key  = $Session.ApiKey
    }

    $xml = [xml] $text
    if ($xml.response.status -ne 'success') {
        throw 'The management station did not return a device inventory.'
    }

    $devices = @()
    $entries = $xml.SelectNodes('/response/result/devices/entry')
    foreach ($entry in $entries) {
        $serial = Get-NodeText -Node $entry -Names @('serial', 'serial-no')
        if (-not $serial) { continue }

        $vsysNames = @()
        foreach ($vsysEntry in $entry.SelectNodes('vsys/entry')) {
            $name = $vsysEntry.GetAttribute('name')
            if (-not $name) { $name = (Get-NodeText -Node $vsysEntry -Names @('name')) }
            if ($name) { $vsysNames += $name }
        }

        $devices += [PSCustomObject]@{
            Serial    = $serial
            Hostname  = (Get-NodeText -Node $entry -Names @('hostname', 'host-name', 'dns-hostname'))
            Model     = (Get-NodeText -Node $entry -Names @('model'))
            Version   = (Get-NodeText -Node $entry -Names @('sw-version', 'software-version'))
            Connected = (Get-NodeText -Node $entry -Names @('connected'))
            Vsys      = $vsysNames
        }
    }
    return $devices
}

function Get-NodeText {
    param($Node, [string[]] $Names)
    foreach ($name in $Names) {
        $child = $Node.SelectSingleNode($name)
        if ($null -ne $child -and $child.InnerText) { return $child.InnerText.Trim() }
    }
    return ''
}

function Show-DeviceTable {
    param($Devices)
    Write-Plain ''
    Write-Plain '          #   Serial            Hostname                   Model           Version      vsys  Connected'
    Write-Plain '          --  ----------------  -------------------------  --------------  -----------  ----  ---------'
    $anyDisconnected = $false
    for ($i = 0; $i -lt $Devices.Count; $i++) {
        $device = $Devices[$i]
        $connected = $device.Connected
        if (-not $connected) { $connected = 'unknown' }
        if ($connected -ne 'yes') { $anyDisconnected = $true }
        Write-Plain ('          {0,-3} {1,-17} {2,-26} {3,-15} {4,-12} {5,-5} {6}' -f `
            ($i + 1), $device.Serial, $device.Hostname, $device.Model, $device.Version, $device.Vsys.Count, $connected)
    }
    Write-Plain ''
    if ($anyDisconnected) {
        Write-Note 'Devices not connected to this station cannot be collected through it.'
        Write-Plain ''
    }
}

function ConvertFrom-SelectionText {
    <#
        "1,4,7-9" or "all" into 1-based positions, or $null when it cannot be read.

        Separate from the prompt so it can be tested: a mis-parsed range does not fail
        loudly, it silently collects the wrong devices.
    #>
    param([string] $Text, [int] $Count)

    $Text = $Text.Trim()
    if (-not $Text) { return $null }
    if ($Text -eq 'all') { return @(1..$Count) }

    $positions = @()
    foreach ($part in ($Text -split ',')) {
        $part = $part.Trim()
        if ($part -match '^(\d+)\s*-\s*(\d+)$') {
            $from = [int] $Matches[1]
            $to = [int] $Matches[2]
            if ($from -lt 1 -or $to -gt $Count -or $from -gt $to) { return $null }
            for ($i = $from; $i -le $to; $i++) { $positions += $i }
        }
        elseif ($part -match '^\d+$') {
            $index = [int] $part
            if ($index -lt 1 -or $index -gt $Count) { return $null }
            $positions += $index
        }
        else { return $null }
    }
    if ($positions.Count -eq 0) { return $null }
    return @($positions | Sort-Object -Unique)
}

function Read-Selection {
    param($Devices)

    while ($true) {
        $answer = Read-Host '        Devices in scope (e.g. 1,3,5-8 or all)'
        $positions = ConvertFrom-SelectionText -Text $answer -Count $Devices.Count
        if ($null -ne $positions) {
            $chosen = @()
            foreach ($position in $positions) { $chosen += $Devices[$position - 1] }
            return @($chosen)
        }
        Write-Bad 'Could not read that. Use numbers from the table, for example 1,3,5-8.'
    }
}

# ------------------------------------------------------------------------------------------
# The scope file - plain text on purpose, so it can be written or corrected by hand
# ------------------------------------------------------------------------------------------

function Write-ScopeFile {
    param([string] $Path, $StationSelections)

    $lines = @()
    $lines += '# OptivEdge collection scope'
    $lines += ('# written {0} by version {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $script:ScriptVersion)
    $lines += '#'
    $lines += '# One section per management station, one serial number per line.'
    $lines += '# Edit this file directly if it is easier than re-running the scope step.'
    $lines += ''
    foreach ($selection in $StationSelections) {
        $lines += ('[{0}]' -f $selection.HostName)
        foreach ($device in $selection.Devices) {
            $comment = $device.Hostname
            if (-not $comment) { $comment = $device.Model }
            $lines += ('{0}    # {1}' -f $device.Serial, $comment)
        }
        $lines += ''
    }
    Set-Content -LiteralPath $Path -Value $lines -Encoding UTF8
}

function Read-ScopeFile {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw ('Scope file not found: {0}. Run the scope step first, or point -ScopeFile at one.' -f $Path)
    }

    $stations = @()
    $current = $null
    foreach ($rawLine in (Get-Content -LiteralPath $Path)) {
        $line = $rawLine
        $hash = $line.IndexOf('#')
        if ($hash -ge 0) { $line = $line.Substring(0, $hash) }
        $line = $line.Trim()
        if (-not $line) { continue }

        if ($line -match '^\[(.+)\]$') {
            $current = [PSCustomObject]@{ HostName = $Matches[1].Trim(); Serials = @() }
            $stations += $current
            continue
        }
        if ($null -eq $current) {
            throw ('Scope file has a serial before any [station] line: {0}' -f $line)
        }
        $current.Serials += $line
    }

    if ($stations.Count -eq 0) { throw ('Scope file names no devices: {0}' -f $Path) }
    return $stations
}

# ------------------------------------------------------------------------------------------
# Collection state, so an interrupted run resumes instead of starting over
# ------------------------------------------------------------------------------------------

function Get-State {
    param([string] $Path)
    if (Test-Path -LiteralPath $Path) {
        try {
            $loaded = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
            $state = @{}
            foreach ($property in $loaded.PSObject.Properties) { $state[$property.Name] = $property.Value }
            return $state
        }
        catch {
            Write-Note 'Could not read the previous state file; starting this folder again.'
        }
    }
    return @{}
}

function Save-State {
    param([string] $Path, [hashtable] $State)
    ($State | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $Path -Encoding UTF8
}

# ------------------------------------------------------------------------------------------
# Collection
# ------------------------------------------------------------------------------------------

function Invoke-CollectionItem {
    <#
        One command, one file, one state entry. A failure is recorded and the run continues:
        one unreachable device must not cost the other fifty-nine.
    #>
    param(
        $Session,
        [hashtable] $State,
        [string] $StatePath,
        [string] $Key,
        [string] $RelativePath,
        [string] $Root,
        [hashtable] $Body,
        [string] $Label
    )

    if ($State.ContainsKey($Key) -and $State[$Key].Status -eq 'ok') {
        Write-Plain ('        skip  {0} (already collected)' -f $Label)
        return
    }

    $fullPath = Join-Path $Root $RelativePath
    $directory = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $started = Get-Date
    try {
        $requestBody = @{ key = $Session.ApiKey }
        foreach ($name in $Body.Keys) { $requestBody[$name] = $Body[$name] }

        Invoke-PanRequest -HostName $Session.HostName -Port $Session.Port `
            -PinnedThumbprint $Session.Thumbprint -Body $requestBody -OutFile $fullPath | Out-Null

        $size = (Get-Item -LiteralPath $fullPath).Length
        if (Test-PanSuccess -Path $fullPath) {
            Write-Good ('ok    {0}  {1}' -f $Label, (Format-Size $size))
            $State[$Key] = [PSCustomObject]@{
                Status = 'ok'; Path = $RelativePath; Bytes = $size
                CollectedAt = $started.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
        }
        else {
            $message = Get-PanErrorText -Path $fullPath
            Write-Note ('error {0}  {1}' -f $Label, $message)
            $State[$Key] = [PSCustomObject]@{
                Status = 'error'; Path = $RelativePath; Bytes = $size; Message = $message
                CollectedAt = $started.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
        }
    }
    catch {
        $message = $_.Exception.Message
        Write-Bad ('failed {0}  {1}' -f $Label, $message)
        $State[$Key] = [PSCustomObject]@{
            Status = 'failed'; Path = $RelativePath; Message = $message
            CollectedAt = $started.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
        if (Test-Path -LiteralPath $fullPath) { Remove-Item -LiteralPath $fullPath -Force }
    }

    Save-State -Path $StatePath -State $State
}

function Get-StationFolderName {
    param([string] $HostName)
    return ($HostName -replace '[^A-Za-z0-9\.\-_]', '_')
}

function Invoke-StationCollection {
    param($Session, [string[]] $Serials, [string] $Root, [hashtable] $State, [string] $StatePath)

    $stationFolder = Join-Path 'stations' (Get-StationFolderName -HostName $Session.HostName)

    Write-Step ('Station-wide data from {0}' -f $Session.HostName)

    Invoke-CollectionItem -Session $Session -State $State -StatePath $StatePath -Root $Root `
        -Key ('{0}|station|show_devices_all' -f $Session.HostName) `
        -RelativePath (Join-Path $stationFolder 'station\show_devices_all.xml') `
        -Body @{ type = 'op'; cmd = '<show><devices><all></all></devices></show>' } `
        -Label 'device inventory'

    Invoke-CollectionItem -Session $Session -State $State -StatePath $StatePath -Root $Root `
        -Key ('{0}|station|show_dg_hierarchy' -f $Session.HostName) `
        -RelativePath (Join-Path $stationFolder 'station\show_dg_hierarchy.xml') `
        -Body @{ type = 'op'; cmd = '<show><dg-hierarchy/></show>' } `
        -Label 'device-group hierarchy'

    # The vsys list comes from the inventory rather than the scope file, so the scope file
    # stays a list of serials that a person can edit.
    $devices = @(Get-ManagedDevices -Session $Session)
    $bySerial = @{}
    foreach ($device in $devices) { $bySerial[$device.Serial] = $device }

    $position = 0
    foreach ($serial in $Serials) {
        $position += 1
        $device = $null
        if ($bySerial.ContainsKey($serial)) { $device = $bySerial[$serial] }

        $label = $serial
        if ($device -and $device.Hostname) { $label = ('{0} ({1})' -f $device.Hostname, $serial) }
        Write-Step ('Device {0} of {1}: {2}' -f $position, $Serials.Count, $label)

        if ($null -eq $device) {
            Write-Note 'This serial is not in the station inventory; collecting what can be reached anyway.'
        }
        elseif ($device.Connected -and $device.Connected -ne 'yes') {
            # Every command for a device the station cannot reach comes back "not connected".
            # Measured 2026-09-23: that is seventeen failed requests per device, each waiting
            # on the network, for an answer the inventory already gave. Nothing is written to
            # the state file, so a later run collects it if the device comes back.
            Write-Note ('Station reports this device as not connected ({0}); skipping it.' -f $device.Connected)
            continue
        }

        $deviceFolder = Join-Path $stationFolder ('appliance\' + $serial)

        $commands = @(
            @{ Name = 'show_config_merged'; Label = 'merged configuration'
               Body = @{ type = 'op'; cmd = '<show><config><merged></merged></config></show>'; target = $serial } },
            @{ Name = 'show_masterkey_properties'; Label = 'master key properties'
               Body = @{ type = 'op'; cmd = '<show><system><masterkey-properties></masterkey-properties></system></show>'; target = $serial } },
            @{ Name = 'show_pushed_shared_policy'; Label = 'pushed shared policy'
               Body = @{ type = 'op'; cmd = '<show><config><pushed-shared-policy/></config></show>'; target = $serial } },
            @{ Name = 'show_predefined_ip_block_lists'; Label = 'predefined IP block lists'
               Body = @{ type = 'op'; cmd = '<show><predefined><xpath>/predefined/ip-block-list-v2</xpath></predefined></show>'; target = $serial } },
            @{ Name = 'show_predefined_url_lists'; Label = 'predefined URL lists'
               Body = @{ type = 'op'; cmd = '<show><predefined><xpath>/predefined/url-predefined</xpath></predefined></show>'; target = $serial } },
            @{ Name = 'config_predefined_ssl_tls_service_profiles'; Label = 'predefined TLS profiles'
               Body = @{ type = 'config'; action = 'get'; xpath = '/config/predefined/ssl-tls-service-profile'; target = $serial } },
            @{ Name = 'config_predefined_certificates'; Label = 'predefined certificates'
               Body = @{ type = 'config'; action = 'get'; xpath = '/config/predefined/certificate'; target = $serial } },
            @{ Name = 'config_predefined_security_profiles'; Label = 'predefined security profiles'
               Body = @{ type = 'config'; action = 'get'; xpath = '/config/predefined/profiles'; target = $serial } }
        )

        foreach ($command in $commands) {
            Invoke-CollectionItem -Session $Session -State $State -StatePath $StatePath -Root $Root `
                -Key ('{0}|{1}|{2}' -f $Session.HostName, $serial, $command.Name) `
                -RelativePath (Join-Path $deviceFolder ($command.Name + '.xml')) `
                -Body $command.Body -Label $command.Label
        }

        if ($device) {
            foreach ($vsys in $device.Vsys) {
                $vsysFolder = Join-Path $deviceFolder ('vsys\' + $vsys)
                Invoke-CollectionItem -Session $Session -State $State -StatePath $StatePath -Root $Root `
                    -Key ('{0}|{1}|{2}|show_pushed_shared_policy_vsys' -f $Session.HostName, $serial, $vsys) `
                    -RelativePath (Join-Path $vsysFolder 'show_pushed_shared_policy_vsys.xml') `
                    -Body @{ type = 'op'
                             cmd = ('<show><config><pushed-shared-policy><vsys>{0}</vsys></pushed-shared-policy></config></show>' -f $vsys)
                             target = $serial } `
                    -Label ('pushed policy for ' + $vsys)
            }
        }
    }
}

function Write-Manifest {
    <#
        What the bundle is, so the far end never has to infer it from folder names.

        The per-item records come from the state file, which means an item that FAILED is in
        the manifest too, with its reason. A gap that is described is a different thing from
        a gap that is silent.
    #>
    param([string] $Root, [hashtable] $State, $Stations, [datetime] $StartedAt)

    $items = @()
    foreach ($key in ($State.Keys | Sort-Object)) {
        $entry = $State[$key]
        $record = @{ key = $key; status = $entry.Status; path = $entry.Path; collected_at = $entry.CollectedAt }
        if ($entry.PSObject.Properties.Name -contains 'Bytes') { $record['bytes'] = $entry.Bytes }
        if ($entry.PSObject.Properties.Name -contains 'Message') { $record['message'] = $entry.Message }
        $items += $record
    }

    $stationRecords = @()
    foreach ($station in $Stations) {
        $stationRecords += @{
            hostname = $station.HostName
            folder = (Join-Path 'stations' (Get-StationFolderName -HostName $station.HostName))
            serials = @($station.Serials)
        }
    }

    $manifest = [ordered]@{
        schema_version   = $script:BundleSchemaVersion
        script_version   = $script:ScriptVersion
        generated_by     = 'Collect-OptivEdgeConfiguration.ps1'
        collected_on     = $env:COMPUTERNAME
        powershell       = $PSVersionTable.PSVersion.ToString()
        started_at       = $StartedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        finished_at      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        stations         = $stationRecords
        items            = $items
    }

    ($manifest | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath (Join-Path $Root 'manifest.json') -Encoding UTF8
}

function New-BundleArchive {
    param([string] $Root)

    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    $archivePath = $Root.TrimEnd('\') + '.zip'
    if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $Root, $archivePath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    return $archivePath
}

# ------------------------------------------------------------------------------------------
# Modes
# ------------------------------------------------------------------------------------------

function Invoke-ScopeMode {
    param([string] $ScopeFilePath)

    Write-Plain '  Step 1 of 2 - choose the devices in scope.'
    Write-Plain ''

    $selections = @()
    while ($true) {
        $hostName = (Read-Host '        Management station hostname or IP').Trim()
        if (-not $hostName) { continue }

        try {
            $session = Connect-Station -HostName $hostName
            $devices = @(Get-ManagedDevices -Session $session)
        }
        catch {
            Write-Bad $_.Exception.Message
            $again = Read-Host '        Try another station? (y/N)'
            if ($again -eq 'y' -or $again -eq 'Y') { continue } else { break }
        }

        if ($devices.Count -eq 0) {
            Write-Note 'This station reports no managed devices.'
        }
        else {
            Write-Good ('{0} managed device(s) found.' -f $devices.Count)
            Show-DeviceTable -Devices $devices
            $chosen = @(Read-Selection -Devices $devices)
            Write-Good ('{0} device(s) selected.' -f $chosen.Count)
            $selections += [PSCustomObject]@{ HostName = $hostName; Devices = $chosen }
        }

        $more = Read-Host '        Add another management station? (y/N)'
        if (-not ($more -eq 'y' -or $more -eq 'Y')) { break }
    }

    if ($selections.Count -eq 0) {
        Write-Bad 'Nothing selected; no scope file written.'
        return
    }

    Write-ScopeFile -Path $ScopeFilePath -StationSelections $selections
    Write-Plain ''
    Write-Good ('Scope file written: {0}' -f (Resolve-Path -LiteralPath $ScopeFilePath))
    Write-Plain '        Review or edit it if you want, then run this script again and choose Collect.'
    Write-Plain ''
}

function Invoke-CollectMode {
    param([string] $ScopeFilePath, [string] $Root, [switch] $SkipArchive)

    $stations = @(Read-ScopeFile -Path $ScopeFilePath)
    $total = 0
    foreach ($station in $stations) { $total += $station.Serials.Count }

    Write-Plain ('  Step 2 of 2 - collecting {0} device(s) across {1} management station(s).' -f $total, $stations.Count)
    Write-Plain '  This is read-only and can be interrupted; re-running it resumes where it stopped.'
    Write-Plain ''

    if (-not (Test-Path -LiteralPath $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
    $statePath = Join-Path $Root 'state.json'
    $state = Get-State -Path $statePath
    if ($state.Count -gt 0) {
        Write-Note ('Resuming - {0} item(s) already collected in this folder.' -f $state.Count)
    }

    $startedAt = Get-Date
    foreach ($station in $stations) {
        try {
            $session = Connect-Station -HostName $station.HostName
        }
        catch {
            Write-Bad ('Skipping {0}: {1}' -f $station.HostName, $_.Exception.Message)
            continue
        }
        Invoke-StationCollection -Session $session -Serials $station.Serials -Root $Root -State $state -StatePath $statePath
    }

    Write-Manifest -Root $Root -State $state -Stations $stations -StartedAt $startedAt

    $ok = 0; $bad = 0
    foreach ($key in $state.Keys) {
        if ($state[$key].Status -eq 'ok') { $ok += 1 } else { $bad += 1 }
    }

    Write-Plain ''
    Write-Step ('Collected {0} file(s); {1} did not return data.' -f $ok, $bad)

    if (-not $SkipArchive) {
        Write-Step 'Building the archive.'
        $archive = New-BundleArchive -Root $Root
        $size = (Get-Item -LiteralPath $archive).Length
        Write-Good ('{0}  ({1})' -f $archive, (Format-Size $size))
        Write-Plain ''
        Write-Plain '        Send that .zip back to your Optiv contact.'
        Write-Plain ('        The plain files stay in {0} so you can see exactly what it contains.' -f $Root)
    }
    else {
        Write-Good $Root
    }
    Write-Plain ''
}

function Show-Menu {
    Write-Plain '  What would you like to do?'
    Write-Plain ''
    Write-Plain '    1  Choose the devices in scope   (connects to a management station, writes a scope file)'
    Write-Plain '    2  Collect the configuration     (reads the scope file, writes the files to send back)'
    Write-Plain '    3  Quit'
    Write-Plain ''
    while ($true) {
        $answer = (Read-Host '        Choice').Trim()
        if ($answer -eq '1') { return 'Scope' }
        if ($answer -eq '2') { return 'Collect' }
        if ($answer -eq '3') { return 'Quit' }
    }
}

# ------------------------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------------------------

if ($MyInvocation.InvocationName -eq '.') {
    # Dot-sourced: define the functions and stop, so they can be tested without a device.
    return
}

Write-Banner

if (-not $OutputPath) {
    $OutputPath = Join-Path (Get-Location).Path ('OptivEdgeCollection-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

$chosenMode = $Mode
if (-not $chosenMode) { $chosenMode = Show-Menu }

try {
    switch ($chosenMode) {
        'Scope' { Invoke-ScopeMode -ScopeFilePath $ScopeFile }
        'Collect' { Invoke-CollectMode -ScopeFilePath $ScopeFile -Root $OutputPath -SkipArchive:$NoArchive }
        'Quit' { Write-Plain '  Nothing to do.'; Write-Plain '' }
    }
}
catch {
    Write-Plain ''
    Write-Bad $_.Exception.Message
    Write-Plain ''
    exit 1
}
