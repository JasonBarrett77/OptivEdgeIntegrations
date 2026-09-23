<#
    Offline tests for Collect-OptivEdgeConfiguration.ps1. No device, no network.

    Run on Windows PowerShell 5.1, which is what the script targets:

        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-CollectorTests.ps1

    The script is dot-sourced, which loads its functions without running either mode.
#>
[CmdletBinding()]
param([string] $ScriptPath)

$ErrorActionPreference = 'Stop'

if (-not $ScriptPath) {
    $ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Collect-OptivEdgeConfiguration.ps1'
}
. $ScriptPath

$script:Failures = 0
function Check {
    param([string] $Name, $Actual, $Expected)
    if ("$Actual" -eq "$Expected") { Write-Host ("  PASS  " + $Name) }
    else {
        Write-Host ("  FAIL  {0}: got '{1}' want '{2}'" -f $Name, $Actual, $Expected) -ForegroundColor Red
        $script:Failures++
    }
}

$work = Join-Path $env:TEMP ('oe-collector-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    Write-Host '-- the selection a person types --'
    Check 'single'         ((ConvertFrom-SelectionText -Text '3' -Count 8) -join ',') '3'
    Check 'list'           ((ConvertFrom-SelectionText -Text '1,3,5' -Count 8) -join ',') '1,3,5'
    Check 'range'          ((ConvertFrom-SelectionText -Text '2-5' -Count 8) -join ',') '2,3,4,5'
    Check 'mixed'          ((ConvertFrom-SelectionText -Text '1,4-6, 8' -Count 8) -join ',') '1,4,5,6,8'
    Check 'all'            ((ConvertFrom-SelectionText -Text 'all' -Count 3) -join ',') '1,2,3'
    Check 'dedupes'        ((ConvertFrom-SelectionText -Text '2,2,1-2' -Count 8) -join ',') '1,2'
    # Each of these must be REFUSED rather than guessed at: a mis-read range does not fail
    # loudly, it quietly collects the wrong devices.
    Check 'past the end'   ((ConvertFrom-SelectionText -Text '9' -Count 8) -join ',') ''
    Check 'zero'           ((ConvertFrom-SelectionText -Text '0' -Count 8) -join ',') ''
    Check 'backwards'      ((ConvertFrom-SelectionText -Text '5-2' -Count 8) -join ',') ''
    Check 'range past end' ((ConvertFrom-SelectionText -Text '1-99' -Count 8) -join ',') ''
    Check 'words'          ((ConvertFrom-SelectionText -Text 'first two' -Count 8) -join ',') ''
    Check 'partly junk'    ((ConvertFrom-SelectionText -Text '1,x' -Count 8) -join ',') ''

    Write-Host '-- scope file round trip --'
    $selections = @(
        [PSCustomObject]@{ HostName = 'panorama-a.example.com'; Devices = @(
            [PSCustomObject]@{ Serial = '013201001085'; Hostname = 'fw-core-tpa-a'; Model = 'PA-5220' },
            [PSCustomObject]@{ Serial = '013201001475'; Hostname = 'fw-core-tpa-b'; Model = 'PA-5220' }) },
        [PSCustomObject]@{ HostName = 'panorama-b.example.com'; Devices = @(
            [PSCustomObject]@{ Serial = '0009C101234'; Hostname = 'pan-fw-111'; Model = 'PA-VM' }) }
    )
    $scopePath = Join-Path $work 'scope.txt'
    Write-ScopeFile -Path $scopePath -StationSelections $selections
    $back = @(Read-ScopeFile -Path $scopePath)
    Check 'two stations'    $back.Count 2
    Check 'first station'   $back[0].HostName 'panorama-a.example.com'
    Check 'first serials'   ($back[0].Serials -join ',') '013201001085,013201001475'
    Check 'second serials'  ($back[1].Serials -join ',') '0009C101234'

    Write-Host '-- a scope file edited by hand --'
    $hand = Join-Path $work 'hand.txt'
    @('# a comment', '', '[fw.example.com]', '  0011AA22  ', '0033BB44   # note') | Set-Content $hand
    Check 'hand edited' ((@(Read-ScopeFile -Path $hand))[0].Serials -join ',') '0011AA22,0033BB44'

    $orphan = Join-Path $work 'orphan.txt'
    @('0011AA22') | Set-Content $orphan
    try { Read-ScopeFile -Path $orphan | Out-Null; Check 'serial with no station' 'accepted' 'refused' }
    catch { Check 'serial with no station' 'refused' 'refused' }

    Write-Host '-- station folder names --'
    Check 'sanitised'  (Get-StationFolderName -HostName '10.1.2.3:443') '10.1.2.3_443'
    Check 'unchanged'  (Get-StationFolderName -HostName 'pano-a.example.com') 'pano-a.example.com'

    Write-Host '-- PAN-OS answers a failed command with HTTP 200 --'
    $ok = Join-Path $work 'ok.xml'
    Set-Content $ok '<response status="success"><result/></response>' -Encoding UTF8
    Check 'success seen' (Test-PanSuccess -Path $ok) $true
    $err = Join-Path $work 'err.xml'
    Set-Content $err '<response status="error" code="13"><msg><line>not connected</line></msg></response>' -Encoding UTF8
    Check 'error seen'   (Test-PanSuccess -Path $err) $false

    Write-Host '-- state survives a restart --'
    $statePath = Join-Path $work 'state.json'
    $state = @{}
    $state['station|serial|show_config_merged'] = [PSCustomObject]@{
        Status = 'ok'; Path = 'x.xml'; Bytes = 10; CollectedAt = '2026-09-23T00:00:00Z' }
    Save-State -Path $statePath -State $state
    $loaded = Get-State -Path $statePath
    Check 'state reloads'  $loaded['station|serial|show_config_merged'].Status 'ok'
    Check 'bytes reload'   $loaded['station|serial|show_config_merged'].Bytes 10

    Write-Host '-- manifest --'
    Write-Manifest -Root $work -State $loaded -StartedAt (Get-Date) `
        -Stations @([PSCustomObject]@{ HostName = 'panorama-a.example.com'; Serials = @('013201001085') })
    $manifest = Get-Content (Join-Path $work 'manifest.json') -Raw | ConvertFrom-Json
    Check 'schema version' $manifest.schema_version 1
    Check 'station named'  $manifest.stations[0].hostname 'panorama-a.example.com'
    Check 'item recorded'  $manifest.items[0].status 'ok'

    Write-Host '-- archive, and the plain files stay --'
    $archive = New-BundleArchive -Root $work
    Check 'archive written' (Test-Path $archive) $true
    Check 'scope file kept' (Test-Path $scopePath) $true

    Write-Host ''
    if ($script:Failures -eq 0) { Write-Host 'ALL PASS' -ForegroundColor Green }
    else { Write-Host ("{0} FAILURE(S)" -f $script:Failures) -ForegroundColor Red; exit 1 }
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item ($work + '.zip') -Force -ErrorAction SilentlyContinue
}
