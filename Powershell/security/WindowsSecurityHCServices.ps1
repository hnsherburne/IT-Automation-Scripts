<#
.SYNOPSIS
    Collects Windows security feature status and exports the results to JSON.

.DESCRIPTION
    This script performs a read-only security health check of a Windows 10/11
    endpoint. It does NOT make any changes to the system.

    The following security controls are checked:
      - Microsoft Defender Antivirus service
      - Microsoft Defender Antivirus status
      - Microsoft Defender Real-Time Protection
      - Windows Firewall - Domain profile
      - Windows Firewall - Private profile
      - Windows Firewall - Public profile
      - Windows Security Center service
      - BitLocker protection status for the OS drive
      - Microsoft Defender Tamper Protection

    Results are written to a timestamped JSON file.

    Tuned, adjusted, commented and proofed properly with chatgpt

    Can be used as base file for custom dashboard

.NOTES
    Requires:
      - Windows 10/11
      - PowerShell 5.1 or later
      - Administrator privileges recommended
      - Author:  Herb Sheburne and ChatGPT

    This script is intended for endpoint inventory, security auditing,
    and future centralized reporting/SIEM ingestion such as Splunk.

.EXAMPLE
    .\Get-WindowsSecurityStatus.ps1

    Creates a JSON report in:
    C:\ProgramData\WindowsSecurityInventory\
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

$OutputDirectory = 'C:\ProgramData\WindowsSecurityInventory'

# Create output directory if it does not exist
if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

$Timestamp = Get-Date

$TimestampForFile = $Timestamp.ToString('yyyyMMdd-HHmmss')

$OutputFile = Join-Path `
    -Path $OutputDirectory `
    -ChildPath "WindowsSecurityStatus-$TimestampForFile.json"

# ---------------------------------------------------------------------------
# Helper function
# ---------------------------------------------------------------------------

function Get-ServiceStatus {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    try {
        $Service = Get-Service -Name $ServiceName -ErrorAction Stop

        return [PSCustomObject]@{
            Name        = $Service.Name
            DisplayName = $Service.DisplayName
            Status      = $Service.Status.ToString()
            StartType   = $Service.StartType.ToString()
        }
    }
    catch {
        return [PSCustomObject]@{
            Name        = $ServiceName
            DisplayName = $null
            Status      = 'NotFound'
            StartType   = 'Unknown'
        }
    }
}

# ---------------------------------------------------------------------------
# Microsoft Defender Antivirus
# ---------------------------------------------------------------------------

$DefenderStatus = $null

try {
    $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop

    $Defender = [PSCustomObject]@{
        ServiceStatus                 = (Get-ServiceStatus -ServiceName 'WinDefend')
        AntivirusEnabled              = $DefenderStatus.AntivirusEnabled
        AntivirusRunning              = $DefenderStatus.AntivirusRunning
        RealTimeProtectionEnabled     = $DefenderStatus.RealTimeProtectionEnabled
        BehaviorMonitorEnabled        = $DefenderStatus.BehaviorMonitorEnabled
        IoavProtectionEnabled         = $DefenderStatus.IoavProtectionEnabled
        OnAccessProtectionEnabled     = $DefenderStatus.OnAccessProtectionEnabled
        NISEnabled                    = $DefenderStatus.NISEnabled
        NetworkRealtimeInspection     = $DefenderStatus.NISEnabled
        AntivirusSignatureVersion     = $DefenderStatus.AntivirusSignatureVersion
        AntivirusSignatureLastUpdated = $DefenderStatus.AntivirusSignatureLastUpdated
        QuickScanAge                  = $DefenderStatus.QuickScanAge
        FullScanAge                   = $DefenderStatus.FullScanAge
    }
}
catch {
    $Defender = [PSCustomObject]@{
        ServiceStatus             = (Get-ServiceStatus -ServiceName 'WinDefend')
        AntivirusEnabled          = $null
        AntivirusRunning          = $null
        RealTimeProtectionEnabled = $null
        BehaviorMonitorEnabled    = $null
        IoavProtectionEnabled     = $null
        OnAccessProtectionEnabled = $null
        NISEnabled                = $null
        NetworkRealtimeInspection = $null
        AntivirusSignatureVersion = $null
        AntivirusSignatureLastUpdated = $null
        QuickScanAge              = $null
        FullScanAge               = $null
        Error                     = $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# Windows Firewall
# ---------------------------------------------------------------------------

try {
    $FirewallProfiles = Get-NetFirewallProfile -ErrorAction Stop

    $Firewall = foreach ($Profile in $FirewallProfiles) {
        [PSCustomObject]@{
            Name            = $Profile.Name
            Enabled         = $Profile.Enabled
            DefaultInbound  = $Profile.DefaultInboundAction.ToString()
            DefaultOutbound = $Profile.DefaultOutboundAction.ToString()
        }
    }
}
catch {
    $Firewall = [PSCustomObject]@{
        Error = $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# Windows Security Center
# ---------------------------------------------------------------------------

$SecurityCenter = Get-ServiceStatus -ServiceName 'wscsvc'

# ---------------------------------------------------------------------------
# BitLocker
# ---------------------------------------------------------------------------

$BitLocker = $null

try {
    $OSDrive = $env:SystemDrive

    $BitLockerVolume = Get-BitLockerVolume `
        -MountPoint $OSDrive `
        -ErrorAction Stop

    $BitLocker = [PSCustomObject]@{
        MountPoint         = $BitLockerVolume.MountPoint
        VolumeStatus       = $BitLockerVolume.VolumeStatus.ToString()
        ProtectionStatus   = $BitLockerVolume.ProtectionStatus.ToString()
        EncryptionMethod   = $BitLockerVolume.EncryptionMethod.ToString()
        EncryptionPercentage = $BitLockerVolume.EncryptionPercentage
        LockStatus         = $BitLockerVolume.LockStatus.ToString()
    }
}
catch {
    $BitLocker = [PSCustomObject]@{
        MountPoint           = $env:SystemDrive
        VolumeStatus         = $null
        ProtectionStatus     = $null
        EncryptionMethod     = $null
        EncryptionPercentage = $null
        LockStatus            = $null
        Error                 = $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# Microsoft Defender Tamper Protection
# ---------------------------------------------------------------------------

$TamperProtection = $null

try {
    $TamperProtection = [PSCustomObject]@{
        Status = $DefenderStatus.TamperProtection.ToString()
    }
}
catch {
    $TamperProtection = [PSCustomObject]@{
        Status = 'Unknown'
        Error  = $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# Calculate basic overall status
# ---------------------------------------------------------------------------

$FirewallHealthy = $false

try {
    $FirewallHealthy = @(
        $Firewall | Where-Object {
            $_.Enabled -eq $true
        }
    ).Count -eq 3
}
catch {
    $FirewallHealthy = $false
}

$DefenderHealthy = $false

try {
    $DefenderHealthy = (
        $Defender.AntivirusEnabled -eq $true -and
        $Defender.AntivirusRunning -eq $true -and
        $Defender.RealTimeProtectionEnabled -eq $true
    )
}
catch {
    $DefenderHealthy = $false
}

$BitLockerHealthy = $false

try {
    $BitLockerHealthy = (
        $BitLocker.ProtectionStatus -eq 'On'
    )
}
catch {
    $BitLockerHealthy = $false
}

$SecurityCenterHealthy = (
    $SecurityCenter.Status -eq 'Running'
)

$OverallStatus = if (
    $DefenderHealthy -and
    $FirewallHealthy -and
    $SecurityCenterHealthy -and
    $BitLockerHealthy
) {
    'Healthy'
}
else {
    'Review'
}

# ---------------------------------------------------------------------------
# Build final report
# ---------------------------------------------------------------------------

$Report = [PSCustomObject]@{
    ReportType    = 'WindowsSecurityHealth'
    SchemaVersion = '1.0'
    ComputerName  = $env:COMPUTERNAME
    Timestamp     = $Timestamp.ToUniversalTime().ToString('o')
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()

    OverallStatus = $OverallStatus

    Defender = $Defender

    Firewall = $Firewall

    SecurityCenter = $SecurityCenter

    BitLocker = $BitLocker

    TamperProtection = $TamperProtection
}

# ---------------------------------------------------------------------------
# Export JSON
# ---------------------------------------------------------------------------

$Report |
    ConvertTo-Json -Depth 10 |
    Set-Content -Path $OutputFile -Encoding UTF8

# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host 'Windows Security Health Check Complete' -ForegroundColor Green
Write-Host '---------------------------------------'
Write-Host "Computer      : $env:COMPUTERNAME"
Write-Host "Overall Status: $OverallStatus"
Write-Host "Output File   : $OutputFile"
Write-Host ''

Write-Host 'Defender:' -ForegroundColor Cyan
Write-Host "  Antivirus Enabled       : $($Defender.AntivirusEnabled)"
Write-Host "  Antivirus Running       : $($Defender.AntivirusRunning)"
Write-Host "  Real-Time Protection    : $($Defender.RealTimeProtectionEnabled)"

Write-Host ''
Write-Host 'Firewall:' -ForegroundColor Cyan

foreach ($Profile in $Firewall) {
    if ($Profile.Name) {
        Write-Host "  $($Profile.Name) : $($Profile.Enabled)"
    }
}

Write-Host ''
Write-Host 'Security Center:' -ForegroundColor Cyan
Write-Host "  Service Status: $($SecurityCenter.Status)"

Write-Host ''
Write-Host 'BitLocker:' -ForegroundColor Cyan
Write-Host "  Protection Status: $($BitLocker.ProtectionStatus)"

Write-Host ''
Write-Host 'Tamper Protection:' -ForegroundColor Cyan
Write-Host "  Status: $($TamperProtection.Status)"

Write-Host ''
Write-Host "JSON saved to:"
Write-Host $OutputFile
Write-Host ''
