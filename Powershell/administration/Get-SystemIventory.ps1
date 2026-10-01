
#Requires -Version 5.1
<#
.SYNOPSIS
    Collects Windows system inventory information and stores it locally.

.DESCRIPTION
    Collects device identity, operating system, hardware, storage,
    network configuration, and selected security status information.

    Results are saved as timestamped JSON files, with an execution log,
    in a directory restricted to SYSTEM and local Administrators.

    This script is read-only. It does not remediate or change security
    settings.

.OUTPUTS
    C:\ProgramData\IT-Management\Inventory\SystemInventory_<timestamp>.json
    C:\ProgramData\IT-Management\Inventory\InventoryLog.txt

.NOTES
    Version: 1.1.0
    Author: Herb Sherburne
    Minimum PowerShell: 5.1
    Intended for Windows 10/11 and Microsoft Intune deployment.
    Assisting with a friend and comments and reformat with chatgpt
    Results could be rolled up to a central repository for additional reporting

    Test in a controlled environment before production deployment.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

$InventoryPath = Join-Path $env:ProgramData 'IT-Management\Inventory'
$LogPath = Join-Path $InventoryPath 'InventoryLog.txt'
$TimeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$JsonPath = Join-Path $InventoryPath "SystemInventory_$TimeStamp.json"

$ScriptVersion = '1.0.0'

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

function Write-InventoryLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $LogTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "[$LogTime] [$Level] $Message"

    Add-Content -LiteralPath $LogPath -Value $LogEntry `
        -Encoding UTF8 -ErrorAction Stop
}

# ---------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------

function Initialize-InventoryDirectory {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -LiteralPath $InventoryPath)) {
        New-Item -Path $InventoryPath -ItemType Directory -Force |
            Out-Null
    }

    # Disable inherited permissions and explicitly grant access only
    # to SYSTEM and the local Administrators group.
    $DirectoryAcl = New-Object System.Security.AccessControl.DirectorySecurity
    $DirectoryAcl.SetAccessRuleProtection($true, $false)

    $Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                   [System.Security.AccessControl.InheritanceFlags]::ObjectInherit

    $Propagation = [System.Security.AccessControl.PropagationFlags]::None
    $Allow = [System.Security.AccessControl.AccessControlType]::Allow
    $FullControl = [System.Security.AccessControl.FileSystemRights]::FullControl

    $SystemSid = New-Object System.Security.Principal.SecurityIdentifier(
        'S-1-5-18'
    )
    $AdministratorsSid = New-Object System.Security.Principal.SecurityIdentifier(
        'S-1-5-32-544'
    )

    foreach ($Sid in @($SystemSid, $AdministratorsSid)) {
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Sid, $FullControl, $Inheritance, $Propagation, $Allow
        )
        $DirectoryAcl.AddAccessRule($Rule)
    }

    Set-Acl -LiteralPath $InventoryPath -AclObject $DirectoryAcl `
        -ErrorAction Stop
}

# ---------------------------------------------------------------------
# Collection helpers
# ---------------------------------------------------------------------

function Get-CollectionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    try {
        return (& $Action)
    }
    catch {
        Write-InventoryLog "$Name collection failed: $($_.Exception.Message)" 'WARN'

        return [PSCustomObject]@{
            CollectionStatus = 'Failed'
            Error            = $_.Exception.Message
        }
    }
}

function Test-PendingReboot {
    [CmdletBinding()]
    param()

    $Indicators = @()

    $RegistryChecks = @(
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
            Name = 'ComponentBasedServicing'
        },
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
            Name = 'WindowsUpdate'
        }
    )

    foreach ($Check in $RegistryChecks) {
        if (Test-Path -LiteralPath $Check.Path) {
            $Indicators += $Check.Name
        }
    }

    try {
        $SessionManager = Get-ItemProperty `
            -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
            -Name PendingFileRenameOperations `
            -ErrorAction SilentlyContinue

        if ($null -ne $SessionManager.PendingFileRenameOperations) {
            $Indicators += 'PendingFileRenameOperations'
        }
    }
    catch {
        # This indicator is optional and should not stop inventory.
    }

    [PSCustomObject]@{
        PendingReboot = ($Indicators.Count -gt 0)
        Indicators    = @($Indicators)
        Note          = 'Common indicators only; not a definitive reboot determination.'
    }
}

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

try {
    # Require an elevated session. Intune can run this as SYSTEM.
    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal(
        $CurrentIdentity
    )

    $IsElevated = $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    if (-not $IsElevated) {
        throw 'Run this script from an elevated PowerShell session or deploy it through Intune using SYSTEM context.'
    }

    # Secure the output directory before writing inventory data.
    if (-not (Test-Path -LiteralPath $InventoryPath)) {
        New-Item -Path $InventoryPath -ItemType Directory -Force |
            Out-Null
    }

    Initialize-InventoryDirectory

    Write-InventoryLog "Starting inventory collection. Version: $ScriptVersion"

    # Device identity
    $ComputerSystem = Get-CollectionResult -Name 'Computer system' -Action {
        Get-CimInstance -ClassName Win32_ComputerSystem
    }

    $ComputerProduct = Get-CollectionResult -Name 'Computer product' -Action {
        Get-CimInstance -ClassName Win32_ComputerSystemProduct
    }

    $Bios = Get-CollectionResult -Name 'BIOS' -Action {
        Get-CimInstance -ClassName Win32_BIOS
    }

    # Operating system
    $OperatingSystem = Get-CollectionResult -Name 'Operating system' -Action {
        Get-CimInstance -ClassName Win32_OperatingSystem
    }

    # Processor
    $Processor = Get-CollectionResult -Name 'Processor' -Action {
        Get-CimInstance -ClassName Win32_Processor |
            Select-Object -First 1
    }

    # Physical memory
    $PhysicalMemory = Get-CollectionResult -Name 'Physical memory' -Action {
        $Modules = @(Get-CimInstance -ClassName Win32_PhysicalMemory)
        $TotalBytes = ($Modules | Measure-Object -Property Capacity -Sum).Sum

        [PSCustomObject]@{
            TotalBytes = $TotalBytes
            TotalGB    = if ($null -ne $TotalBytes) {
                [math]::Round($TotalBytes / 1GB, 2)
            } else {
                $null
            }
            Modules    = @(
                $Modules | Select-Object Manufacturer, PartNumber,
                    @{Name = 'CapacityGB'; Expression = {
                        [math]::Round($_.Capacity / 1GB, 2)
                    }},
                    Speed
            )
        }
    }

    # Local fixed disks
    $Disks = Get-CollectionResult -Name 'Disk storage' -Action {
        @(
            Get-CimInstance -ClassName Win32_LogicalDisk `
                -Filter 'DriveType = 3' |
                Select-Object DeviceID, VolumeName, FileSystem,
                    @{Name = 'SizeGB'; Expression = {
                        if ($null -ne $_.Size) {
                            [math]::Round($_.Size / 1GB, 2)
                        } else { $null }
                    }},
                    @{Name = 'FreeSpaceGB'; Expression = {
                        if ($null -ne $_.FreeSpace) {
                            [math]::Round($_.FreeSpace / 1GB, 2)
                        } else { $null }
                    }},
                    @{Name = 'FreeSpacePercent'; Expression = {
                        if ($_.Size -gt 0) {
                            [math]::Round(($_.FreeSpace / $_.Size) * 100, 2)
                        } else { $null }
                    }}
        )
    }

    # BitLocker
    $BitLocker = Get-CollectionResult -Name 'BitLocker' -Action {
        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            @(
                Get-BitLockerVolume | Select-Object MountPoint,
                    VolumeType, VolumeStatus, ProtectionStatus,
                    EncryptionPercentage, EncryptionMethod
            )
        }
        else {
            [PSCustomObject]@{
                CollectionStatus = 'Unavailable'
                Note = 'Get-BitLockerVolume is not available on this system.'
            }
        }
    }

    # Windows Firewall
    $Firewall = Get-CollectionResult -Name 'Windows Firewall' -Action {
        @(
            Get-NetFirewallProfile | Select-Object Name, Enabled,
                DefaultInboundAction, DefaultOutboundAction,
                NotifyOnListen
        )
    }

    # Microsoft Defender Antivirus
    $Defender = Get-CollectionResult -Name 'Microsoft Defender' -Action {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $Status = Get-MpComputerStatus

            [PSCustomObject]@{
                AMServiceEnabled          = $Status.AMServiceEnabled
                AntivirusEnabled          = $Status.AntivirusEnabled
                AntispywareEnabled        = $Status.AntispywareEnabled
                RealTimeProtectionEnabled = $Status.RealTimeProtectionEnabled
                AntivirusSignatureVersion = $Status.AntivirusSignatureVersion
                AntivirusSignatureAge     = $Status.AntivirusSignatureAge
                QuickScanAge              = $Status.QuickScanAge
                FullScanAge               = $Status.FullScanAge
            }
        }
        else {
            [PSCustomObject]@{
                CollectionStatus = 'Unavailable'
                Note = 'Defender status cmdlet is not available.'
            }
        }
    }

    # Network adapters and IP configuration
    $Network = Get-CollectionResult -Name 'Network configuration' -Action {
        @(
            Get-NetIPConfiguration -ErrorAction Stop |
                Select-Object InterfaceAlias, InterfaceIndex,
                    @{Name = 'IPv4Address'; Expression = {
                        @($_.IPv4Address | ForEach-Object { $_.IPAddress })
                    }},
                    @{Name = 'IPv6Address'; Expression = {
                        @($_.IPv6Address | ForEach-Object { $_.IPAddress })
                    }},
                    @{Name = 'IPv4DefaultGateway'; Expression = {
                        @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
                    }},
                    @{Name = 'DNSServer'; Expression = {
                        @($_.DNSServer.ServerAddresses)
                    }}
        )
    }

    # Reboot indicators
    $RebootStatus = Get-CollectionResult -Name 'Pending reboot' -Action {
        Test-PendingReboot
    }

    # Assemble inventory
    $Inventory = [PSCustomObject]@{
        SchemaVersion = '1.0'
        Script = [PSCustomObject]@{
            Name    = 'Get-SystemInventory.ps1'
            Version = $ScriptVersion
        }
        Collection = [PSCustomObject]@{
            Timestamp       = (Get-Date).ToString('o')
            ComputerName    = $env:COMPUTERNAME
            ExecutionIdentity = $CurrentIdentity.Name
        }
        Device = [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Manufacturer = $ComputerSystem.Manufacturer
            Model        = $ComputerSystem.Model
            Domain       = $ComputerSystem.Domain
            DomainRole   = $ComputerSystem.DomainRole
            SerialNumber = $Bios.SerialNumber
            UUID         = $ComputerProduct.UUID
        }
        OperatingSystem = [PSCustomObject]@{
            Caption        = $OperatingSystem.Caption
            Version        = $OperatingSystem.Version
            BuildNumber    = $OperatingSystem.BuildNumber
            Architecture   = $OperatingSystem.OSArchitecture
            InstallDate    = $OperatingSystem.InstallDate
            LastBootUpTime = $OperatingSystem.LastBootUpTime
        }
        Hardware = [PSCustomObject]@{
            Processor = [PSCustomObject]@{
                Name                 = $Processor.Name
                Manufacturer         = $Processor.Manufacturer
                NumberOfCores        = $Processor.NumberOfCores
                NumberOfLogicalCores = $Processor.NumberOfLogicalProcessors
                MaxClockSpeedMHz     = $Processor.MaxClockSpeed
            }
            Memory = $PhysicalMemory
        }
        Storage       = $Disks
        BitLocker     = $BitLocker
        Firewall      = $Firewall
        Defender      = $Defender
        Network       = $Network
        RebootStatus  = $RebootStatus
    }

    # Convert to JSON and save.
    $Json = $Inventory | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $JsonPath -Value $Json `
        -Encoding UTF8 -Force -ErrorAction Stop

    # Reapply protected ACLs to the output directory to ensure that
    # newly created files inherit the intended directory permissions.
    Initialize-InventoryDirectory

    Write-InventoryLog "Inventory collection completed successfully."
    Write-InventoryLog "JSON report: $JsonPath"

    Write-Output 'System inventory collection completed.'
    Write-Output "Computer: $env:COMPUTERNAME"
    Write-Output "JSON report: $JsonPath"
    Write-Output "Execution log: $LogPath"

    exit 0
}
catch {
    $FailureMessage = $_.Exception.Message

    # Best-effort error logging. The directory may not yet be writable.
    try {
        if (Test-Path -LiteralPath $InventoryPath) {
            Write-InventoryLog "Inventory collection failed: $FailureMessage" 'ERROR'
        }
    }
    catch {
        # Do not mask the original error if logging also fails.
    }

    Write-Error "System inventory collection failed: $FailureMessage"
    exit 1
}
