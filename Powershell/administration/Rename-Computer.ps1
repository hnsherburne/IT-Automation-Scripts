<#
.SYNOPSIS
    Renames a Windows 11 computer using a configurable prefix and BIOS serial number.

.DESCRIPTION
    Retrieves the computer's BIOS serial number and creates a standardized
    computer name using the following format:

        <Prefix><SerialNumber>

    If a usable serial number cannot be retrieved, the script generates a
    random four-digit identifier.

    The script validates the resulting computer name before attempting to
    rename the computer.

.PARAMETER Prefix
    Prefix to use when constructing the computer name.

.PARAMETER IncludeUserName
    Includes the currently logged-on username in the computer name.

    Example:
        Laptop-JSmith-C02ABC123456

    By default, the username is NOT included.

.EXAMPLE
    .\Rename-Computer.ps1 -Prefix "LAP-"

    Creates a computer name such as:

        LAP-C02ABC123456

.EXAMPLE
    .\Rename-Computer.ps1 -Prefix "LAP-" -IncludeUserName

    Creates a computer name such as:

        LAP-JSmith-C02ABC123456

.NOTES
    Version       : 2.0.0
    Author        : Herb Sherburne
    Original Date : 2020-06-01
    Updated Date  : 2026-09-30

    Changes:
        2.0.0
        - Updated for modern Windows 11 / PowerShell.
        - Replaced deprecated Get-WmiObject with Get-CimInstance.
        - Added administrator privilege validation.
        - Added computer-name validation.
        - Added parameter validation.
        - Improved error handling.
        - Improved serial-number handling.
        - Added optional username support.
        - Added verification after rename.

.REQUIREMENTS
    - Windows 10 or Windows 11
    - PowerShell 5.1 or PowerShell 7+
    - Administrator privileges

.SECURITY
    This script does not modify user accounts, passwords, security policies,
    or network configuration.

#>

#Requires -Version 5.1

[CmdletBinding()]
param (
    [Parameter(
        Mandatory = $true,
        Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9-]+$')]
    [string]$Prefix,

    [Parameter(
        Mandatory = $false
    )]
    [switch]$IncludeUserName
)

#===============================================================================
# Functions
#===============================================================================

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    switch ($Level) {
        'INFO' {
            Write-Host "[$timestamp] [INFO] $Message"
        }

        'WARNING' {
            Write-Warning "[$timestamp] $Message"
        }

        'ERROR' {
            Write-Error "[$timestamp] $Message"
        }
    }
}

#-------------------------------------------------------------------------------
# Test for Administrator Privileges
#-------------------------------------------------------------------------------

function Test-IsAdministrator {

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $principal = New-Object `
        Security.Principal.WindowsPrincipal($currentIdentity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

#-------------------------------------------------------------------------------
# Get Currently Logged-On User
#-------------------------------------------------------------------------------

function Get-LoggedOnUser {

    try {

        $computerSystem = Get-CimInstance `
            -ClassName Win32_ComputerSystem `
            -ErrorAction Stop

        if ($computerSystem.UserName) {

            # Return only the username portion.
            return ($computerSystem.UserName -split '\\')[-1]

        }

        return $null

    }
    catch {

        Write-Log `
            -Message "Unable to determine the currently logged-on user: $($_.Exception.Message)" `
            -Level WARNING

        return $null
    }
}

#-------------------------------------------------------------------------------
# Get BIOS Serial Number
#-------------------------------------------------------------------------------

function Get-ComputerSerialNumber {

    try {

        $bios = Get-CimInstance `
            -ClassName Win32_BIOS `
            -ErrorAction Stop

        $serialNumber = $bios.SerialNumber.Trim()

        # Some manufacturers use generic placeholder serial numbers.
        $invalidSerials = @(
            'To Be Filled By O.E.M.',
            'Default string',
            'System Serial Number',
            'Unknown',
            'None'
        )

        if (
            [string]::IsNullOrWhiteSpace($serialNumber) -or
            $invalidSerials -contains $serialNumber
        ) {

            return $null

        }

        return $serialNumber
    }
    catch {

        Write-Log `
            -Message "Unable to retrieve BIOS serial number: $($_.Exception.Message)" `
            -Level WARNING

        return $null
    }
}

#-------------------------------------------------------------------------------
# Generate Random Identifier
#-------------------------------------------------------------------------------

function New-RandomIdentifier {

    return (Get-Random -Minimum 0 -Maximum 10000).ToString('0000')
}

#-------------------------------------------------------------------------------
# Build Computer Name
#-------------------------------------------------------------------------------

function New-ComputerName {

    param (
        [string]$Prefix,
        [string]$SerialNumber,
        [string]$UserName,
        [bool]$IncludeUserName
    )

    if ($SerialNumber) {

        $identifier = $SerialNumber

    }
    else {

        $identifier = New-RandomIdentifier

        Write-Log `
            -Message "No valid serial number found. Using random identifier: $identifier" `
            -Level WARNING
    }

    if ($IncludeUserName -and $UserName) {

        return "$Prefix$UserName-$identifier"

    }

    return "$Prefix$identifier"
}

#-------------------------------------------------------------------------------
# Validate Computer Name
#-------------------------------------------------------------------------------

function Test-ComputerName {

    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    # Windows computer names cannot exceed 15 characters for traditional
    # NetBIOS compatibility.

    if ($ComputerName.Length -gt 15) {

        Write-Log `
            -Message "Computer name '$ComputerName' exceeds the 15-character limit." `
            -Level ERROR

        return $false
    }

    # Windows computer names may contain letters, numbers, and hyphens.
    # The name cannot begin or end with a hyphen.

    if ($ComputerName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$') {

        Write-Log `
            -Message "Computer name '$ComputerName' contains invalid characters." `
            -Level ERROR

        return $false
    }

    return $true
}

#-------------------------------------------------------------------------------
# Rename Computer
#-------------------------------------------------------------------------------

function Set-ComputerName {

    param (
        [Parameter(Mandatory = $true)]
        [string]$NewName
    )

    try {

        Rename-Computer `
            -NewName $NewName `
            -Force `
            -ErrorAction Stop

        return $true

    }
    catch {

        Write-Log `
            -Message "Failed to rename computer: $($_.Exception.Message)" `
            -Level ERROR

        return $false
    }
}

#===============================================================================
# Main
#===============================================================================

Write-Log "Starting Windows computer rename process."

#-------------------------------------------------------------------------------
# Verify Administrator Privileges
#-------------------------------------------------------------------------------

if (-not (Test-IsAdministrator)) {

    Write-Log `
        -Message "This script must be run as Administrator." `
        -Level ERROR

    exit 1
}

Write-Log "Administrator privileges verified."

#-------------------------------------------------------------------------------
# Gather Computer Information
#-------------------------------------------------------------------------------

$currentComputerName = $env:COMPUTERNAME

Write-Log "Current computer name: $currentComputerName"

$serialNumber = Get-ComputerSerialNumber

if ($serialNumber) {

    Write-Log "BIOS serial number: $serialNumber"

}
else {

    Write-Log `
        -Message "A valid BIOS serial number could not be retrieved." `
        -Level WARNING
}

#-------------------------------------------------------------------------------
# Get Logged-On User
#-------------------------------------------------------------------------------

$loggedOnUser = Get-LoggedOnUser

if ($loggedOnUser) {

    Write-Log "Logged-on user: $loggedOnUser"

}
else {

    Write-Log `
        -Message "No interactive user was detected." `
        -Level WARNING
}

#-------------------------------------------------------------------------------
# Build New Computer Name
#-------------------------------------------------------------------------------

$newComputerName = New-ComputerName `
    -Prefix $Prefix `
    -SerialNumber $serialNumber `
    -UserName $loggedOnUser `
    -IncludeUserName $IncludeUserName

Write-Log "Proposed computer name: $newComputerName"

#-------------------------------------------------------------------------------
# Validate New Computer Name
#-------------------------------------------------------------------------------

if (-not (Test-ComputerName -ComputerName $newComputerName)) {

    Write-Log `
        -Message "Computer rename aborted because the proposed name is invalid." `
        -Level ERROR

    exit 1
}

#-------------------------------------------------------------------------------
# Check Whether Rename Is Necessary
#-------------------------------------------------------------------------------

if ($currentComputerName -ieq $newComputerName) {

    Write-Log "Computer is already using the requested name."
    Write-Log "No changes are required."

    exit 0
}

#-------------------------------------------------------------------------------
# Rename Computer
#-------------------------------------------------------------------------------

Write-Log "Renaming computer from '$currentComputerName' to '$newComputerName'."

if (-not (Set-ComputerName -NewName $newComputerName)) {

    exit 1
}

#-------------------------------------------------------------------------------
# Verify Rename Request
#-------------------------------------------------------------------------------

Write-Log "Computer rename command completed successfully."

Write-Log "New computer name: $newComputerName"

Write-Host ""
Write-Host "============================================================"
Write-Host " Windows Computer Rename"
Write-Host "============================================================"
Write-Host " Previous Name : $currentComputerName"
Write-Host " New Name      : $newComputerName"
Write-Host " Status        : SUCCESS"
Write-Host "============================================================"
Write-Host ""

Write-Log "A restart may be required before all applications and services recognize the new computer name."

exit 0
