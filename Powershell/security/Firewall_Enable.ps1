#Requires -Version 5.1

<#
.SYNOPSIS
    Checks and enforces Windows Firewall status.

.DESCRIPTION
    Checks whether the Windows Defender Firewall is enabled for all
    network profiles.

    If the firewall is enabled, the script logs the status and exits.

    If the firewall is disabled for one or more profiles, the script
    displays a notification to the logged-on user explaining that the
    firewall is required by IT. The script then enables the firewall
    for all network profiles and verifies the result.

    Designed for Windows 10/11 endpoint administration and MDM workflows.

.OUTPUTS
    Log file:
        C:\ProgramData\IT-Management\Logs\WindowsFirewall.log

.NOTES
    Version:        2.0
    Author:         Herb Sherburne
    Updated:        2026

    Security:
        - Requires administrator privileges.
        - Uses native Windows Defender Firewall PowerShell cmdlets.
        - Does not disable existing firewall rules.
        - Does not modify individual firewall rules.
        - Only enables the firewall when one or more profiles are disabled.

.EXAMPLE
    .\Check-WindowsFirewall.ps1
#>

[CmdletBinding()]
param ()

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

$LogDirectory = "C:\ProgramData\IT-Management\Logs"
$LogFile = Join-Path $LogDirectory "WindowsFirewall.log"

# ---------------------------------------------------------
# Functions
# ---------------------------------------------------------

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Determines whether PowerShell is running with administrator privileges.
    #>

    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object Security.Principal.WindowsPrincipal(
        $CurrentIdentity
    )

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped message to the firewall log.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $LogEntry = "[$Timestamp] [$Level] $Message"

    Add-Content -Path $LogFile -Value $LogEntry
}

function Show-FirewallNotification {
    <#
    .SYNOPSIS
        Displays a notification to the currently logged-on user.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    try {

        $LoggedOnUser = Get-CimInstance Win32_ComputerSystem |
            Select-Object -ExpandProperty UserName

        if ([string]::IsNullOrWhiteSpace($LoggedOnUser)) {
            Write-Log `
                -Message "No interactive user detected. Firewall will be remediated without notification." `
                -Level "WARNING"

            return
        }

        $Username = $LoggedOnUser.Split("\")[-1]

        # Find the user's interactive session.
        $Process = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" |
            Where-Object {
                try {
                    $Owner = Invoke-CimMethod `
                        -InputObject $_ `
                        -MethodName GetOwner `
                        -ErrorAction Stop

                    $Owner.User -eq $Username
                }
                catch {
                    $false
                }
            } |
            Select-Object -First 1

        if (-not $Process) {
            Write-Log `
                -Message "Unable to locate interactive user session for '$LoggedOnUser'." `
                -Level "WARNING"

            return
        }

        $SessionId = $Process.SessionId

        $MessageTitle = "IT Security Requirement"

        $Command = @"
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show(
    '$Message',
    '$MessageTitle',
    'OK',
    'Warning'
)
"@

        $EncodedCommand = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes($Command)
        )

        Start-Process `
            -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -EncodedCommand $EncodedCommand" `
            -WindowStyle Hidden `
            -WorkingDirectory "C:\" `
            -Wait:$false

        Write-Log `
            -Message "Firewall notification displayed to user '$LoggedOnUser'."
    }
    catch {
        Write-Log `
            -Message "Unable to display firewall notification. $($_.Exception.Message)" `
            -Level "WARNING"
    }
}

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

try {

    # -----------------------------------------------------
    # Verify administrator privileges
    # -----------------------------------------------------

    if (-not (Test-IsAdministrator)) {
        throw "This script must be run with administrator privileges."
    }

    # -----------------------------------------------------
    # Create log directory
    # -----------------------------------------------------

    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item `
            -Path $LogDirectory `
            -ItemType Directory `
            -Force `
            -ErrorAction Stop |
            Out-Null
    }

    Write-Log "============================================="
    Write-Log "Windows Firewall compliance check started."
    Write-Log "Computer: $env:COMPUTERNAME"

    # -----------------------------------------------------
    # Check Windows Firewall profiles
    # -----------------------------------------------------

    $FirewallProfiles = Get-NetFirewallProfile -ErrorAction Stop

    foreach ($Profile in $FirewallProfiles) {

        Write-Log `
            "Firewall profile '$($Profile.Name)' status: Enabled=$($Profile.Enabled)"
    }

    $DisabledProfiles = $FirewallProfiles |
        Where-Object { $_.Enabled -eq $false }

    # -----------------------------------------------------
    # Firewall is enabled
    # -----------------------------------------------------

    if (-not $DisabledProfiles) {

        Write-Log "Windows Firewall is ENABLED for all network profiles."

        Write-Log "Firewall compliance check completed."

        exit 0
    }

    # -----------------------------------------------------
    # Firewall is disabled
    # -----------------------------------------------------

    $DisabledProfileNames = $DisabledProfiles.Name -join ", "

    Write-Log `
        "Windows Firewall is DISABLED for profile(s): $DisabledProfileNames" `
        -Level "WARNING"

    # -----------------------------------------------------
    # Notify user
    # -----------------------------------------------------

    $NotificationMessage = @"
The Windows Firewall is currently disabled.

IT requires the Windows Firewall to be enabled to help protect this computer from unauthorized network connections.

The firewall will now be enabled.

Please click OK to continue.
"@

    Show-FirewallNotification -Message $NotificationMessage

    # -----------------------------------------------------
    # Enable Windows Firewall
    # -----------------------------------------------------

    Write-Log "Enabling Windows Firewall for all network profiles."

    Set-NetFirewallProfile `
        -Profile Domain,Private,Public `
        -Enabled True `
        -ErrorAction Stop

    Write-Log "Windows Firewall enable command completed successfully."

    # -----------------------------------------------------
    # Verify remediation
    # -----------------------------------------------------

    $FirewallProfilesAfter = Get-NetFirewallProfile -ErrorAction Stop

    $StillDisabled = $FirewallProfilesAfter |
        Where-Object { $_.Enabled -eq $false }

    if ($StillDisabled) {

        $FailedProfiles = $StillDisabled.Name -join ", "

        Write-Log `
            "Firewall remediation FAILED. Disabled profile(s): $FailedProfiles" `
            -Level "ERROR"

        throw "Windows Firewall remains disabled for: $FailedProfiles"
    }

    # -----------------------------------------------------
    # Successful remediation
    # -----------------------------------------------------

    Write-Log "Windows Firewall is now ENABLED for all network profiles."
    Write-Log "Firewall remediation completed successfully."
    Write-Log "============================================="

    exit 0
}
catch {

    # Make sure the log directory exists before attempting to log.
    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item `
            -Path $LogDirectory `
            -ItemType Directory `
            -Force `
            -ErrorAction SilentlyContinue |
            Out-Null
    }

    Write-Log `
        "Firewall compliance check failed: $($_.Exception.Message)" `
        -Level "ERROR"

    Write-Log "============================================="

    exit 1
}
