#Requires -Version 5.1

<#
.SYNOPSIS
    Creates and configures a local administrator account on Windows.

.DESCRIPTION
    Creates a local user account if it does not already exist and adds the
    account to the local Administrators group.

    If the account already exists, the script does not overwrite the existing
    password. It verifies that the account is a member of the local
    Administrators group and adds it if necessary.

    The password is supplied as a SecureString and is never stored directly
    in the script.

    This script is intended for Windows 10/11 endpoint administration and
    MDM/management workflows.

.PARAMETER Username
    The name of the local administrator account to create.

.PARAMETER Password
    Secure password for the local administrator account.

.PARAMETER FullName
    Optional display name for the local account.

.EXAMPLE
    $Password = Read-Host "Enter local admin password" -AsSecureString
    .\Create-Local-Admin.ps1 -Username "miadmin" -Password $Password

.EXAMPLE
    .\Create-Local-Admin.ps1 `
        -Username "miadmin" `
        -Password (Read-Host "Password" -AsSecureString) `
        -FullName "Managed Local Administrator"

.NOTES
    Version:        2.0
    Author:         Herb Sherburne
    Updated:       2026
    Purpose:
        Modernized Windows 10 script for Windows 11.

    Security:
        - Do not hard-code passwords in scripts.
        - Do not commit passwords to source control.
        - PasswordNeverExpires is intentionally not enabled.
        - UserMayNotChangePassword is intentionally not enabled.
        - For enterprise environments, Windows LAPS should generally be
          considered for managing local administrator passwords.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 20)]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [securestring]$Password,

    [Parameter(Mandatory = $false)]
    [ValidateLength(0, 256)]
    [string]$FullName = ""
)

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

$AdminGroup = "Administrators"

# ---------------------------------------------------------
# Functions
# ---------------------------------------------------------

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Determines whether the script is running with administrator privileges.
    #>

    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object Security.Principal.WindowsPrincipal(
        $CurrentIdentity
    )

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Test-LocalUserExists {
    <#
    .SYNOPSIS
        Checks whether a local user account exists.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $null = Get-LocalUser -Name $Name -ErrorAction Stop
        return $true
    }
    catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
        return $false
    }
    catch {
        throw "Unable to determine whether local user '$Name' exists. $($_.Exception.Message)"
    }
}

function Test-LocalAdminMembership {
    <#
    .SYNOPSIS
        Determines whether the specified user is a member of the
        local Administrators group.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $Members = Get-LocalGroupMember `
            -Group $AdminGroup `
            -ErrorAction Stop

        return ($Members.Name -contains "$env:COMPUTERNAME\$Name")
    }
    catch {
        throw "Unable to check local Administrators membership. $($_.Exception.Message)"
    }
}

function New-LocalAdmin {
    <#
    .SYNOPSIS
        Creates the local user and adds it to Administrators.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [securestring]$SecurePassword,

        [Parameter(Mandatory = $false)]
        [string]$AccountFullName
    )

    try {
        $NewUserParams = @{
            Name              = $Name
            Password          = $SecurePassword
            Description       = "Managed local administrator account"
            AccountNeverExpires = $true
            ErrorAction       = "Stop"
        }

        if (-not [string]::IsNullOrWhiteSpace($AccountFullName)) {
            $NewUserParams["FullName"] = $AccountFullName
        }

        New-LocalUser @NewUserParams

        Write-Output "Local user '$Name' created successfully."

        Add-LocalGroupMember `
            -Group $AdminGroup `
            -Member $Name `
            -ErrorAction Stop

        Write-Output "User '$Name' added to the local '$AdminGroup' group."
    }
    catch {
        throw "Failed to create or configure local administrator '$Name'. $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

try {

    # Verify administrator privileges.
    if (-not (Test-IsAdministrator)) {
        throw "This script must be run with administrator privileges."
    }

    # Verify LocalAccounts cmdlets are available.
    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        throw "The LocalAccounts PowerShell module is not available on this system."
    }

    Write-Output "Checking local administrator account '$Username'..."

    if (Test-LocalUserExists -Name $Username) {

        Write-Output "User '$Username' already exists."

        # Verify Administrators membership.
        if (Test-LocalAdminMembership -Name $Username) {

            Write-Output "User '$Username' is already a member of '$AdminGroup'."
            Write-Output "No changes are required."

        }
        else {

            Write-Output "User '$Username' is not a member of '$AdminGroup'."
            Write-Output "Adding user to '$AdminGroup'..."

            Add-LocalGroupMember `
                -Group $AdminGroup `
                -Member $Username `
                -ErrorAction Stop

            Write-Output "User '$Username' successfully added to '$AdminGroup'."
        }
    }
    else {

        Write-Output "User '$Username' does not exist."
        Write-Output "Creating local administrator account..."

        New-LocalAdmin `
            -Name $Username `
            -SecurePassword $Password `
            -AccountFullName $FullName

    }

    # -----------------------------------------------------
    # Final verification
    # -----------------------------------------------------

    $User = Get-LocalUser -Name $Username -ErrorAction Stop

    if (-not (Test-LocalAdminMembership -Name $Username)) {
        throw "Verification failed: '$Username' is not a member of '$AdminGroup'."
    }

    Write-Output ""
    Write-Output "============================================="
    Write-Output " Local Administrator Configuration Complete"
    Write-Output "============================================="
    Write-Output "Username : $($User.Name)"
    Write-Output "Enabled  : $($User.Enabled)"
    Write-Output "Admin    : Yes"
    Write-Output "============================================="

}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
