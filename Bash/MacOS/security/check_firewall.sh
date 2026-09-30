#!/usr/bin/env bash
#
#===============================================================================
# Script Name    : check_firewall.sh
#
# Description    :
#   Checks the macOS Application Firewall status.
#
#   If the firewall is disabled, the script displays a native macOS dialog
#   informing the user that IT requires the firewall to be enabled.
#
#   After the user acknowledges the message, the script enables the macOS
#   Application Firewall and verifies the resulting configuration.
#
# Author         : Herb Sherburne
# Created        : 2023-07-22
# Version        : 1.0.0
#
# Requirements   :
#   - macOS
#   - Administrator privileges
#   - socketfilterfw
#   - osascript
#
# Usage          :
#   sudo ./check_firewall.sh
#
# Deployment     :
#   Can be run locally or deployed through an MDM solution.
#
# Security       :
#   - The script does not modify individual application firewall rules.
#   - The script only enables the macOS Application Firewall when disabled.
#   - No passwords, keys, or other credentials are collected.
#
#===============================================================================

set -euo pipefail

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------

FIREWALL="/usr/libexec/ApplicationFirewall/socketfilterfw"

DIALOG_TITLE="IT Security Requirement"

DIALOG_MESSAGE="The macOS firewall is currently disabled.

IT requires the firewall to be enabled to help protect this Mac from
unauthorized network connections.

The firewall will now be enabled."

#------------------------------------------------------------------------------
# Logging Functions
#------------------------------------------------------------------------------

log() {
    echo "[INFO] $1"
}

error() {
    echo "[ERROR] $1" >&2
}

#------------------------------------------------------------------------------
# Verify macOS
#------------------------------------------------------------------------------

if [[ "$(uname -s)" != "Darwin" ]]; then
    error "This script is intended for macOS only."
    exit 1
fi

#------------------------------------------------------------------------------
# Verify administrator privileges
#------------------------------------------------------------------------------

if [[ "$EUID" -ne 0 ]]; then
    error "Administrator privileges are required."
    echo "Usage: sudo $0"
    exit 1
fi

#------------------------------------------------------------------------------
# Verify required commands
#------------------------------------------------------------------------------

if [[ ! -x "$FIREWALL" ]]; then
    error "macOS Application Firewall utility was not found:"
    error "$FIREWALL"
    exit 1
fi

if ! command -v osascript >/dev/null 2>&1; then
    error "osascript was not found."
    exit 1
fi

#------------------------------------------------------------------------------
# Determine current logged-in user
#------------------------------------------------------------------------------

CONSOLE_USER="$(stat -f '%Su' /dev/console)"

if [[ -z "$CONSOLE_USER" ||
      "$CONSOLE_USER" == "root" ||
      "$CONSOLE_USER" == "loginwindow" ]]; then

    log "No active graphical user session detected."

    ACTIVE_USER=false

else

    ACTIVE_USER=true
    USER_ID="$(id -u "$CONSOLE_USER")"

    log "Logged-in user: $CONSOLE_USER"
    log "User ID: $USER_ID"

fi

#------------------------------------------------------------------------------
# Check firewall status
#------------------------------------------------------------------------------

log "Checking macOS Application Firewall status..."

FIREWALL_STATUS="$("$FIREWALL" --getglobalstate 2>&1)"

log "Firewall status: $FIREWALL_STATUS"

#------------------------------------------------------------------------------
# Determine whether firewall is enabled
#------------------------------------------------------------------------------

if echo "$FIREWALL_STATUS" | grep -q "State = 1"; then

    log "macOS Application Firewall is already enabled."

    echo
    echo "============================================================"
    echo " Firewall Compliance Check"
    echo "============================================================"
    echo " Status : ENABLED"
    echo " Action : No changes required"
    echo "============================================================"
    echo

    exit 0

fi

#------------------------------------------------------------------------------
# Firewall is disabled
#------------------------------------------------------------------------------

log "macOS Application Firewall is disabled."

#------------------------------------------------------------------------------
# Display user notification
#------------------------------------------------------------------------------

if [[ "$ACTIVE_USER" == true ]]; then

    log "Displaying firewall security notification."

    launchctl asuser "$USER_ID" \
        osascript \
        -e "display dialog \"$DIALOG_MESSAGE\" with title \"$DIALOG_TITLE\" buttons {\"Enable Firewall\"} default button \"Enable Firewall\" with icon caution" \
        >/dev/null

else

    log "No graphical user session is available."
    log "Continuing with firewall remediation."

fi

#------------------------------------------------------------------------------
# Enable Application Firewall
#------------------------------------------------------------------------------

log "Enabling macOS Application Firewall..."

if "$FIREWALL" --setglobalstate on; then

    log "Firewall enable command completed successfully."

else

    error "Failed to enable the macOS Application Firewall."
    exit 1

fi

#------------------------------------------------------------------------------
# Verify firewall status
#------------------------------------------------------------------------------

log "Verifying firewall status..."

FINAL_STATUS="$("$FIREWALL" --getglobalstate 2>&1)"

log "Final firewall status: $FINAL_STATUS"

#------------------------------------------------------------------------------
# Confirm successful remediation
#------------------------------------------------------------------------------

if echo "$FINAL_STATUS" | grep -q "State = 1"; then

    echo
    echo "============================================================"
    echo " Firewall Compliance Check"
    echo "============================================================"
    echo " Status : ENABLED"
    echo " Action : Firewall was enabled"
    echo "============================================================"
    echo

    log "Firewall compliance remediation completed successfully."

else

    echo
    echo "============================================================"
    echo " Firewall Compliance Check"
    echo "============================================================"
    echo " Status : FAILED"
    echo " Action : Firewall could not be verified as enabled"
    echo "============================================================"
    echo

    error "Firewall verification failed."
    exit 1

fi

exit 0
