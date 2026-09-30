#!/usr/bin/env bash
#
#===============================================================================
# Script Name    : check_filevault.sh
#
# Description    :
#   Checks whether FileVault disk encryption is enabled on macOS.
#
#   If FileVault is not enabled, the script displays a native macOS dialog
#   informing the user that IT requires FileVault to be enabled.
#
#   The script does NOT enable FileVault automatically.
#
# Author         : Herb Sherburne
# Created        : 2024-03-12
# Version        : 1.1.0
#
# Requirements   :
#   - macOS
#   - fdesetup
#   - osascript
#   - An active graphical user session for the dialog
#
# Usage          :
#   ./check_filevault.sh
#
# Deployment     :
#   This script can be run locally or deployed through an MDM solution.
#
# Security       :
#   - Does not collect passwords.
#   - Does not collect or display FileVault recovery keys.
#   - Does not enable FileVault automatically.
#   - Does not write sensitive information to disk.
#
#===============================================================================

set -euo pipefail

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------

SCRIPT_NAME="$(basename "$0")"

DIALOG_TITLE="IT Security Requirement"

DIALOG_MESSAGE="FileVault is not enabled on this Mac.

IT requires FileVault to be enabled to protect company data.

Please contact IT for assistance enabling FileVault."

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
# Verify required commands
#------------------------------------------------------------------------------

if ! command -v fdesetup >/dev/null 2>&1; then
    error "fdesetup was not found."
    exit 1
fi

if ! command -v osascript >/dev/null 2>&1; then
    error "osascript was not found."
    exit 1
fi

#------------------------------------------------------------------------------
# Check FileVault status
#------------------------------------------------------------------------------

log "Checking FileVault status..."

FILEVAULT_STATUS="$(fdesetup status 2>&1 || true)"

log "FileVault status: $FILEVAULT_STATUS"

#------------------------------------------------------------------------------
# Determine FileVault state
#------------------------------------------------------------------------------

if echo "$FILEVAULT_STATUS" | grep -qi "FileVault is On"; then

    log "FileVault is enabled."
    log "No user action is required."

    exit 0

fi

#------------------------------------------------------------------------------
# FileVault is not enabled
#------------------------------------------------------------------------------

log "FileVault is not enabled."
log "A security reminder will be displayed to the logged-in user."

#------------------------------------------------------------------------------
# Determine the currently logged-in graphical user
#------------------------------------------------------------------------------

CONSOLE_USER="$(stat -f '%Su' /dev/console)"

if [[ -z "$CONSOLE_USER" || "$CONSOLE_USER" == "root" || "$CONSOLE_USER" == "loginwindow" ]]; then

    log "No active graphical user session was detected."
    log "Unable to display the FileVault dialog."

    exit 0

fi

USER_ID="$(id -u "$CONSOLE_USER" 2>/dev/null || true)"

if [[ -z "$USER_ID" ]]; then

    error "Unable to determine UID for logged-in user: $CONSOLE_USER"
    exit 1

fi

log "Logged-in user: $CONSOLE_USER"
log "User ID: $USER_ID"

#------------------------------------------------------------------------------
# Display FileVault compliance dialog
#------------------------------------------------------------------------------

log "Displaying FileVault security dialog..."

launchctl asuser "$USER_ID" \
    osascript <<EOF
display dialog "$DIALOG_MESSAGE" \
    with title "$DIALOG_TITLE" \
    buttons {"OK"} \
    default button "OK" \
    with icon caution
EOF

#------------------------------------------------------------------------------
# Final Status
#------------------------------------------------------------------------------

echo
echo "============================================================"
echo " FileVault Compliance Check"
echo "============================================================"
echo " Status : NOT ENABLED"
echo " User   : $CONSOLE_USER"
echo " Action : Security dialog displayed"
echo "============================================================"
echo

log "FileVault compliance check complete."

exit 0
