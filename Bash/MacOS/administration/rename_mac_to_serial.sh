#!/bin/bash
#
#===============================================================================
# Script Name    : rename_mac_to_serial.sh
# Description    : Renames a macOS computer using a defined prefix and the
#                  device serial number.
#
#                  The following macOS computer names are updated:
#                    - ComputerName
#                    - HostName
#                    - LocalHostName
#
# Author         : Herb Sherburne
# Original Date  : 2019-12-05
# Updated By     : Your Name
# Updated Date   : 2025-09-30
# Version        : 2.0.0
#
# Requirements   :
#   - macOS
#   - Administrator privileges
#   - ioreg
#   - scutil
#
# Usage          :
#   sudo ./rename_mac_to_serial.sh
#
# Example        :
#   Serial Number : C02ABC123456
#   Prefix        : US
#   Computer Name : USC02ABC123456
#
# Notes          :
#   - The serial number is retrieved from IOPlatformExpertDevice.
#   - The prefix can be modified in the Configuration section.
#   - ComputerName, HostName, and LocalHostName are intentionally set to
#     the same value.
#
# Security       :
#   - This script does not transmit or store the serial number externally.
#   - Review naming requirements before deploying in production.
#
#===============================================================================

set -euo pipefail

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------

PREFIX="US"

#------------------------------------------------------------------------------
# Functions
#------------------------------------------------------------------------------

log() {
    echo "[INFO] $1"
}

error() {
    echo "[ERROR] $1" >&2
}

#------------------------------------------------------------------------------
# Verify operating system
#------------------------------------------------------------------------------

if [[ "$(uname -s)" != "Darwin" ]]; then
    error "This script is intended for macOS only."
    exit 1
fi

#------------------------------------------------------------------------------
# Verify required commands
#------------------------------------------------------------------------------

for command in ioreg scutil; do
    if ! command -v "$command" >/dev/null 2>&1; then
        error "Required command not found: $command"
        exit 1
    fi
done

#------------------------------------------------------------------------------
# Retrieve macOS serial number
#------------------------------------------------------------------------------

log "Retrieving Mac serial number..."

SERIAL_NUMBER=$(
    ioreg -c IOPlatformExpertDevice -d 2 |
    awk -F\" '/IOPlatformSerialNumber/{print $(NF-1); exit}'
)

#------------------------------------------------------------------------------
# Validate serial number
#------------------------------------------------------------------------------

if [[ -z "$SERIAL_NUMBER" ]]; then
    error "Unable to retrieve the Mac serial number."
    exit 1
fi

log "Serial number retrieved successfully."

#------------------------------------------------------------------------------
# Build computer name
#------------------------------------------------------------------------------

COMPUTER_NAME="${PREFIX}${SERIAL_NUMBER}"

#------------------------------------------------------------------------------
# Validate resulting computer name
#------------------------------------------------------------------------------

if [[ -z "$COMPUTER_NAME" ]]; then
    error "Computer name is empty."
    exit 1
fi

log "New computer name: $COMPUTER_NAME"

#------------------------------------------------------------------------------
# Display current configuration
#------------------------------------------------------------------------------

echo
echo "Current macOS computer names:"
echo "----------------------------------------"
echo "ComputerName    : $(scutil --get ComputerName 2>/dev/null || echo "Not Set")"
echo "HostName        : $(scutil --get HostName 2>/dev/null || echo "Not Set")"
echo "LocalHostName   : $(scutil --get LocalHostName 2>/dev/null || echo "Not Set")"
echo

#------------------------------------------------------------------------------
# Apply new computer name
#------------------------------------------------------------------------------

log "Setting ComputerName..."
scutil --set ComputerName "$COMPUTER_NAME"

log "Setting HostName..."
scutil --set HostName "$COMPUTER_NAME"

log "Setting LocalHostName..."
scutil --set LocalHostName "$COMPUTER_NAME"

#------------------------------------------------------------------------------
# Verify configuration
#------------------------------------------------------------------------------

echo
log "Verifying new macOS computer names..."

CURRENT_COMPUTER_NAME="$(scutil --get ComputerName)"
CURRENT_HOSTNAME="$(scutil --get HostName)"
CURRENT_LOCALHOSTNAME="$(scutil --get LocalHostName)"

echo
echo "Updated macOS computer names:"
echo "----------------------------------------"
echo "ComputerName    : $CURRENT_COMPUTER_NAME"
echo "HostName        : $CURRENT_HOSTNAME"
echo "LocalHostName   : $CURRENT_LOCALHOSTNAME"
echo

#------------------------------------------------------------------------------
# Confirm expected configuration
#------------------------------------------------------------------------------

if [[ "$CURRENT_COMPUTER_NAME" == "$COMPUTER_NAME" &&
      "$CURRENT_HOSTNAME" == "$COMPUTER_NAME" &&
      "$CURRENT_LOCALHOSTNAME" == "$COMPUTER_NAME" ]]; then

    log "Computer naming configuration completed successfully."

else

    error "Computer naming verification failed."
    exit 1

fi

#------------------------------------------------------------------------------
# Exit
#------------------------------------------------------------------------------

exit 0
