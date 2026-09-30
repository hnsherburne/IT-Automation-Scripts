#!/bin/bash
#
#===============================================================================
# Script Name    : enable_ssh.sh
# Description    : Enables SSH Remote Login on macOS.
#
# Author         : Herb Sherburne
# Created        : 2024-10-12
# Version        : 1.0.0
#
# Requirements   :
#   - macOS
#   - Administrator privileges
#
# Usage          :
#   sudo ./enable_ssh.sh
#
# Notes          :
#   - This script enables macOS Remote Login (SSH).
#   - It does not configure Apple Remote Management or Screen Sharing.
#   - macOS controls SSH access through the Remote Login configuration.
#
# Security       :
#   - SSH increases the remote attack surface of the Mac.
#   - Use strong authentication and appropriate network/firewall controls.
#   - Avoid exposing SSH directly to the public Internet.
#
#===============================================================================

set -euo pipefail

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------

SYSTEMSETUP="/usr/sbin/systemsetup"

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
# Verify systemsetup exists
#------------------------------------------------------------------------------

if [[ ! -x "$SYSTEMSETUP" ]]; then
    error "systemsetup was not found at $SYSTEMSETUP."
    exit 1
fi

#------------------------------------------------------------------------------
# Check current Remote Login status
#------------------------------------------------------------------------------

log "Checking current SSH Remote Login status..."

CURRENT_STATUS=$("$SYSTEMSETUP" -getremotelogin 2>/dev/null || true)

log "Current status: $CURRENT_STATUS"

#------------------------------------------------------------------------------
# Enable SSH Remote Login
#------------------------------------------------------------------------------

if echo "$CURRENT_STATUS" | grep -qi "On"; then

    log "SSH Remote Login is already enabled."

else

    log "Enabling SSH Remote Login..."

    "$SYSTEMSETUP" -setremotelogin on

    log "SSH Remote Login has been enabled."

fi

#------------------------------------------------------------------------------
# Verify final configuration
#------------------------------------------------------------------------------

echo
log "Verifying SSH Remote Login configuration..."

FINAL_STATUS=$("$SYSTEMSETUP" -getremotelogin)

echo
echo "============================================================"
echo " macOS SSH Configuration"
echo "============================================================"
echo " Remote Login: $FINAL_STATUS"
echo "============================================================"
echo

log "SSH configuration complete."

exit 0
