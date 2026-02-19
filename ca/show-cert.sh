#!/usr/bin/env bash
# show-cert.sh — Inspect the contents of an SSH host certificate.
#
# Usage:
#   bash ca/show-cert.sh <cert.pub>
#
# Displays: type, public key fingerprint, signing CA fingerprint,
# key ID, principals (valid hostnames), validity window, and extensions.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <cert.pub>"
    echo ""
    echo "  cert.pub   Path to the SSH host certificate to inspect."
    exit 1
fi

CERT="$1"

if [[ ! -f "$CERT" ]]; then
    echo "ERROR: Certificate file not found: $CERT"
    exit 1
fi

echo "=== Certificate: $CERT ==="
echo ""
ssh-keygen -Lf "$CERT"
