#!/usr/bin/env bash
# revoke-host-key.sh — Add a host key or certificate to the revocation list.
#
# Usage:
#   bash ca/revoke-host-key.sh <key-or-cert.pub>
#
# Examples:
#   bash ca/revoke-host-key.sh /tmp/ssh_host_ed25519_key.pub       # revoke plain key
#   bash ca/revoke-host-key.sh /tmp/ssh_host_ed25519_key-cert.pub  # revoke certificate
#
# This updates ca/revoked.krl (a Key Revocation List in OpenSSH binary format).
# Deploy the updated KRL to clients via RevokedHostKeys in ssh_config:
#
#   RevokedHostKeys /etc/ssh/revoked_host_keys.krl
#
# See README-cert.md for the full revocation workflow.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KRL_FILE="$SCRIPT_DIR/revoked.krl"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <key-or-cert.pub>"
    echo ""
    echo "  key-or-cert.pub   Path to the host public key or certificate to revoke."
    echo ""
    echo "Examples:"
    echo "  $0 /tmp/ssh_host_ed25519_key.pub"
    echo "  $0 /tmp/ssh_host_ed25519_key-cert.pub"
    exit 1
fi

KEY="$1"

if [[ ! -f "$KEY" ]]; then
    echo "ERROR: Key file not found: $KEY"
    exit 1
fi

# Initialise the KRL if it doesn't exist yet
if [[ ! -f "$KRL_FILE" ]]; then
    echo "Initialising KRL at $KRL_FILE ..."
    ssh-keygen -kf "$KRL_FILE"
    echo ""
fi

echo "=== Revoking key ==="
echo ""
echo "  Key : $KEY"
echo "  KRL : $KRL_FILE"
echo ""

ssh-keygen -ukf "$KRL_FILE" "$KEY"

echo ""
echo "=== Key added to KRL ==="
echo ""
echo "Deploy the updated KRL to all SSH clients:"
echo ""
echo "  scp $KRL_FILE root@frflashy.com:/etc/ssh/revoked_host_keys.krl"
echo ""
echo "  # For client machines, copy to their /etc/ssh/ or ~/.ssh/ and ensure"
echo "  # their ssh_config contains:"
echo "  #   RevokedHostKeys /etc/ssh/revoked_host_keys.krl"
echo ""
echo "Verify the key is revoked:"
echo "  ssh-keygen -Qf $KRL_FILE $KEY && echo 'REVOKED' || echo 'not in KRL'"
