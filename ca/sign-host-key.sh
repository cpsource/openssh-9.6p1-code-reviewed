#!/usr/bin/env bash
# sign-host-key.sh — Sign a server's host public key with the Host CA.
#
# Usage:
#   bash ca/sign-host-key.sh <host-pubkey.pub> [hostname[,hostname,...]]
#
# Examples:
#   bash ca/sign-host-key.sh /tmp/ssh_host_ed25519_key.pub "frflashy.com"
#   bash ca/sign-host-key.sh /tmp/ssh_host_ed25519_key.pub "frflashy.com,www.frflashy.com,203.0.113.5"
#
# The signed certificate is written alongside the input key:
#   /tmp/ssh_host_ed25519_key-cert.pub
#
# Copy that file to /etc/ssh/ on the server and add to sshd_config:
#   HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
#
# See README-cert.md for the full workflow.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_KEY="$SCRIPT_DIR/ssh_host_ca"

VALIDITY="+52w"   # 1 year; adjust as needed

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <host-pubkey.pub> [hostname[,hostname,...]]"
    echo ""
    echo "  host-pubkey.pub   Path to the server's public host key"
    echo "  hostname          Comma-separated hostnames/IPs (default: frflashy.com)"
    echo ""
    echo "Examples:"
    echo "  $0 /tmp/ssh_host_ed25519_key.pub"
    echo "  $0 /tmp/ssh_host_ed25519_key.pub frflashy.com,www.frflashy.com"
    exit 1
fi

HOST_PUB="$1"
PRINCIPALS="${2:-frflashy.com}"

if [[ ! -f "$CA_KEY" ]]; then
    echo "ERROR: CA private key not found at $CA_KEY"
    echo "       Run 'bash ca/setup-ca.sh' first."
    exit 1
fi

if [[ ! -f "$HOST_PUB" ]]; then
    echo "ERROR: Host public key not found: $HOST_PUB"
    exit 1
fi

# Derive cert output path:  foo.pub -> foo-cert.pub
CERT_FILE="${HOST_PUB%.pub}-cert.pub"
KEY_ID="$(basename "${HOST_PUB%.pub}") ${PRINCIPALS} $(date +%Y-%m-%d)"

echo "=== Signing host key ==="
echo ""
echo "  Host key   : $HOST_PUB"
echo "  Principals : $PRINCIPALS"
echo "  Validity   : $VALIDITY  ($(date -d "$VALIDITY" '+%Y-%m-%d' 2>/dev/null || date -v+52w '+%Y-%m-%d' 2>/dev/null || echo 'approx. 1 year'))"
echo "  Key ID     : $KEY_ID"
echo "  Output     : $CERT_FILE"
echo ""

ssh-keygen \
    -s "$CA_KEY" \
    -I "$KEY_ID" \
    -h \
    -n "$PRINCIPALS" \
    -V "$VALIDITY" \
    "$HOST_PUB"

echo ""
echo "=== Certificate generated: $CERT_FILE ==="
echo ""
echo "Next steps:"
echo ""
echo "  1. Inspect the certificate:"
echo "       bash ca/show-cert.sh $CERT_FILE"
echo ""
echo "  2. Copy the certificate to the server:"
echo "       scp $CERT_FILE root@frflashy.com:/etc/ssh/"
echo ""
echo "  3. Add to /etc/ssh/sshd_config on the server:"
echo "       HostCertificate /etc/ssh/$(basename "$CERT_FILE")"
echo ""
echo "  4. Reload sshd on the server:"
echo "       systemctl reload ssh"
echo ""
echo "  5. Test from a client that has the CA in its known_hosts:"
echo "       ssh -v user@frflashy.com 2>&1 | grep -i 'host certificate\|server host key'"
