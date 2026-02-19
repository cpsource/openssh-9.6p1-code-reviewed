#!/usr/bin/env bash
# setup-ca.sh — Generate the frflashy.com Host CA keypair.
#
# Run this ONCE on your local machine (laptop/workstation).
# The private key (ssh_host_ca) NEVER leaves this machine.
# The public key (ssh_host_ca.pub) is safe to distribute and commit.
#
# See README-cert.md for the full setup guide.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_KEY="$SCRIPT_DIR/ssh_host_ca"
CA_PUB="$SCRIPT_DIR/ssh_host_ca.pub"

echo "=== Host CA Setup — frflashy.com ==="
echo ""

if [[ -f "$CA_KEY" ]]; then
    echo "ERROR: CA private key already exists at $CA_KEY"
    echo "       Delete it manually if you want to regenerate the CA."
    echo "       WARNING: Regenerating the CA invalidates ALL existing host certificates."
    exit 1
fi

echo "This generates an ed25519 CA keypair."
echo "You will be prompted for a passphrase — use a strong one and"
echo "store it in your password manager."
echo ""

ssh-keygen \
    -t ed25519 \
    -f "$CA_KEY" \
    -C "frflashy.com Host CA $(date +%Y-%m-%d)"

echo ""
echo "=== CA keypair generated ==="
echo ""
echo "  Private key : $CA_KEY"
echo "    --> NEVER copy this to the server or commit it to git."
echo ""
echo "  Public key  : $CA_PUB"
echo "    --> Safe to distribute and commit."
echo ""
echo "Add this line to /etc/ssh/ssh_known_hosts on every client machine:"
echo ""
printf '  @cert-authority frflashy.com,*.frflashy.com '
cat "$CA_PUB"
echo ""
echo "Or run:  sudo bash -c 'printf \"@cert-authority frflashy.com,*.frflashy.com \"; cat $CA_PUB' >> /etc/ssh/ssh_known_hosts"
echo ""
echo "Next step: sign the server's host key with:"
echo "  bash ca/sign-host-key.sh /path/to/ssh_host_ed25519_key.pub frflashy.com"
echo ""
echo "See README-cert.md for the full setup guide."
