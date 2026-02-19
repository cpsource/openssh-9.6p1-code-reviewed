# SSH Host Certificate Authority — frflashy.com

This document covers the setup and ongoing operation of the Host CA that
eliminates the SSH Trust-On-First-Use (TOFU) problem for `frflashy.com`.

Instead of clients storing and verifying individual host keys, they trust
the CA's public key once.  Any server presenting a certificate signed by
that CA is automatically trusted — no fingerprint prompt, no
`known_hosts` management.

**See also:** `README-sshd-security-flaws.md` — Man-in-the-Middle Attack
Analysis (Mitigation 4) for background on why this matters.

---

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  Your laptop (offline CA)                                   │
│                                                             │
│  ca/ssh_host_ca       ← private key  (NEVER leaves here)   │
│  ca/ssh_host_ca.pub   ← public key   (safe to distribute)  │
└───────────────┬────────────────────────────┬────────────────┘
                │ signs                      │ distribute pub key
                ▼                            ▼
┌──────────────────────────┐   ┌──────────────────────────────┐
│  frflashy.com (server)   │   │  Client machines             │
│                          │   │                              │
│  /etc/ssh/               │   │  /etc/ssh/ssh_known_hosts:   │
│    ssh_host_ed25519_key  │   │    @cert-authority           │
│    ssh_host_ed25519_key  │   │    frflashy.com,...          │
│      -cert.pub  ◄────────┤   │    ssh-ed25519 AAAA...       │
│                          │   │                              │
│  sshd_config:            │   │  ssh automatically trusts    │
│    HostCertificate ...   │   │  any cert signed by the CA   │
└──────────────────────────┘   └──────────────────────────────┘
```

On connection:
1. Server presents its host certificate (signed by the CA).
2. Client verifies the certificate against the CA public key in `known_hosts`.
3. If valid and the hostname matches: trusted immediately, no prompt.
4. If invalid or unsigned: `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`

---

## Prerequisites

- `ssh-keygen` (from this OpenSSH build, or any OpenSSH ≥ 5.6)
- The scripts in `ca/` run on your **local machine** (laptop/workstation)
- `bash` and `make`
- Root access to `frflashy.com` for deploying the certificate

---

## One-time setup

### Step 1 — Generate the Host CA (run once, on your local machine)

```bash
# From the repo root on your laptop:
bash ca/setup-ca.sh
```

This generates:
- `ca/ssh_host_ca` — the private key (gitignored, stays on your laptop)
- `ca/ssh_host_ca.pub` — the public key (safe to commit and distribute)

You will be prompted for a passphrase.  Use a strong one and store it in
your password manager.  You will need it every time you sign a host key.

**Do not copy `ca/ssh_host_ca` to the server.**

---

### Step 2 — Distribute the CA public key to clients

Every machine that connects to `frflashy.com` needs one line in its
`/etc/ssh/ssh_known_hosts` (system-wide) or `~/.ssh/known_hosts` (per-user):

```bash
# Append the CA trust line to the system-wide known_hosts:
sudo bash -c 'printf "@cert-authority frflashy.com,*.frflashy.com "; \
    cat ca/ssh_host_ca.pub' >> /etc/ssh/ssh_known_hosts
```

Or use the template in `ca/known_hosts.example` after filling in the public
key.

After this one step, the client will trust **any** server at `frflashy.com`
that presents a valid CA-signed certificate.  No further `known_hosts`
changes are needed as host keys rotate.

---

### Step 3 — Sign the server's host key

Fetch the server's host public key:

```bash
# Copy the public key from the server to your local machine:
scp root@frflashy.com:/etc/ssh/ssh_host_ed25519_key.pub /tmp/
```

Sign it:

```bash
bash ca/sign-host-key.sh /tmp/ssh_host_ed25519_key.pub "frflashy.com"
# Produces: /tmp/ssh_host_ed25519_key-cert.pub
```

Inspect the result before deploying:

```bash
bash ca/show-cert.sh /tmp/ssh_host_ed25519_key-cert.pub
```

Expected output:
```
=== Certificate: /tmp/ssh_host_ed25519_key-cert.pub ===

        Type: ssh-ed25519-cert-v01@openssh.com host certificate
        Public key: ED25519-CERT SHA256:...
        Signing CA: ED25519 SHA256:...  (using ssh-ed25519)
        Key ID: "ssh_host_ed25519_key frflashy.com 2025-01-01"
        Serial: 0
        Valid: from 2025-01-01T00:00:00 to 2026-01-01T00:00:00
        Principals:
                frflashy.com
        Critical Options: (none)
        Extensions: (none)
```

---

### Step 4 — Deploy the certificate to the server

```bash
scp /tmp/ssh_host_ed25519_key-cert.pub root@frflashy.com:/etc/ssh/
```

Add to `/etc/ssh/sshd_config` on the server:

```
# Host certificate — eliminates client TOFU prompts
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

Reload sshd:

```bash
systemctl reload ssh
```

---

### Step 5 — Verify

From a client machine that has Step 2 applied:

```bash
ssh -v user@frflashy.com 2>&1 | grep -i 'host certificate\|server host key\|CA key'
```

You should see something like:
```
debug1: Server host certificate: ssh-ed25519-cert-v01@openssh.com, ...
debug1: Host certificate authority matches a CA in known_hosts
debug1: Host 'frflashy.com' is known and matches the host certificate
```

No `Are you sure you want to continue connecting?` prompt.

---

## Ongoing operations

### Sign multiple hostnames / IPs

If `frflashy.com` is also reachable as `www.frflashy.com` or by IP:

```bash
bash ca/sign-host-key.sh /tmp/ssh_host_ed25519_key.pub \
    "frflashy.com,www.frflashy.com,203.0.113.5"
```

The `@cert-authority` line in `known_hosts` already covers `*.frflashy.com`;
the additional principals are embedded in the certificate itself.

### Using `make` as a shorthand

```bash
# From the repo root:
make -C ca setup
make -C ca sign HOST_KEY=/tmp/ssh_host_ed25519_key.pub
make -C ca sign HOST_KEY=/tmp/ssh_host_ed25519_key.pub NAMES="frflashy.com,www.frflashy.com"
make -C ca show CERT=/tmp/ssh_host_ed25519_key-cert.pub
make -C ca revoke KEY=/tmp/ssh_host_ed25519_key.pub
```

---

## Certificate renewal

Certificates are valid for **1 year** (configured as `+52w` in
`ca/sign-host-key.sh`).  When a certificate expires, clients will see:

```
Certificate invalid: expired
```

To renew:

1. Fetch the current host public key from the server (unchanged):
   ```bash
   scp root@frflashy.com:/etc/ssh/ssh_host_ed25519_key.pub /tmp/
   ```

2. Sign it again (generates a new certificate, same key):
   ```bash
   bash ca/sign-host-key.sh /tmp/ssh_host_ed25519_key.pub "frflashy.com"
   ```

3. Deploy and reload:
   ```bash
   scp /tmp/ssh_host_ed25519_key-cert.pub root@frflashy.com:/etc/ssh/
   ssh root@frflashy.com systemctl reload ssh
   ```

Clients need no changes — the CA public key stays the same.

**Tip:** Set a calendar reminder ~2 weeks before expiry.  The certificate's
validity window is shown by `bash ca/show-cert.sh`.

---

## Rotating the host key

If the server's private host key is compromised or needs rotation:

1. Generate a new host key on the server:
   ```bash
   ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''
   ```

2. Revoke the old key:
   ```bash
   # If you have the old public key locally:
   bash ca/revoke-host-key.sh /tmp/old_ssh_host_ed25519_key.pub
   ```

3. Sign the new key:
   ```bash
   scp root@frflashy.com:/etc/ssh/ssh_host_ed25519_key.pub /tmp/new_ssh_host_ed25519_key.pub
   bash ca/sign-host-key.sh /tmp/new_ssh_host_ed25519_key.pub "frflashy.com"
   scp /tmp/new_ssh_host_ed25519_key-cert.pub root@frflashy.com:/etc/ssh/ssh_host_ed25519_key-cert.pub
   ssh root@frflashy.com systemctl reload ssh
   ```

4. Deploy the updated KRL to clients:
   ```bash
   scp ca/revoked.krl root@frflashy.com:/etc/ssh/revoked_host_keys.krl
   # Distribute to client machines as well
   ```

Clients using the CA trust line need no `known_hosts` changes — the old
fingerprint was never stored directly.

---

## Revocation

The KRL (Key Revocation List) allows you to actively reject a compromised
key even if its certificate has not yet expired.

```bash
# Revoke a host key:
bash ca/revoke-host-key.sh /tmp/ssh_host_ed25519_key.pub

# Revoke a certificate directly:
bash ca/revoke-host-key.sh /tmp/ssh_host_ed25519_key-cert.pub
```

This updates `ca/revoked.krl`.  Deploy it to clients via `RevokedHostKeys`
in `ssh_config`:

```
# /etc/ssh/ssh_config or ~/.ssh/config
RevokedHostKeys /etc/ssh/revoked_host_keys.krl
```

Deploy:
```bash
scp ca/revoked.krl root@frflashy.com:/etc/ssh/revoked_host_keys.krl
# Repeat for each client machine that needs the updated list
```

Verify a key is revoked:
```bash
ssh-keygen -Qf ca/revoked.krl /tmp/ssh_host_ed25519_key.pub \
    && echo "REVOKED" || echo "not in KRL"
```

---

## CA private key security

The CA private key (`ca/ssh_host_ca`) is the most sensitive piece of this
setup.  If it is compromised, an attacker can sign certificates for
`frflashy.com` that all clients will trust automatically.

| Rule | Why |
|------|-----|
| Never copy to the server | Server compromise → CA compromise |
| Never commit to git | Git history is forever; `.gitignore` blocks accidents |
| Always use a strong passphrase | Last line of defence if the file leaks |
| Keep on an encrypted volume | Full-disk encryption on your laptop is the baseline |
| Use only when signing | Minimise time the key is decrypted in memory |

**For higher assurance:** store `ca/ssh_host_ca` on an encrypted USB drive
(VeraCrypt / LUKS) that is only plugged in during signing operations.  This
keeps the key fully offline between uses.

**For team environments:** use HashiCorp Vault's SSH secrets engine or
AWS KMS to manage the CA key so multiple operators can sign without sharing
a private key file.

---

## File reference

```
ca/
├── setup-ca.sh          Generate the Host CA keypair (run once, locally)
├── sign-host-key.sh     Sign a server's host public key
├── revoke-host-key.sh   Add a key/cert to the revocation list (KRL)
├── show-cert.sh         Inspect a certificate's contents
├── Makefile             Convenience targets for the above
├── known_hosts.example  @cert-authority line template for clients
├── ssh_host_ca.pub      CA public key — safe to commit and distribute
├── .gitignore           Blocks ssh_host_ca (private), *.krl, *-cert.pub
│
│   (gitignored — never committed)
├── ssh_host_ca          CA private key — lives on your laptop only
└── revoked.krl          Key revocation list — deploy to clients as needed
```

### Config changes on the server (`/etc/ssh/sshd_config`)

```
# Uncomment after deploying the signed certificate:
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

### Config changes on clients (`/etc/ssh/ssh_known_hosts`)

```
@cert-authority frflashy.com,*.frflashy.com ssh-ed25519 AAAA...
```

### Optional: revocation on clients (`/etc/ssh/ssh_config`)

```
RevokedHostKeys /etc/ssh/revoked_host_keys.krl
```
