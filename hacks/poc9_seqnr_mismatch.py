#!/usr/bin/env python3
"""
PoC #9 — Wrong Sequence Number in Non-AEAD First-Block Decryption
=================================================================
Finding : LOW  (README-sshd-security-flaws.md #16)
File    : packet.c:1525-1527
Branch  : master

Vulnerability
-------------
When decrypting the first cipher block of an incoming non-AEAD packet
(to extract the packet length), cipher_crypt() is called with the SEND
sequence number instead of the READ sequence number:

    /* packet.c:1521-1528  — packlen == 0 branch, non-AEAD path */
    if ((r = cipher_crypt(state->receive_context,
        state->p_send.seqnr,          /* <-- BUG: should be p_read.seqnr */
        cp, sshbuf_ptr(state->input),
        block_size, 0, 0)) != 0)
        goto out;

Every subsequent decryption in the same function correctly uses
state->p_read.seqnr (line 1593).

Why it is harmless today
------------------------
For all ciphers in the current SSH2 cipher suite:
  - AES-CBC:  cipher_crypt ignores seqnr (CBC is stateful via the IV chain).
  - AES-CTR:  cipher_crypt ignores seqnr (counter is tracked in the cipher ctx).
  - chacha20-poly1305 (AEAD): takes the cipher_get_length() path for length
    extraction; the packlen==0 branch is not reached at all.

Latent risk
-----------
p_send.seqnr and p_read.seqnr diverge immediately in any real SSH session
because traffic is asymmetric.  If a future non-AEAD cipher uses the seqnr
as a nonce for the first-block decryption, the wrong nonce would produce
garbage where the packet length is expected — silently corrupting the
connection without a clear error.

This PoC:
  1. Simulates a realistic SSH session and shows p_send/p_read diverging.
  2. Demonstrates the decryption mismatch using a simplified seqnr-keyed
     cipher, proving that any cipher that uses seqnr would produce garbage.
  3. Compares correct (p_read.seqnr) vs. buggy (p_send.seqnr) decryption.
"""

import os
import sys
import subprocess
import tempfile

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * Simplified cipher that uses seqnr as the nonce — analogous to how
 * chacha20-poly1305 uses the sequence number as its 64-bit nonce.
 * (Chacha20-poly1305 actually takes the AEAD path and is unaffected;
 * this models a *hypothetical* non-AEAD cipher that uses seqnr.)
 */
static void
seqnr_cipher(uint32_t seqnr, const unsigned char *in, unsigned char *out,
    size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ (unsigned char)(seqnr >> (8 * (i % 4)));
}

int
main(void)
{
    uint32_t p_send = 0;   /* incremented when we send a packet   */
    uint32_t p_recv = 0;   /* incremented when we receive a packet */

    printf("=== PoC #9: seqnr mismatch in packet.c:1526 ===\n\n");

    /* ------------------------------------------------------------------ */
    printf("--- Phase 1: show p_send / p_read diverging in a real session ---\n\n");

    /* KEX phase: ~10 packets each direction (symmetric) */
    for (int i = 0; i < 10; i++) { p_send++; p_recv++; }
    printf("After KEX      (10 each):   p_send = %-6u  p_recv = %-6u  diff = %d\n",
           p_send, p_recv, (int)(p_recv - p_send));

    /* Auth phase: client sends ~5 auth exchanges, server sends ~5 replies */
    for (int i = 0; i < 5; i++) { p_send++; p_recv++; }
    printf("After auth     (5 each):    p_send = %-6u  p_recv = %-6u  diff = %d\n",
           p_send, p_recv, (int)(p_recv - p_send));

    /* scp upload: client sends 2000 data packets, server sends 20 acks */
    for (int i = 0; i < 2000; i++) p_recv++;
    for (int i = 0; i < 20;   i++) p_send++;
    printf("After scp upload (2000/20): p_send = %-6u  p_recv = %-6u  diff = %d\n",
           p_send, p_recv, (int)(p_recv - p_send));

    /* scp download: server sends 2000 data packets, client sends 20 acks */
    for (int i = 0; i < 2000; i++) p_send++;
    for (int i = 0; i < 20;   i++) p_recv++;
    printf("After scp download:         p_send = %-6u  p_recv = %-6u  diff = %d\n",
           p_send, p_recv, (int)(p_recv - p_send));

    printf("\np_send.seqnr != p_recv.seqnr after any asymmetric traffic.\n");

    /* ------------------------------------------------------------------ */
    printf("\n--- Phase 2: decryption outcome with correct vs. buggy seqnr ---\n\n");

    /*
     * Peer sends a packet.  Their send seqnr == our p_recv.
     * They encrypt the first block with their seqnr = p_recv.
     */
    unsigned char plaintext[8]  = {0x00, 0x00, 0x00, 0x1C,  /* packlen=28 */
                                    0x0A,                     /* padlen     */
                                    0x05, 0xAA, 0xBB};        /* payload    */
    unsigned char ciphertext[8];
    unsigned char decrypted_correct[8];
    unsigned char decrypted_buggy[8];

    printf("Plaintext first block (contains packet length):\n");
    printf("  ");
    for (int i = 0; i < 8; i++) printf("%02x ", plaintext[i]);
    printf("\n  packet_length field = 0x%02x%02x%02x%02x = %u\n\n",
           plaintext[0], plaintext[1], plaintext[2], plaintext[3],
           (uint32_t)plaintext[0]<<24 | (uint32_t)plaintext[1]<<16 |
           (uint32_t)plaintext[2]<<8  | plaintext[3]);

    /* Peer encrypts with their send seqnr = our p_recv */
    seqnr_cipher(p_recv, plaintext, ciphertext, 8);
    printf("Ciphertext (encrypted by peer with seqnr=%u):\n  ", p_recv);
    for (int i = 0; i < 8; i++) printf("%02x ", ciphertext[i]);
    printf("\n\n");

    /* Correct:  packet.c should use p_read.seqnr (= p_recv here) */
    seqnr_cipher(p_recv, ciphertext, decrypted_correct, 8);

    /* Buggy:    packet.c:1526 actually uses p_send.seqnr */
    seqnr_cipher(p_send, ciphertext, decrypted_buggy, 8);

    int correct_ok = (memcmp(decrypted_correct, plaintext, 8) == 0);
    int buggy_ok   = (memcmp(decrypted_buggy,   plaintext, 8) == 0);

    printf("Decryption of first incoming block:\n");
    printf("  p_recv.seqnr (%u): ", p_recv);
    for (int i = 0; i < 8; i++) printf("%02x ", decrypted_correct[i]);
    uint32_t pktlen_correct =
        (uint32_t)decrypted_correct[0]<<24 | (uint32_t)decrypted_correct[1]<<16 |
        (uint32_t)decrypted_correct[2]<<8  | decrypted_correct[3];
    printf("  packlen=%u  %s\n",
           pktlen_correct, correct_ok ? "[CORRECT]" : "[WRONG]");

    printf("  p_send.seqnr (%u):  ", p_send);
    for (int i = 0; i < 8; i++) printf("%02x ", decrypted_buggy[i]);
    uint32_t pktlen_buggy =
        (uint32_t)decrypted_buggy[0]<<24 | (uint32_t)decrypted_buggy[1]<<16 |
        (uint32_t)decrypted_buggy[2]<<8  | decrypted_buggy[3];
    printf("  packlen=%u  %s  <- packet.c:1526 uses this\n",
           pktlen_buggy, buggy_ok ? "[CORRECT — seqnr happened to match]"
                                  : "[+] WRONG — garbage packet length");

    /* ------------------------------------------------------------------ */
    printf("\n--- Phase 3: context ---\n\n");
    printf("  packet.c:1526  cipher_crypt(receive_ctx, p_send.seqnr, ...)\n");
    printf("  packet.c:1593  cipher_crypt(receive_ctx, p_read.seqnr, ...)  <- correct\n\n");
    printf("  AES-CTR / AES-CBC: seqnr is not used in cipher_crypt -> no impact today.\n");
    printf("  chacha20-poly1305: AEAD path (aadlen!=0) -> packlen==0 branch not reached.\n");
    printf("  Any future non-AEAD cipher using seqnr as nonce -> garbage packlen.\n");
    printf("\n  Fix: replace p_send.seqnr with p_read.seqnr at packet.c:1526.\n");

    return 0;
}
"""


def main():
    print("=" * 60)
    print("PoC #9 — Wrong seqnr in non-AEAD first-block decryption")
    print("=" * 60)
    print()
    print("[*] Compiles a C reproducer that shows p_send.seqnr and")
    print("    p_read.seqnr diverging in a typical SSH session, then")
    print("    demonstrates the decryption mismatch for any cipher")
    print("    that uses the sequence number as a nonce.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc9.c")
        bin_ = os.path.join(tmpdir, "poc9")

        with open(src, "w") as f:
            f.write(C_REPRODUCER)

        r = subprocess.run(
            ["cc", "-O2", "-o", bin_, src, "-Wall"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"[!] Compilation failed:\n{r.stderr}")
            sys.exit(1)
        print("[*] Compiled reproducer OK\n")

        r = subprocess.run([bin_], capture_output=True, text=True)
        print(r.stdout)
        if r.stderr:
            print(r.stderr, file=sys.stderr)


if __name__ == "__main__":
    main()
