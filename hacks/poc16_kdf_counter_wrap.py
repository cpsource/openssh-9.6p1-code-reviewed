#!/usr/bin/env python3
"""
PoC #16 — kdf() Counter Byte Truncation — Silent Wrap at 256 AES Blocks
========================================================================
Finding : INFO  (README-sshd-security-flaws.md #24)
File    : umac.c:199
Branch  : master

Vulnerability
-------------
The UMAC key-derivation function kdf() (umac.c:185) drives an AES
counter-mode keystream.  The counter is maintained as a C `int` but stored
in a single-byte slot of the AES input block:

    static void kdf(void *bufp, aes_int_key key, UINT8 ndx, int nbytes)
    {
        UINT8 in_buf[AES_BLOCK_LEN] = {0};
        int i;
        in_buf[AES_BLOCK_LEN-1] = i = 1;    /* counter starts at 1 */

        while (nbytes >= AES_BLOCK_LEN) {
            aes_encryption(in_buf, out_buf, key);
            in_buf[AES_BLOCK_LEN-1] = ++i;  /* truncates int→UINT8 at i=256 */
            ...
        }
    }

When `i` is incremented to 256, the assignment `in_buf[AES_BLOCK_LEN-1] = ++i`
silently truncates the 32-bit integer 256 to the 8-bit value 0.  On the next
AES encryption the counter byte is 0, duplicating the counter value used at
i=256 (which also stores 0x00).  More critically, the counter sequence from
that point forward: 0, 1, 2, ... repeats the counters used in the first
256 blocks verbatim.

A repeated AES-CTR counter with the same key produces the same keystream.
In a KDF context, the derived key bytes from block 257 onward would be
identical to those from block 1 — partially repeating key material.

Attack surface:
  Maximum bytes requested across all kdf() callers:
    - ndx=0  PDF key:   16 bytes  = 1 AES block
    - ndx=1  NH key:    1040 bytes = 65 blocks
    - ndx=2  poly keys: (8*4+4)*8 = 288 bytes = 18 blocks (STREAMS=4)
    - ndx=3  IP keys:   (8*4+4)*8 = 288 bytes = 18 blocks
    - ndx=4  IP trans:  4*4 = 16 bytes = 1 block
  Total: ~103 blocks maximum.  Wrap at block 256 is NOT reachable.

This PoC:
  1. Mirrors the counter truncation in C.
  2. Generates keystream blocks 1..260 and shows blocks 1 and 257
     are identical (counter both = 0x01 → but wait, this needs careful
     reading: i starts at 1, so block 1 uses counter=1.  After 255
     increments, i=256 stored as 0.  Block 256 uses counter=0.
     Block 257 uses counter=1 again — same as block 1).
  3. Flags the collision: AES(counter=1) appears at both block 1 and 257.
  4. Confirms in-practice safety: max usage ~103 blocks.
"""

import os
import sys
import subprocess
import tempfile

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define AES_BLOCK_LEN 16

/*
 * Stub AES "encryption": XOR input with a fixed pattern so we can
 * observe counter-block collisions without a real AES implementation.
 * Output[i] = input[i] ^ 0xAA — fully deterministic and reversible.
 */
static void
stub_aes(const uint8_t in[AES_BLOCK_LEN], uint8_t out[AES_BLOCK_LEN])
{
    for (int i = 0; i < AES_BLOCK_LEN; i++)
        out[i] = in[i] ^ 0xAAu;
}

/*
 * Mirror of kdf() from umac.c:185 — exact reproduction of the bug.
 * We capture the AES input block (the counter block) at each iteration
 * to show when the counter byte repeats.
 */
static void
kdf_mirror(uint8_t *dst, int nbytes,
           uint8_t counter_log[][AES_BLOCK_LEN], int *log_count)
{
    uint8_t in_buf[AES_BLOCK_LEN]  = {0};
    uint8_t out_buf[AES_BLOCK_LEN];
    int i;

    in_buf[AES_BLOCK_LEN - 1] = i = 1;   /* umac.c:194 */
    *log_count = 0;

    while (nbytes >= AES_BLOCK_LEN) {
        /* Log the counter block before encryption */
        memcpy(counter_log[*log_count], in_buf, AES_BLOCK_LEN);
        (*log_count)++;

        stub_aes(in_buf, out_buf);
        memcpy(dst, out_buf, AES_BLOCK_LEN);
        dst    += AES_BLOCK_LEN;
        nbytes -= AES_BLOCK_LEN;

        in_buf[AES_BLOCK_LEN - 1] = ++i;  /* umac.c:199 — truncation here */
    }
    if (nbytes > 0) {
        memcpy(counter_log[*log_count], in_buf, AES_BLOCK_LEN);
        (*log_count)++;
        stub_aes(in_buf, out_buf);
        memcpy(dst, out_buf, nbytes);
    }
}

int
main(void)
{
    /* Request 260 AES blocks to see the wrap at block 256 */
    int request_blocks = 260;
    int nbytes = request_blocks * AES_BLOCK_LEN;

    uint8_t keystream[260 * AES_BLOCK_LEN];
    uint8_t counter_log[300][AES_BLOCK_LEN];
    int log_count = 0;

    printf("=== PoC #16: kdf() counter wrap at block 256 (umac.c:199) ===\n\n");
    printf("Generating %d AES blocks (%d bytes)...\n\n",
           request_blocks, nbytes);

    kdf_mirror(keystream, nbytes, counter_log, &log_count);

    /* Print counter bytes for selected blocks */
    printf("%-10s  %-6s  %-8s  %s\n",
           "Block #", "i val", "ctr byte", "collision?");
    printf("%-10s  %-6s  %-8s  %s\n",
           "────────", "──────", "────────", "──────────");

    int first_collision = -1;
    for (int b = 0; b < log_count; b++) {
        uint8_t ctr = counter_log[b][AES_BLOCK_LEN - 1];

        /* Check for previous block with same counter byte */
        int collision = -1;
        for (int j = 0; j < b; j++) {
            if (counter_log[j][AES_BLOCK_LEN - 1] == ctr) {
                collision = j + 1;  /* 1-indexed */
                break;
            }
        }

        /* Only print interesting blocks */
        int print = (b < 5) || (b >= 253 && b <= 260) || (collision >= 0);
        if (print) {
            if (b == 5 && log_count > 10)
                printf("  ... (%d blocks omitted) ...\n", 248);
            printf("%-10d  %-6d  0x%02X      %s\n",
                   b + 1,
                   (b + 1 <= 255) ? b + 1 :
                       (b == 255) ? 256 : (b - 255),  /* what int i holds */
                   ctr,
                   (collision >= 0) ?
                       (first_collision < 0 ?
                           (first_collision = b + 1, "[+] COLLISION with block %d") :
                           "[+] COLLISION") :
                       "-");
            if (collision >= 0 && first_collision == b + 1) {
                /* print the collision block number */
                printf("    ^^^ counter byte 0x%02X also used at block %d\n",
                       ctr, collision);
                /* Verify keystream is identical */
                const uint8_t *ks_a = keystream + (collision - 1) * AES_BLOCK_LEN;
                const uint8_t *ks_b = keystream + b * AES_BLOCK_LEN;
                if (memcmp(ks_a, ks_b, AES_BLOCK_LEN) == 0) {
                    printf("    Keystream blocks %d and %d are IDENTICAL!\n",
                           collision, b + 1);
                    printf("    XOR of derived key bytes = 0x00 (full repetition).\n");
                }
            }
        }
    }

    printf("\n");
    printf("Analysis:\n");
    printf("  Block 256: i is incremented to 256, stored as (uint8_t)256 = 0x00\n");
    printf("  Block 257: ++i = 257 in int, stored as (uint8_t)1 = 0x01\n");
    printf("             — same counter byte as block 1!\n");
    printf("  AES(same_key, same_counter) = same output -> keystream repeats.\n\n");

    printf("In-practice safety:\n");
    printf("  Max kdf() usage in UMAC (STREAMS=4): ~103 AES blocks.\n");
    printf("  Wrap threshold: 256 blocks.  Margin: 153 blocks.\n");
    printf("  NOT reachable in OpenSSH today.\n\n");
    printf("Fix: use UINT8 counter with a static_assert on max nbytes,\n");
    printf("  or replace the single-byte counter with a proper 128-bit\n");
    printf("  counter (only the last 4 bytes need to be incremented\n");
    printf("  given the actual usage).\n");

    return 0;
}
"""


def main():
    print("=" * 60)
    print("PoC #16 — kdf() counter byte wrap at block 256 (umac.c:199)")
    print("=" * 60)
    print()
    print("[*] Generates 260 AES counter blocks and shows that block 257")
    print("    uses counter byte 0x01 — the same as block 1 — causing")
    print("    keystream repetition beyond the 256-block (4096 byte) boundary.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc16.c")
        bin_ = os.path.join(tmpdir, "poc16")

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

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    umac_c = os.path.join(repo_root, "umac.c")
    if os.path.exists(umac_c):
        print("[*] Vulnerable source line (umac.c:199):")
        with open(umac_c) as f:
            lines = f.readlines()
        for i in range(185, 210):
            if i < len(lines):
                marker = "  <-- TRUNCATION" if i == 198 else ""
                print(f"    {i+1}: {lines[i].rstrip()}{marker}")


if __name__ == "__main__":
    main()
