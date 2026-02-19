#!/usr/bin/env python3
"""
PoC #15 — Signed Integer Overflow in nh_final() — `bytes_hashed << 3`
=======================================================================
Finding : INFO  (README-sshd-security-flaws.md #23)
File    : umac.c:692
Branch  : master

Vulnerability
-------------
In nh_final() (umac.c:692), the total bytes hashed is converted to bits
by left-shifting a *signed int*:

    int nh_len, nbits;                  /* 'nbits' is signed int */
    ...
    nbits = (hc->bytes_hashed << 3);   /* UB if bytes_hashed > 2^28 */

Left-shifting a signed integer when the result would not fit in the type
(i.e. when bytes_hashed * 8 > INT_MAX) is undefined behaviour per
C11 §6.5.7p4.  At bytes_hashed = 2^28 (256 MB) the shift overflows the
signed int and the resulting nbits value is implementation-defined — on
x86-64 the bit pattern wraps to a negative number.  This corrupted nbits
value is then added to every NH state accumulator, producing a wrong hash.

Contrast with the companion function nh() (umac.c:718):

    UINT32 nbits;                      /* unsigned */
    nbits = (unpadded_len << 3);       /* well-defined up to 512 MB */

The inconsistency (int vs UINT32) between the two functions that perform
the same computation is the root cause.

Current safety:
  bytes_hashed is reset by nh_reset() after each 1024-byte chunk, so its
  value never exceeds 1024 in practice.  The UB is unreachable given SSH's
  PACKET_MAX_SIZE limit.

This PoC:
  1. Shows the UB expression for bytes_hashed values from 0 to 2^30.
  2. Flags the threshold (2^28) where overflow begins.
  3. Re-compiles with -fsanitize=undefined to confirm UBSAN detection.
  4. Contrasts with the UINT32 version which handles the same range safely.
"""

import os
import sys
import subprocess
import tempfile

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>

/*
 * Mirror of nh_final() line 692:
 *   int nbits;
 *   nbits = (hc->bytes_hashed << 3);
 */
static int
nbits_signed(int bytes_hashed)
{
    return (bytes_hashed << 3);   /* UB if bytes_hashed > INT_MAX/8 */
}

/*
 * The correct version — as used in nh() at line 718:
 *   UINT32 nbits;
 *   nbits = (unpadded_len << 3);
 */
static uint32_t
nbits_unsigned(uint32_t bytes_hashed)
{
    return (bytes_hashed << 3);   /* well-defined for bytes_hashed <= 512MB */
}

int
main(void)
{
    printf("=== PoC #15: nh_final() bytes_hashed<<3 signed UB (umac.c:692) ===\n\n");
    printf("C11 §6.5.7p4: left-shift of signed int into/past sign bit is UB.\n");
    printf("INT_MAX = %d (0x%08X)\n", INT_MAX, INT_MAX);
    printf("Overflow threshold: bytes_hashed > INT_MAX/8 = %d (= 2^%d - 1)\n\n",
           INT_MAX / 8, 28);

    /* Threshold is INT_MAX/8 = 2^28 - 1 for 32-bit int */
    int thresholds[] = {
        1024,           /* typical max in SSH (L1_KEY_LEN) */
        256 * 1024,     /* PACKET_MAX_SIZE */
        1 << 26,        /* 64 MB — still safe */
        1 << 27,        /* 128 MB — still safe */
        (1 << 28) - 1,  /* 256 MB - 1 — last safe value */
        1 << 28,        /* 256 MB — UB threshold */
        (1 << 28) + 1,  /* just over — UB */
        1 << 29,        /* 512 MB — UB */
        INT_MAX / 8,    /* exact boundary */
        INT_MAX / 8 + 1 /* one over boundary — UB */
    };
    const char *labels[] = {
        "1024 (L1_KEY_LEN, typical)",
        "256 KB (PACKET_MAX_SIZE)",
        "64 MB",
        "128 MB",
        "256 MB - 1 (last safe)",
        "256 MB (UB threshold)",
        "256 MB + 1 (UB)",
        "512 MB (UB)",
        "INT_MAX/8 (exact boundary)",
        "INT_MAX/8 + 1 (UB)"
    };

    printf("%-36s  %-14s  %-14s  %s\n",
           "bytes_hashed", "signed nbits", "uint32 nbits", "status");
    printf("%-36s  %-14s  %-14s  %s\n",
           "────────────────────────────────────",
           "────────────",
           "────────────",
           "──────");

    for (int i = 0; i < (int)(sizeof thresholds / sizeof thresholds[0]); i++) {
        int bh = thresholds[i];
        int signed_result   = nbits_signed(bh);
        uint32_t uint_result = nbits_unsigned((uint32_t)bh);
        int is_ub = (bh > INT_MAX / 8);
        const char *status = is_ub
            ? "*** UB: signed overflow ***"
            : "OK";

        printf("%-36s  %-14d  %-14u  %s\n",
               labels[i], signed_result, uint_result, status);

        if (is_ub && signed_result < 0) {
            printf("  [+] signed nbits is NEGATIVE (%d) — added to NH state\n"
                   "      accumulators → corrupts hash output!\n",
                   signed_result);
        }
    }

    printf("\nKey observation:\n");
    printf("  nh() (umac.c:718) uses UINT32 nbits  — correct for ≤ 512 MB.\n");
    printf("  nh_final() (umac.c:692) uses int nbits — UB above 256 MB.\n");
    printf("  Both compute the same value.  The type inconsistency is the bug.\n");
    printf("\n  In SSH: bytes_hashed is reset at ≤ 1024 bytes per call.  UB unreachable.\n");
    printf("  Fix: declare 'int nbits' as 'UINT32 nbits' in nh_final().\n");

    return 0;
}
"""


def main():
    print("=" * 60)
    print("PoC #15 — nh_final() bytes_hashed<<3 signed UB (umac.c:692)")
    print("=" * 60)
    print()
    print("[*] Shows the signed-int left-shift overflow threshold and")
    print("    contrasts with the UINT32 version in nh() (umac.c:718).")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc15.c")
        bin_ = os.path.join(tmpdir, "poc15")
        bin_ubsan = os.path.join(tmpdir, "poc15_ubsan")

        with open(src, "w") as f:
            f.write(C_REPRODUCER)

        r = subprocess.run(
            ["cc", "-O2", "-o", bin_, src, "-Wall"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"[!] Compilation failed:\n{r.stderr}")
            sys.exit(1)
        print("[*] Compiled OK\n")

        r = subprocess.run([bin_], capture_output=True, text=True)
        print(r.stdout)

        # UBSAN pass
        r2 = subprocess.run(
            ["cc", "-O1", "-fsanitize=undefined", "-fno-sanitize-recover=all",
             "-o", bin_ubsan, src],
            capture_output=True, text=True,
        )
        if r2.returncode == 0:
            print("[*] Re-running with -fsanitize=undefined:")
            r3 = subprocess.run(
                [bin_ubsan], capture_output=True, text=True,
                env={**os.environ, "UBSAN_OPTIONS": "print_stacktrace=0"},
            )
            if r3.stderr:
                for line in r3.stderr.strip().splitlines():
                    print(f"    [UBSAN] {line}")
                print()
                print("[+] UBSAN confirmed: signed left-shift UB detected.")
            else:
                print("    (UBSAN silent — compiler may have optimised around the UB.)")
        else:
            print("[~] -fsanitize=undefined not available; skipping UBSAN pass.")

    # Show the actual source lines
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    umac_c = os.path.join(repo_root, "umac.c")
    if os.path.exists(umac_c):
        print("\n[*] Source lines in umac.c:")
        with open(umac_c) as f:
            lines = f.readlines()
        print("    nh_final() — signed int (umac.c:677):")
        for i in range(676, 705):
            if i < len(lines) and ("nbits" in lines[i] or "bytes_hashed" in lines[i]):
                print(f"      {i+1}: {lines[i].rstrip()}")
        print()
        print("    nh() — UINT32 (umac.c:708):")
        for i in range(707, 733):
            if i < len(lines) and "nbits" in lines[i]:
                print(f"      {i+1}: {lines[i].rstrip()}")


if __name__ == "__main__":
    main()
