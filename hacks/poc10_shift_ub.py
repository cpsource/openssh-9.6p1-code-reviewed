#!/usr/bin/env python3
"""
PoC #10 — Shift Undefined Behaviour in Rekey Block-Limit Calculation
=====================================================================
Finding : INFO  (README-sshd-security-flaws.md #20)
File    : packet.c:946
Branch  : master

Vulnerability
-------------
When new session keys are installed, packet.c computes a per-direction
block limit to trigger rekeying (RFC 4344 §3.2):

    if (enc->block_size >= 16)
        *max_blocks = (u_int64_t)1 << (enc->block_size * 2);   /* line 946 */
    else
        *max_blocks = ((u_int64_t)1 << 30) / enc->block_size;

For enc->block_size = 32, the shift amount is 64.  Shifting a 64-bit
integer by 64 or more positions is undefined behaviour in C
(C11 §6.5.7 paragraph 3: "the result is undefined" if the right operand
is greater than or equal to the width of the promoted left operand).

On x86-64 with gcc/clang, the common observed behaviours are:
  - shift by 64 produces the original value (1 or 0, compiler-dependent)
  - shift by 128 wraps modulo 64, producing 1 << 0 = 1

These produce absurdly small max_blocks values, causing sshd to rekey
after every single block — effectively a denial of service against the
connection once a cipher with a large block size is in use.

No cipher in the current SSH2 suite has block_size >= 32 (AES uses 16).
The guard (>= 16) does not prevent future cipher registrations from
triggering the UB silently.

This PoC:
  1. Compiles the expression for block_size values 8..40.
  2. Flags the undefined-behaviour cases.
  3. Re-compiles with -fsanitize=undefined to show UBSAN detection.
"""

import os
import sys
import subprocess
import tempfile

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

/*
 * Reproduce packet.c:945-948:
 *
 *   if (enc->block_size >= 16)
 *       *max_blocks = (u_int64_t)1 << (enc->block_size * 2);
 *   else
 *       *max_blocks = ((u_int64_t)1 << 30) / enc->block_size;
 */
static uint64_t
compute_max_blocks(int block_size)
{
    uint64_t max_blocks;
    if (block_size >= 16)
        max_blocks = (uint64_t)1 << (block_size * 2);   /* UB if block_size>=32 */
    else
        max_blocks = ((uint64_t)1 << 30) / (uint64_t)block_size;
    return max_blocks;
}

int
main(void)
{
    printf("=== PoC #10: shift UB in rekey block-limit (packet.c:946) ===\n\n");
    printf("C11 §6.5.7p3: shifting a 64-bit type by >= 64 is undefined behaviour.\n\n");
    printf("%-14s  %-8s  %-22s  %s\n",
           "block_size", "shift", "max_blocks (observed)", "status");
    printf("%-14s  %-8s  %-22s  %s\n",
           "──────────", "──────", "─────────────────────", "──────");

    for (int bs = 8; bs <= 40; bs += 4) {
        int shift = bs * 2;
        uint64_t result = compute_max_blocks(bs);
        const char *status;

        if (bs < 16)
            status = "OK (small-block path)";
        else if (shift < 64)
            status = "OK";
        else if (shift == 64)
            status = "*** UB: shift == bit-width (C11 §6.5.7) ***";
        else
            status = "*** UB: shift > bit-width  (C11 §6.5.7) ***";

        printf("%-14d  %-8d  %-22" PRIu64 "  %s\n",
               bs, shift, result, status);

        if (shift >= 64 && result <= 1) {
            printf("              [+] max_blocks=%llu — rekeying after every block!\n",
                   (unsigned long long)result);
        }
    }

    printf("\n");
    printf("Notes:\n");
    printf("  * AES block_size = 16  -> shift = 32 -> max_blocks = 2^32  (OK)\n");
    printf("  * No current SSH2 cipher has block_size >= 32.\n");
    printf("  * The guard (>= 16) does not prevent a future cipher with\n");
    printf("    block_size=32 from reaching the UB expression silently.\n");
    printf("  * Compilers may optimise assuming UB never occurs, potentially\n");
    printf("    miscompiling surrounding logic (dead-code elimination, etc.).\n");
    printf("\n  Fix:\n");
    printf("    if (enc->block_size >= 16 && enc->block_size < 32)\n");
    printf("        *max_blocks = (u_int64_t)1 << (enc->block_size * 2);\n");
    printf("    else if (enc->block_size >= 32)\n");
    printf("        *max_blocks = UINT64_MAX;  /* rely on rekey_limit instead */\n");

    return 0;
}
"""


def run_with_flags(src, bin_, extra_flags, label):
    flags = ["cc", "-O2"] + extra_flags + ["-o", bin_, src, "-Wall"]
    r = subprocess.run(flags, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[!] Compilation with {label} failed:\n{r.stderr}")
        return False

    print(f"[*] Running with {label}:")
    r = subprocess.run([bin_], capture_output=True, text=True)
    print(r.stdout)
    if r.stderr:
        # UBSAN writes runtime errors to stderr
        lines = r.stderr.strip().splitlines()
        for line in lines:
            print(f"    [UBSAN] {line}")
        print()
    return True


def main():
    print("=" * 60)
    print("PoC #10 — Shift UB in rekey block-limit (packet.c:946)")
    print("=" * 60)
    print()
    print("[*] Compiles the shift expression for block_size 8..40 and")
    print("    flags the undefined-behaviour cases.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc10.c")
        bin_ = os.path.join(tmpdir, "poc10")
        bin_ubsan = os.path.join(tmpdir, "poc10_ubsan")

        with open(src, "w") as f:
            f.write(C_REPRODUCER)

        # Pass 1: plain compilation
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

        # Pass 2: with UBSAN (may not be available on all platforms)
        r2 = subprocess.run(
            ["cc", "-O1", "-fsanitize=undefined", "-fno-sanitize-recover=all",
             "-o", bin_ubsan, src],
            capture_output=True, text=True,
        )
        if r2.returncode == 0:
            print("[*] Re-running with -fsanitize=undefined to confirm UB detection:")
            r3 = subprocess.run(
                [bin_ubsan], capture_output=True, text=True,
                env={**os.environ, "UBSAN_OPTIONS": "print_stacktrace=0"},
            )
            # Print stdout as normal output
            # UBSAN runtime errors go to stderr
            if r3.stdout:
                # Only print the UB-flagged rows for brevity
                for line in r3.stdout.splitlines():
                    if "UB" in line or "shift" in line.lower() or ">>>" in line:
                        print(f"    {line}")
            if r3.stderr:
                for line in r3.stderr.strip().splitlines():
                    print(f"    [UBSAN] {line}")
                print()
                print("[+] UBSAN confirmed: shift UB detected at runtime.")
            else:
                print("    (UBSAN detected no runtime errors on this platform —")
                print("     may indicate the compiler optimised around the UB.)")
        else:
            print("[~] -fsanitize=undefined not available; skipping UBSAN pass.")
            if r2.stderr:
                print(f"    {r2.stderr.splitlines()[0]}")


if __name__ == "__main__":
    main()
