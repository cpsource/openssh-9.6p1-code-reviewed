#!/usr/bin/env python3
"""
PoC #18 — `long len` Silently Truncated to UINT32 at nh_update() Boundary
==========================================================================
Finding : INFO  (README-sshd-security-flaws.md #26)
File    : umac.c:1044 (uhash_update()), umac.c:613 (nh_update())
Branch  : master

Vulnerability
-------------
The public-facing umac_update() and internal uhash_update() both accept
a `long len`, but the innermost function nh_update() takes `UINT32 nbytes`:

    /* umac.c:1255 */
    int umac_update(struct umac_ctx *ctx, const u_char *input, long len)
        /* calls → */

    /* umac.c:1044 */
    static int uhash_update(uhash_ctx_t ctx, const u_char *input, long len)
        /* calls → */

    /* umac.c:613 */
    static void nh_update(nh_ctx *hc, const UINT8 *buf, UINT32 nbytes)
        /*                                                ^^^^^^
         * implicit conversion: long → UINT32
         * if len > 4 GB, nbytes = len & 0xFFFFFFFF (low 32 bits only)
         */

If `len` were greater than UINT32_MAX (4,294,967,295 ≈ 4 GB), the implicit
conversion to UINT32 would silently discard the high 32 bits, causing
nh_update() to process fewer bytes than requested.  The resulting MAC would
be computed over a truncated message with no error indication — a MAC that
appears valid but covers less data than intended.

In addition, uhash_update() accumulates the total in a UINT32 msg_len field:
    ctx->msg_len += len;   /* UINT32 += long: wraps at 4 GB */

A wrap in msg_len would cause the short-message (ip_short) vs long-message
(ip_long) dispatch to behave incorrectly for messages that straddle the
UINT32 boundary.

Current safety:
  SSH limits packets to PACKET_MAX_SIZE (~256 KB), so `len` passed to
  umac_update() is always well within UINT32_MAX.  This is unreachable.

This PoC:
  1. Shows the implicit long → UINT32 truncation at the call boundary.
  2. Demonstrates how msg_len wraps at UINT32_MAX.
  3. Shows the short-vs-long dispatch flipping at the wrap boundary.
  4. Confirms the SSH safety margin (PACKET_MAX_SIZE << UINT32_MAX).
"""

import os
import sys
import subprocess
import tempfile

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

/* ------------------------------------------------------------------ */
/* Reproduce the type mismatch across the call stack                   */
/* ------------------------------------------------------------------ */

#define L1_KEY_LEN  1024     /* same as umac.c */

/* Mirror of nh_update()'s first action: receive UINT32 nbytes */
static void
nh_update_mirror(uint32_t nbytes, long original_len)
{
    if ((long)nbytes != original_len) {
        printf("  [+] TRUNCATION: long len=%ld truncated to UINT32 nbytes=%u\n",
               original_len, nbytes);
        printf("      Bytes that would be LOST: %ld\n",
               original_len - (long)nbytes);
    } else {
        printf("  [-] No truncation (len fits in UINT32)\n");
    }
}

/* Mirror of uhash_update()'s msg_len accumulation */
typedef struct {
    uint32_t msg_len;
} fake_uhash_ctx;

static void
uhash_update_mirror(fake_uhash_ctx *ctx, long len, long original_total)
{
    ctx->msg_len += (uint32_t)len;   /* umac.c:1058 / 1074 / 1084 / 1094 */
    /* Check for the short-vs-long dispatch threshold */
    int prev_short = (original_total              <= L1_KEY_LEN);
    int new_short  = (ctx->msg_len                <= L1_KEY_LEN);
    (void)prev_short;
    if (!new_short) {
        /* long message path: poly_hash() will be invoked */
    }
}

int
main(void)
{
    printf("=== PoC #18: long→UINT32 truncation at nh_update() (umac.c:613) ===\n\n");

    /* ---------------------------------------------------------------- */
    /* Part 1: show the truncation for various len values                */
    /* ---------------------------------------------------------------- */
    printf("--- Part 1: implicit long→UINT32 truncation ---\n\n");

    struct { long len; const char *label; } cases[] = {
        { 256 * 1024,          "256 KB (PACKET_MAX_SIZE) — safe"        },
        { (long)UINT32_MAX,    "UINT32_MAX (4 GB) — boundary"           },
        { (long)UINT32_MAX + 1,"UINT32_MAX + 1 — first truncation"      },
        { (long)UINT32_MAX + L1_KEY_LEN + 1, "UINT32_MAX + 1025 — wraps to 1 KB" },
        { (long)2 * UINT32_MAX, "2 * UINT32_MAX — wraps to UINT32_MAX-1" },
    };

    for (int i = 0; i < (int)(sizeof cases / sizeof cases[0]); i++) {
        long   len    = cases[i].len;
        uint32_t u32  = (uint32_t)len;   /* the implicit conversion */
        printf("  len = %20ld  (%-38s)\n"
               "  → UINT32 nbytes = %10u  ",
               len, cases[i].label, u32);
        nh_update_mirror(u32, len);
    }
    printf("\n");

    /* ---------------------------------------------------------------- */
    /* Part 2: msg_len UINT32 wrap and dispatch flip                     */
    /* ---------------------------------------------------------------- */
    printf("--- Part 2: UINT32 msg_len wrap affects dispatch ---\n\n");
    printf("  The dispatch in uhash_final() (umac.c:1109):\n");
    printf("    if (ctx->msg_len > L1_KEY_LEN) → ip_long (poly hash used)\n");
    printf("    else                           → ip_short (poly hash skipped)\n\n");

    /* Show what happens when msg_len crosses UINT32 boundary */
    fake_uhash_ctx ctx = { .msg_len = UINT32_MAX - 512 };
    long remaining = 1024;  /* a normal 1 KB update */
    long orig_total = (long)ctx.msg_len + remaining;

    printf("  Before update: msg_len = %u (0x%08X)\n", ctx.msg_len, ctx.msg_len);
    printf("  Adding len = %ld bytes...\n", remaining);

    uint32_t before = ctx.msg_len;
    ctx.msg_len += (uint32_t)remaining;
    printf("  After update:  msg_len = %u (0x%08X)  %s\n",
           ctx.msg_len, ctx.msg_len,
           ctx.msg_len < before ? "[+] WRAPPED!" : "");

    int dispatch_before = (before        > L1_KEY_LEN) ? 1 : 0;  /* long */
    int dispatch_after  = (ctx.msg_len   > L1_KEY_LEN) ? 1 : 0;  /* short or long */
    int dispatch_correct = (orig_total   > L1_KEY_LEN) ? 1 : 0;  /* what it should be */

    printf("  Dispatch before wrap: %-5s (msg_len=%u > %d)\n",
           dispatch_before ? "ip_long" : "ip_short", before, L1_KEY_LEN);
    printf("  Dispatch after  wrap: %-5s (msg_len=%u > %d)\n",
           dispatch_after ? "ip_long" : "ip_short", ctx.msg_len, L1_KEY_LEN);
    printf("  Correct  dispatch:    %-5s (true total=%ld > %d)\n",
           dispatch_correct ? "ip_long" : "ip_short", orig_total, L1_KEY_LEN);

    if (dispatch_after != dispatch_correct)
        printf("  [+] DISPATCH FLIPPED — wrong MAC function selected!\n");
    else
        printf("  [-] Dispatch unchanged in this example.\n");

    /* ---------------------------------------------------------------- */
    /* Part 3: SSH safety margin                                         */
    /* ---------------------------------------------------------------- */
    printf("\n--- Part 3: SSH safety margin ---\n\n");
    printf("  PACKET_MAX_SIZE           = %u bytes (256 KB)\n", 256 * 1024u);
    printf("  UINT32_MAX                = %u bytes (4 GB)\n", UINT32_MAX);
    printf("  Ratio (UINT32_MAX / pkt)  = %.1f×\n",
           (double)UINT32_MAX / (256.0 * 1024));
    printf("  Truncation unreachable in SSH — each umac_update() call\n");
    printf("  receives at most one packet payload (≤ 256 KB).\n\n");
    printf("  Fix: change nh_update()'s parameter from UINT32 to size_t,\n");
    printf("  add an upper-bound check in uhash_update() / umac_update(),\n");
    printf("  or add a static_assert that PACKET_MAX_SIZE <= UINT32_MAX.\n");

    return 0;
}
"""


def main():
    print("=" * 60)
    print("PoC #18 — long→UINT32 truncation at nh_update() (umac.c:613)")
    print("=" * 60)
    print()
    print("[*] Demonstrates the implicit long→UINT32 conversion at the")
    print("    nh_update() call boundary and the UINT32 msg_len wrap that")
    print("    would flip the ip_short/ip_long dispatch for 4 GB+ inputs.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc18.c")
        bin_ = os.path.join(tmpdir, "poc18")

        with open(src, "w") as f:
            f.write(C_REPRODUCER)

        r = subprocess.run(
            ["cc", "-O2", "-o", bin_, src, "-Wall", "-Wconversion"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"[!] Compilation failed:\n{r.stderr}")
            sys.exit(1)

        if r.stderr:
            print("[*] -Wconversion warnings (compiler sees the type mismatch):")
            for line in r.stderr.strip().splitlines():
                print(f"    {line}")
            print()
        else:
            print("[*] No -Wconversion warnings (cast is explicit in the PoC).")
            print()

        print("[*] Compiled reproducer OK\n")
        r2 = subprocess.run([bin_], capture_output=True, text=True)
        print(r2.stdout)
        if r2.stderr:
            print(r2.stderr, file=sys.stderr)

    # Show the relevant source lines
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    umac_c = os.path.join(repo_root, "umac.c")
    if os.path.exists(umac_c):
        print("[*] Call-stack signatures in umac.c:")
        with open(umac_c) as f:
            lines = f.readlines()
        targets = {
            1255: "umac_update() — public API",
            1043: "uhash_update() — long len",
            613:  "nh_update() — UINT32 nbytes (truncation point)",
        }
        for lineno, label in sorted(targets.items()):
            i = lineno - 1
            if i < len(lines):
                print(f"    {lineno}: {lines[i].rstrip()}")
                print(f"         ^^ {label}")


if __name__ == "__main__":
    main()
