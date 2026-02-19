#!/usr/bin/env python3
"""
PoC #11 — Cipher Key/IV Lengths Not Validated in newkeys_from_blob()
=====================================================================
Finding : LOW  (README-sshd-security-flaws.md #21)
File    : packet.c:2375-2404
Branch  : master

Vulnerability
-------------
newkeys_from_blob() deserialises key material from the privilege-separation
state blob.  It validates the MAC key length against the algorithm's
expected length, but silently accepts any cipher key or IV length:

    /* MAC key — IS validated (packet.c:2390-2393) */
    if ((r = sshbuf_get_string(b, &mac->key, &maclen)) != 0)
        goto out;
    if (maclen > mac->key_len) {          /* <-- range check present */
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }
    mac->key_len = maclen;

    /* Cipher key and IV — NOT validated (packet.c:2403-2404) */
    enc->key_len = keylen;                /* <-- blindly accepted */
    enc->iv_len  = ivlen;                 /* <-- blindly accepted */

enc->key_len and enc->iv_len are later passed directly to cipher_init().
A mismatch between the blob value and the cipher's expectation results in
the cipher being initialised with the wrong key size:

  * keylen < expected: cipher is initialised with a too-short key
    (bytes beyond keylen are uninitialised in the cipher state).
  * keylen > expected: cipher is initialised with a truncated key
    (only expected_len bytes are consumed; the rest are silently ignored
    depending on the OpenSSL EVP implementation).
  * ivlen mismatch: same effects on the IV.

Attack surface
--------------
The blob is written by the monitor (privileged) and read in the network
child after the privsep handoff.  Tampering requires compromising the
network child process and injecting a crafted blob through the privsep
socket.  While a high bar, this is a defence-in-depth gap — especially
since the MAC key IS protected.

This PoC mirrors the newkeys_from_blob() validation logic in C and
demonstrates:
  1. MAC key validation catches mismatched lengths.
  2. Cipher key and IV length mismatches pass through without error.
  3. The resulting enc->key_len / enc->iv_len seen by cipher_init() is wrong.
"""

import os
import sys
import subprocess
import tempfile

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * Expected key and IV lengths for common SSH2 ciphers.
 */
typedef struct {
    const char *name;
    size_t expected_key_len;
    size_t expected_iv_len;
    size_t mac_key_len;       /* if not AEAD */
} cipher_info_t;

static const cipher_info_t ciphers[] = {
    { "aes128-ctr",           16, 16, 20 },   /* hmac-sha1 */
    { "aes256-ctr",           32, 16, 20 },
    { "aes128-gcm@openssh.com", 16, 12, 0  }, /* AEAD, no separate MAC */
    { "chacha20-poly1305@openssh.com", 64, 0, 0 }, /* AEAD */
    { NULL, 0, 0, 0 }
};

/*
 * Mirror of the relevant section of newkeys_from_blob() (packet.c:2372-2404).
 * Returns 0 on success, -1 on SSH_ERR_INVALID_FORMAT.
 */
static int
simulate_newkeys_parse(const char *cipher_name,
    size_t key_len_from_blob, size_t iv_len_from_blob,
    size_t mac_len_from_blob,
    size_t *out_key_len, size_t *out_iv_len)
{
    const cipher_info_t *ci = NULL;
    for (int i = 0; ciphers[i].name; i++) {
        if (strcmp(ciphers[i].name, cipher_name) == 0) {
            ci = &ciphers[i];
            break;
        }
    }
    if (!ci) {
        printf("  [err] unknown cipher %s\n", cipher_name);
        return -1;
    }

    /* ------------------------------------------------------------------ */
    /* MAC key — packet.c:2390-2393: IS validated                          */
    /* ------------------------------------------------------------------ */
    if (ci->mac_key_len > 0) {
        if (mac_len_from_blob > ci->mac_key_len) {
            printf("  [CAUGHT] MAC key length mismatch: blob=%zu expected<=%zu"
                   " -> SSH_ERR_INVALID_FORMAT\n",
                   mac_len_from_blob, ci->mac_key_len);
            return -1;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Cipher key / IV — packet.c:2403-2404: NOT validated                 */
    /* ------------------------------------------------------------------ */
    *out_key_len = key_len_from_blob;  /* silently accepted */
    *out_iv_len  = iv_len_from_blob;   /* silently accepted */

    return 0;
}

static void
test_case(const char *label,
    const char *cipher_name,
    size_t key_from_blob, size_t iv_from_blob,
    size_t mac_from_blob)
{
    const cipher_info_t *ci = NULL;
    for (int i = 0; ciphers[i].name; i++) {
        if (strcmp(ciphers[i].name, cipher_name) == 0) {
            ci = &ciphers[i];
            break;
        }
    }

    size_t out_key = 0, out_iv = 0;
    printf("Test: %s\n", label);
    printf("  Cipher: %s  (expected key=%zu iv=%zu mac<=%zu)\n",
           cipher_name,
           ci ? ci->expected_key_len : 0,
           ci ? ci->expected_iv_len  : 0,
           ci ? ci->mac_key_len      : 0);
    printf("  Blob:   key=%zu iv=%zu mac=%zu\n",
           key_from_blob, iv_from_blob, mac_from_blob);

    int rc = simulate_newkeys_parse(cipher_name,
        key_from_blob, iv_from_blob, mac_from_blob,
        &out_key, &out_iv);

    if (rc == 0) {
        printf("  Result: enc->key_len=%zu  enc->iv_len=%zu\n",
               out_key, out_iv);
        if (ci) {
            int key_mismatch = (out_key != ci->expected_key_len);
            int iv_mismatch  = ci->expected_iv_len > 0 &&
                               (out_iv != ci->expected_iv_len);
            if (key_mismatch)
                printf("  [+] ISSUE: cipher_init() will receive key_len=%zu "
                       "but cipher expects %zu — silent mismatch!\n",
                       out_key, ci->expected_key_len);
            if (iv_mismatch)
                printf("  [+] ISSUE: cipher_init() will receive iv_len=%zu "
                       "but cipher expects %zu — silent mismatch!\n",
                       out_iv, ci->expected_iv_len);
            if (!key_mismatch && !iv_mismatch)
                printf("  [-] Key/IV lengths matched expected (no issue).\n");
        }
    }
    printf("\n");
}

int
main(void)
{
    printf("=== PoC #11: newkeys_from_blob() key/IV length validation (packet.c:2375) ===\n\n");

    /* Case 1: correct lengths — baseline */
    test_case("Correct lengths (baseline)",
        "aes128-ctr", 16, 16, 20);

    /* Case 2: cipher key too short — passes silently */
    test_case("Cipher key too short (8 instead of 16)",
        "aes128-ctr", 8, 16, 20);

    /* Case 3: cipher key too long — passes silently */
    test_case("Cipher key too long (32 instead of 16)",
        "aes128-ctr", 32, 16, 20);

    /* Case 4: IV too short — passes silently */
    test_case("IV too short (8 instead of 16)",
        "aes128-ctr", 16, 8, 20);

    /* Case 5: MAC key too long — IS caught */
    test_case("MAC key too long (CAUGHT)",
        "aes128-ctr", 16, 16, 64);

    /* Case 6: aes256-ctr with aes128-ctr key length — passes silently */
    test_case("aes256-ctr with 16-byte key (should be 32)",
        "aes256-ctr", 16, 16, 20);

    printf("Summary:\n");
    printf("  MAC key:    validated against expected length  (SSH_ERR_INVALID_FORMAT on mismatch)\n");
    printf("  Cipher key: NOT validated — blob value stored as-is\n");
    printf("  Cipher IV:  NOT validated — blob value stored as-is\n\n");
    printf("  Fix: after cipher_by_name(), check:\n");
    printf("    if (keylen != cipher_keylen(enc->cipher) ||\n");
    printf("        ivlen  != cipher_ivlen(enc->cipher)) {\n");
    printf("        r = SSH_ERR_INVALID_FORMAT;\n");
    printf("        goto out;\n");
    printf("    }\n");

    return 0;
}
"""


def main():
    print("=" * 60)
    print("PoC #11 — Cipher key/IV not validated in newkeys_from_blob")
    print("=" * 60)
    print()
    print("[*] Mirrors the newkeys_from_blob() validation logic from")
    print("    packet.c:2375-2404 and demonstrates the asymmetry:")
    print("    MAC key lengths are validated; cipher key/IV are not.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc11.c")
        bin_ = os.path.join(tmpdir, "poc11")

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

    print("[*] Context:")
    print("    The blob is written by the privileged monitor and consumed")
    print("    in ssh_packet_set_state() during the privsep handoff.")
    print("    Tampering requires a compromised network child process.")
    print("    The asymmetry (MAC validated, cipher not) is the core issue.")


if __name__ == "__main__":
    main()
