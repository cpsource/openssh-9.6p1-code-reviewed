#!/usr/bin/env python3
"""
PoC #13 — kex_from_blob() Hardcodes kex->server = 1
=====================================================
Finding : INFO  (README-sshd-security-flaws.md #18)
File    : packet.c:2436
Branch  : master

Vulnerability
-------------
kex_from_blob() deserialises the key-exchange state from the privsep blob
and unconditionally sets kex->server = 1, regardless of the actual role
of the process that is calling it:

    static int
    kex_from_blob(struct sshbuf *m, struct kex **kexp)
    {
        struct kex *kex;
        ...
        if ((r = sshbuf_get_u32(m, &kex->flags)) != 0)
            goto out;
        kex->server = 1;    /* <-- always 1, no parameter, no assertion */
        kex->done = 1;
        ...
    }

Compare with ssh_packet_set_server() at packet.c:2212-2217, which sets
both flags together and even carries a "XXX unify?" comment hinting the
developer noticed the inconsistency:

    void ssh_packet_set_server(struct ssh *ssh) {
        ssh->state->server_side = 1;
        ssh->kex->server = 1;   /* XXX unify? */
    }

kex_from_blob() sets kex->server but does NOT set state->server_side.

Why kex->server matters
-----------------------
kex->server is tested in at least 15 places in kex.c to control:
  - Which side sends KEXINIT first
  - Algorithm list direction (client-to-server vs server-to-client)
  - Whether SSH_MSG_EXT_INFO is sent (server: after NEWKEYS, client: later)
  - Version banner send order
  - Compat flags checked (SSH_BUG_PROBE, SSH_BUG_SCANNER — server-only)
  - Key derivation direction (ctos / stoc)

If kex_from_blob() were ever called in a client-side context, kex->server=1
would silently flip all of these decisions to server mode — corrupting
algorithm negotiation without any assertion failure or error message.

Current call graph
------------------
  ssh_packet_set_state()          <- called only in monitor (server side)
    kex_from_blob()               <- therefore always correct today

This PoC:
  1. Scans the source to show the hardcoded assignment.
  2. Lists all call sites of kex->server in kex.c to show the blast radius.
  3. Compares with ssh_packet_set_server() which sets both fields.
  4. Demonstrates with a C reproducer that a client calling kex_from_blob
     would have its role silently misconfigured.
"""

import os
import re
import sys
import subprocess
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * Stub kex struct — enough to show the role misconfiguration.
 */
typedef struct {
    int server;       /* 1 = server side, 0 = client side */
    int done;
    uint32_t flags;
    /* ... real kex has many more fields ... */
} fake_kex_t;

/*
 * Mirror of the relevant part of kex_from_blob() (packet.c:2416-2449).
 * The blob parsing is simplified; the key line is kex->server = 1.
 */
static void
kex_from_blob_mirror(fake_kex_t *kex, int actual_is_server)
{
    /* ... parse we_need, hostkey_alg, kex_type, etc. from blob ... */

    kex->server = 1;   /* packet.c:2436 — always 1, ignores actual_is_server */
    kex->done   = 1;
}

/*
 * Mirror of ssh_packet_set_server() (packet.c:2212-2217).
 */
static void
ssh_packet_set_server_mirror(fake_kex_t *kex, int *state_server_side,
    int is_server)
{
    *state_server_side = is_server;   /* sets state->server_side correctly */
    kex->server = is_server;          /* sets kex->server correctly */
    /* "XXX unify?" comment in the real source at packet.c:2216 */
}

/*
 * Illustrate the decisions that depend on kex->server in kex.c.
 */
static void
show_kex_decisions(const fake_kex_t *kex, const char *label)
{
    printf("  [%s]  kex->server = %d\n", label, kex->server);
    printf("    KEXINIT first sender  : %s\n",
           kex->server ? "server" : "client");
    printf("    Algorithm dir ctos    : %s (mode==OUT means %s)\n",
           kex->server ? "MODE_IN is ctos" : "MODE_OUT is ctos",
           kex->server ? "receive" : "send");
    printf("    SSH_MSG_EXT_INFO sent : %s\n",
           kex->server ? "immediately after NEWKEYS" : "after auth service accepted");
    printf("    Compat bug probe check: %s\n",
           kex->server ? "yes (SSH_BUG_PROBE, SSH_BUG_SCANNER)" : "no");
    printf("    Banner send side      : %s sends first\n",
           kex->server ? "server" : "client");
}

int
main(void)
{
    printf("=== PoC #13: kex->server hardcoded in kex_from_blob() (packet.c:2436) ===\n\n");

    /* Scenario: a CLIENT process calls kex_from_blob() */
    fake_kex_t kex_client;
    memset(&kex_client, 0, sizeof(kex_client));

    int state_server_side = 0;

    printf("--- Correct path: ssh_packet_set_server() called on client (is_server=0) ---\n");
    ssh_packet_set_server_mirror(&kex_client, &state_server_side, 0);
    printf("  state->server_side = %d  kex->server = %d\n\n",
           state_server_side, kex_client.server);
    show_kex_decisions(&kex_client, "correct");

    printf("\n--- Buggy path: kex_from_blob() called on same client ---\n");
    kex_from_blob_mirror(&kex_client, 0 /* actual_is_server=0: we are a client */);
    printf("  state->server_side = %d (unchanged)  kex->server = %d (WRONG!)\n\n",
           state_server_side, kex_client.server);
    show_kex_decisions(&kex_client, "after kex_from_blob");

    printf("\n--- Inconsistency ---\n");
    printf("  state->server_side = %d  (says: client)\n", state_server_side);
    printf("  kex->server        = %d  (says: server  <- WRONG)\n", kex_client.server);
    printf("\n  kex.c uses kex->server for ~15 decisions.\n");
    printf("  state->server_side is used by packet.c for other decisions.\n");
    printf("  The two fields are now inconsistent — silent misbehaviour.\n\n");

    printf("--- Fix ---\n");
    printf("  Pass role as a parameter:\n");
    printf("    kex_from_blob(m, kexp, is_server)\n");
    printf("  and assign:\n");
    printf("    kex->server = is_server;\n");
    printf("  Or add:\n");
    printf("    KASSERT(is_monitor, \"kex_from_blob called outside monitor\");\n");

    return 0;
}
"""


def scan_source():
    """Show the relevant source lines from the repo."""
    packet_c = os.path.join(REPO_ROOT, "packet.c")
    kex_c    = os.path.join(REPO_ROOT, "kex.c")

    print("[*] Finding #1: kex->server = 1 hardcode in kex_from_blob():")
    with open(packet_c) as f:
        for i, line in enumerate(f, 1):
            if "kex->server" in line and ("= 1" in line or "= 0" in line):
                print(f"    packet.c:{i}: {line.rstrip()}")
    print()

    print("[*] Finding #2: ssh_packet_set_server() sets BOTH fields:")
    with open(packet_c) as f:
        lines = f.readlines()
    for i, line in enumerate(lines, 1):
        if "ssh_packet_set_server" in line or \
           ("server_side" in line and i > 2210 and i < 2225) or \
           ("kex->server = 1" in line and i > 2210 and i < 2225):
            print(f"    packet.c:{i}: {line.rstrip()}")
    print()

    print("[*] Finding #3: kex->server controls these decisions in kex.c")
    print("    (all sites where the server/client role is branched on):")
    with open(kex_c) as f:
        for i, line in enumerate(f, 1):
            if re.search(r'kex->server\b', line) and ("?" in line or "if" in line):
                print(f"    kex.c:{i}: {line.rstrip()}")
    print()


def main():
    print("=" * 60)
    print("PoC #13 — kex->server hardcoded in kex_from_blob()")
    print("=" * 60)
    print()

    # Part 1: source scan
    try:
        scan_source()
    except Exception as e:
        print(f"[~] Source scan failed: {e}")
        print()

    # Part 2: C reproducer
    print("[*] C reproducer: demonstrates the inconsistency when a client")
    print("    process would call kex_from_blob().")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc13.c")
        bin_ = os.path.join(tmpdir, "poc13")

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

    print("[*] Current call graph (why this is currently safe):")
    print("    ssh_packet_set_state()  <- called only in the monitor process")
    print("      kex_from_blob()       <- monitor is always the server side")
    print("    The monitor never calls kex_from_blob() as a client, so")
    print("    kex->server = 1 is always correct today.")
    print()
    print("[*] Risk: no assertion documents this constraint. A future")
    print("    client-side privsep or mux refactoring could call")
    print("    ssh_packet_set_state() / kex_from_blob() as a client,")
    print("    silently misconfiguring the kex role with no error.")


if __name__ == "__main__":
    main()
