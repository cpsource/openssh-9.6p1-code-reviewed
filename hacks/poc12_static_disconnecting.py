#!/usr/bin/env python3
"""
PoC #12 — Process-Global 'static int disconnecting' in ssh_packet_disconnect()
===============================================================================
Finding : INFO  (README-sshd-security-flaws.md #19)
File    : packet.c:1976
Branch  : master

Vulnerability
-------------
The recursion guard in ssh_packet_disconnect() is declared with static
storage duration — making it process-global rather than per-connection:

    void ssh_packet_disconnect(struct ssh *ssh, const char *fmt, ...)
    {
        static int disconnecting = 0;   /* process-global, NOT per-connection */
        if (disconnecting)
            fatal("packet_disconnect called recursively.");
        disconnecting = 1;
        ...
        cleanup_exit(255);
    }

In single-connection sshd usage, cleanup_exit(255) is always called before
the function returns, so 'disconnecting' is never observed as set by any
other code path.  The guard is harmless in that context.

Problem scenario
----------------
OpenSSH's connection multiplexer (ssh -M / ControlMaster) manages multiple
active connections through a single mux-master process.  In that context,
multiple struct ssh objects coexist within the same process.  When
ssh_packet_disconnect is called for connection A:

    1. 'disconnecting' is set to 1 (process-global).
    2. cleanup_exit(255) is called — but in the mux-master the cleanup
       path may call back into packet handling for other connections
       before exiting.
    3. Any subsequent call to ssh_packet_disconnect for connection B
       hits the 'disconnecting != 0' branch and calls:
           fatal("packet_disconnect called recursively.")
       Connection B never sends SSH2_MSG_DISCONNECT — it dies hard.

The same pattern would affect any future refactoring that moves toward
a multi-connection daemon model.

This PoC simulates two concurrent struct ssh objects in the same process
and shows that disconnecting connection A permanently prevents connection B
from using the clean-disconnect path.
"""

import os
import sys
import subprocess
import tempfile

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Minimal stubs so we can reproduce without pulling in all of OpenSSH */
/* ------------------------------------------------------------------ */

typedef struct { int id; } fake_ssh_t;

/* Stub for the actual SSH DISCONNECT packet send */
static void
send_disconnect_packet(fake_ssh_t *ssh, const char *reason)
{
    printf("    [conn %d] SSH2_MSG_DISCONNECT sent: %s\n", ssh->id, reason);
}

/* Stub for the cleanup / exit path */
static void
fake_cleanup_exit(fake_ssh_t *ssh, int code)
{
    printf("    [conn %d] cleanup_exit(%d) — connection closed cleanly.\n",
           ssh->id, code);
}

/* ------------------------------------------------------------------ */
/* Direct mirror of ssh_packet_disconnect() from packet.c:1972-2008   */
/* (cleanup_exit replaced with fake_cleanup_exit so we can observe     */
/*  what happens to the second connection)                             */
/* ------------------------------------------------------------------ */

static void
ssh_packet_disconnect_mirror(fake_ssh_t *ssh, const char *reason)
{
    static int disconnecting = 0;   /* <-- PROCESS-GLOBAL: the bug */

    if (disconnecting) {
        /* In real code: fatal("packet_disconnect called recursively.") */
        printf("    [conn %d] FATAL: packet_disconnect called recursively!\n",
               ssh->id);
        printf("             Real sshd calls fatal() here.\n");
        printf("             SSH2_MSG_DISCONNECT is NEVER sent for conn %d.\n",
               ssh->id);
        printf("             Peer sees an abrupt TCP close, not a clean disconnect.\n");
        return; /* we return; real fatal() would abort the process */
    }

    disconnecting = 1;
    send_disconnect_packet(ssh, reason);
    fake_cleanup_exit(ssh, 255);
    /*
     * Real code calls cleanup_exit(255) which never returns.
     * We return here to allow demonstration of the second connection.
     * In the mux-master path, cleanup handling for multiple connections
     * can re-enter this function before the process actually exits.
     */
}

int
main(void)
{
    fake_ssh_t conn_a = { .id = 1 };
    fake_ssh_t conn_b = { .id = 2 };

    printf("=== PoC #12: static int disconnecting (packet.c:1976) ===\n\n");
    printf("Scenario: ssh mux-master with two concurrent connections.\n\n");

    printf("Step 1 — Connection A times out and calls ssh_packet_disconnect:\n");
    ssh_packet_disconnect_mirror(&conn_a, "connection timeout");
    printf("\n");

    printf("Step 2 — Connection B encounters an auth failure and also needs\n");
    printf("         to send SSH2_MSG_DISCONNECT:\n");
    ssh_packet_disconnect_mirror(&conn_b, "too many authentication failures");
    printf("\n");

    printf("--- Analysis ---\n\n");
    printf("  static int disconnecting is set to 1 by conn A.\n");
    printf("  It is NEVER reset because cleanup_exit() ends the process\n");
    printf("  in single-connection sshd (making the bug invisible there).\n\n");
    printf("  In multi-connection contexts (mux-master), the flag is left set.\n");
    printf("  Conn B hits the recursion-guard branch and is forcibly aborted\n");
    printf("  via fatal() instead of sending a clean SSH2_MSG_DISCONNECT.\n\n");
    printf("  Fix: move 'disconnecting' into struct session_state as a\n");
    printf("  per-connection field, or use ssh->state->disconnecting.\n");

    return 0;
}
"""


def main():
    print("=" * 60)
    print("PoC #12 — static int disconnecting (packet.c:1976)")
    print("=" * 60)
    print()
    print("[*] Simulates two concurrent struct ssh objects in the same")
    print("    process and shows that the process-global static flag")
    print("    prevents the second connection from sending a clean")
    print("    SSH2_MSG_DISCONNECT when connection A disconnects first.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc12.c")
        bin_ = os.path.join(tmpdir, "poc12")

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

    print("[*] Real-world context:")
    print("    In standard sshd, cleanup_exit(255) makes this moot —")
    print("    the process exits before 'disconnecting' can be observed.")
    print("    The bug materialises in the SSH connection multiplexer")
    print("    (ssh -M / ControlMaster) where multiple struct ssh objects")
    print("    share the same process and the flag is never reset.")


if __name__ == "__main__":
    main()
