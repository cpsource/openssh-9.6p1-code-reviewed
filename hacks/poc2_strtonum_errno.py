#!/usr/bin/env python3
"""
PoC #2 — strtonum Failure Returns -errno, but strtonum Does Not Set errno
==========================================================================
Finding : HIGH  (README-sshd-security-flaws.md #2)
File    : sshd.c:1053-1054 and sshd.c:1064-1065
Branch  : master (unfixed)

Vulnerability
-------------
    listen_pid = (pid_t)strtonum(listen_pid_str, 2, INT_MAX, &errstr);
    if (errstr != NULL)
            return -errno;    // BUG: strtonum does NOT set errno

strtonum(3) signals errors via the errstr output parameter only; it never
touches errno.  When the conversion fails and errno happens to be 0 (the
common case early in sshd startup), get_systemd_listen_fds() returns 0
instead of a negative error code.

The caller treats a non-negative return as "N file descriptors were passed
by systemd":

    systemd_num_listen_fds = r;   // silently set to 0

With systemd_num_listen_fds=0 sshd skips socket activation entirely and
falls back to opening its own listening sockets — possibly on different
addresses, ports, or with different socket options than the systemd unit
intended.

Attack vector
-------------
An attacker who can manipulate the environment of sshd (e.g. via a
compromised supervisor, container escape, or writable /proc/PID/environ
before exec) can set LISTEN_PID or LISTEN_FDS to a syntactically invalid
value, causing sshd to silently ignore the pre-bound systemd sockets and
re-bind on its own terms.

This PoC reproduces the exact C logic in Python, then compiles and runs a
small C reproducer to confirm the behaviour on this system.
"""

import os
import sys
import subprocess
import tempfile

C_REPRODUCER = r"""
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Minimal strtonum from OpenBSD (same implementation used by openssh) */
long long
strtonum(const char *numstr, long long minval, long long maxval,
    const char **errstrp)
{
    long long ll = 0;
    int error = 0;
    char *ep;
    struct errval { const char *errstr; int err; } ev[4] = {
        { NULL,         0 },
        { "invalid",    EINVAL },
        { "too small",  ERANGE },
        { "too large",  ERANGE },
    };

    ev[0].err = errno;
    errno = 0;
    if (minval > maxval) {
        error = 3;
    } else {
        ll = strtoll(numstr, &ep, 10);
        if (numstr == ep || *ep != '\0')
            error = 1;
        else if ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
            error = 2;
        else if ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
            error = 3;
    }
    if (errstrp != NULL)
        *errstrp = ev[error].errstr;
    errno = ev[0].err;   /* NOTE: errno is RESTORED to original value */
    if (error)
        ll = 0;
    return ll;
}

int get_systemd_listen_fds_vulnerable(void) {
    const char *listen_fds_str;
    int listen_fds;
    const char *errstr = NULL;

    listen_fds_str = getenv("LISTEN_FDS");
    if (listen_fds_str == NULL)
        return 0;

    /* Simulate errno=0 (typical at this point in sshd startup) */
    errno = 0;

    listen_fds = (int)strtonum(listen_fds_str, 1, 2147483644, &errstr);
    if (errstr != NULL) {
        printf("  strtonum failed: errstr=\"%s\", errno=%d\n", errstr, errno);
        printf("  VULNERABLE path: returning -errno = -%d = %d\n",
               errno, -errno);
        return -errno;    /* BUG: returns 0 when errno==0 */
    }
    return listen_fds;
}

int get_systemd_listen_fds_fixed(void) {
    const char *listen_fds_str;
    int listen_fds;
    const char *errstr = NULL;

    listen_fds_str = getenv("LISTEN_FDS");
    if (listen_fds_str == NULL)
        return 0;

    errno = 0;
    listen_fds = (int)strtonum(listen_fds_str, 1, 2147483644, &errstr);
    if (errstr != NULL) {
        printf("  strtonum failed: errstr=\"%s\"\n", errstr);
        printf("  FIXED path: returning -EINVAL = %d\n", -22);
        return -22;   /* -EINVAL */
    }
    return listen_fds;
}

int main(void) {
    int r;

    printf("--- Vulnerable version ---\n");
    r = get_systemd_listen_fds_vulnerable();
    printf("  Return value: %d\n", r);
    if (r == 0)
        printf("  [+] BUG CONFIRMED: returns 0 (not negative) -> "
               "caller sets systemd_num_listen_fds=0, skips fatal()\n");
    else if (r < 0)
        printf("  [-] Returns negative (errno was non-zero at time of call)\n");

    printf("\n--- Fixed version ---\n");
    r = get_systemd_listen_fds_fixed();
    printf("  Return value: %d\n", r);
    if (r < 0)
        printf("  [+] FIXED: returns negative -> caller calls fatal()\n");

    return 0;
}
"""

def main():
    print("=" * 60)
    print("PoC #2 — strtonum failure silently returns 0 via -errno")
    print("=" * 60)
    print()
    print("[*] This PoC compiles a C reproducer that mirrors the exact")
    print("    strtonum logic from sshd.c and runs it with a malformed")
    print("    LISTEN_FDS environment variable.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src = os.path.join(tmpdir, 'poc2.c')
        bin_ = os.path.join(tmpdir, 'poc2')

        with open(src, 'w') as f:
            f.write(C_REPRODUCER)

        r = subprocess.run(['cc', '-o', bin_, src], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[!] Compilation failed:\n{r.stderr}")
            sys.exit(1)
        print("[*] Compiled reproducer OK")
        print()

        # Run with a malformed LISTEN_FDS
        env = os.environ.copy()
        env['LISTEN_FDS'] = 'NOTANUMBER'
        env['LISTEN_PID'] = str(os.getpid())   # match our PID

        print(f"[*] Setting LISTEN_FDS=NOTANUMBER, LISTEN_PID={os.getpid()}")
        print()

        r = subprocess.run([bin_], env=env, capture_output=True, text=True)
        print(r.stdout)
        if r.stderr:
            print(r.stderr)

    print("[*] Impact:")
    print("    sshd sees systemd_num_listen_fds=0, skips socket activation,")
    print("    and opens its own sockets — potentially on different addresses")
    print("    or without the options (FreeBind, BindIPv6Only, etc.) that")
    print("    the systemd unit configured.")
    print()
    print("[*] Fix: return -EINVAL (not -errno) after strtonum failure.")
    print("    (applied on branch security-flaw-fixes)")

if __name__ == '__main__':
    main()
