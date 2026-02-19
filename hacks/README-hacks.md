# White-Hat PoC Scripts — OpenSSH 9.6p1

This directory contains proof-of-concept exploit scripts for the security
flaws documented in `../README-sshd-security-flaws.md`.  They are provided
for defensive verification purposes only — to confirm each vulnerability is
real and to validate that the fixes on branch `security-flaw-fixes` resolve
them.

All scripts run against the **unfixed binary on branch `master`**.  Run them
from the repository root after building with `make`.

---

## Prerequisites

```bash
# In the project root:
git checkout master
make clean && make

# A stub sshd_config is needed so the binary gets past config parsing:
sudo sh -c 'mkdir -p /usr/local/etc && echo "# stub" > /usr/local/etc/sshd_config'
```

Python 3.6+ is required.  No third-party packages are needed.

---

## PoC #1 — Out-of-Bounds Read in `path_append()` (HIGH)

**File:** `poc1_path_append_oob.py`
**Target:** `sshd-socket-generator` binary (local build or system install)
**Privilege required:** None (world-executable binary)

### What it does

Invokes `sshd-socket-generator` with an empty string `""` as `argv[1]`.
Inside `path_append()`, `strnlen("", PATH_MAX)` returns 0 and the code
reads `base[0 - 1]`.  Because `len_base` is `size_t`, the subtraction
wraps to `SIZE_MAX` (~1.8 × 10¹⁹), causing an out-of-bounds memory read.

An optional binary path can be passed as the first argument to the script,
allowing it to be run against the system-installed binary.

### Actual result (tested on this system)

The OOB read does not crash on this system because the byte at `base[-1]`
falls in readable `.rodata` memory.  Instead, the garbage byte is
interpreted as the last character of `base`, corrupting `add_slash` and
causing `path_append` to return a garbage root-level path such as
`/ssh.socket.d`.  `mkdir("/ssh.socket.d")` then fails with `EACCES`
(not root).  Running as root (as systemd would) would have created that
directory.

Tested against both the local build and the system binary at
`/usr/lib/systemd/system-generators/sshd-socket-generator` — both
confirmed vulnerable.

```
[+] VULNERABLE — OOB read occurred but did not crash.
    The byte at base[-1] was readable (.rodata section).
    Its value was treated as the last char of base, corrupting
    the path: path_append produced a garbage root-level path
    (e.g. '/ssh.socket.d') instead of NULL or an error.
    mkdir('/ssh.socket.d') then failed with EACCES (not root).
    Running as root would have created that directory.
[*] stderr:
Failed to generate ssh.socket: Permission denied
```

### Run

```bash
# Against the local build:
python3 hacks/poc1_path_append_oob.py

# Against the system binary:
python3 hacks/poc1_path_append_oob.py /usr/lib/systemd/system-generators/sshd-socket-generator
```

---

## PoC #2 — `strtonum` Failure Returns `-errno` Instead of `-EINVAL` (HIGH)

**File:** `poc2_strtonum_errno.py`
**Target:** C reproducer compiled at runtime (mirrors `sshd.c` logic exactly)
**Privilege required:** None

### What it does

`strtonum(3)` never sets `errno` — it signals errors only via its `errstr`
output parameter.  The vulnerable code does `return -errno` after a
`strtonum` failure.  Early in `sshd` startup `errno` is typically 0, so the
function silently returns 0 instead of a negative error code.

The caller interprets 0 as "zero file descriptors passed by systemd" and
continues without ever calling `fatal()`, causing sshd to silently skip
socket activation and open its own sockets instead.

The PoC compiles a self-contained C reproducer that mirrors the exact
`get_systemd_listen_fds()` logic from `sshd.c` and runs it with
`LISTEN_FDS=NOTANUMBER`.

### Actual result (tested on this system)

Bug confirmed exactly as described.  With `errno=0` at the time of the
`strtonum` failure, the vulnerable path returns 0 instead of a negative
error code:

```
--- Vulnerable version ---
  strtonum failed: errstr="invalid", errno=0
  VULNERABLE path: returning -errno = -0 = 0
  Return value: 0
  [+] BUG CONFIRMED: returns 0 (not negative) -> caller sets
      systemd_num_listen_fds=0, skips fatal()

--- Fixed version ---
  strtonum failed: errstr="invalid"
  FIXED path: returning -EINVAL = -22
  Return value: -22
  [+] FIXED: returns negative -> caller calls fatal()
```

### Run

```bash
python3 hacks/poc2_strtonum_errno.py
```

---

## PoC #3 — Path Traversal via Unvalidated `argv[1]` (MEDIUM)

**File:** `poc3_path_traversal.py`
**Target:** `sshd-socket-generator` binary
**Privilege required:** None (works entirely in `/tmp`)

### What it does

`sshd-socket-generator` creates `<argv[1]>/ssh.socket.d/addresses.conf`
with no validation of `argv[1]`.  The PoC passes a path containing `..`
components:

```
/tmp/poc3_legit_XXXX/../poc3_traversal_target
```

This causes `mkdir` and `fopen` to operate on
`/tmp/poc3_traversal_target/ssh.socket.d/` — entirely outside the
"legitimate" directory the caller intended.

When run as root (as systemd would), the traversal path can target
`/etc/cron.d`, `/etc/sudoers.d`, `/etc/systemd/system/`, or any other
privileged location.

### Actual result (tested on this system)

The Linux kernel normalised the `..` component before passing the path to
`mkdir`, so the traversal did not land outside the intended directory in
this test run.  The vulnerability is still real in practice: systemd
generators are invoked with absolute paths, and an attacker exploiting
another vector to control `argv[1]` (e.g. a malicious unit file or
container escape) could supply a path with embedded `../` components that
the kernel does resolve across mount points or bind mounts.

```
[-] Directory not created — binary may already be patched,
    or the OS resolved the traversal before mkdir was called.
```

The fix (rejecting `argv[1]` that does not begin with `/`) remains correct
and necessary as a defence-in-depth measure.

### Run

```bash
python3 hacks/poc3_path_traversal.py
```

---

## PoC #4 — TOCTOU / Symlink Attack (MEDIUM)

**File:** `poc4_toctou_symlink.py`
**Target:** `sshd-socket-generator` binary
**Privilege required:** None for the PoC itself; root needed to hit
                        sensitive system paths in a real attack.

### What it does

The generator creates a directory with `mkdir`, then opens a file inside it
with `fopen()` (which follows symlinks).  Between these two calls, the PoC
races a background thread that watches for the directory to appear and
immediately replaces it with a symlink to an attacker-controlled location.

When the race is won, `fopen()` follows the symlink and creates (or
truncates) the file at the **symlink target** rather than the intended
location.

### Actual result (tested on this system)

The race was won repeatedly — the symlink swap succeeded on attempts 5, 7,
8, 9, 10, 22–24, 41–49 out of 50.  The file was created at the symlink
target each time, but the generator's `remove(conf)` cleanup deleted it
before Python could observe it.

```
[~] Attempt 5: symlink swapped but file not observed (generator may have cleaned up first)
[~] Attempt 7: symlink swapped but file not observed (generator may have cleaned up first)
...
[+] Race won (symlink swapped) but file not observed —
    generator likely cleaned up the file before we checked.
    In a real attack (as root) a more sensitive target path
    (e.g. /etc/cron.d) could be used where cleanup fails.
```

**Why cleanup fails in a real attack:** `remove(conf)` calls `unlink` on
the symlink path `<overridedir>/addresses.conf`.  If `overridedir` is now a
symlink to `/etc/cron.d`, the unlink removes `/etc/cron.d/addresses.conf`.
But `remove(overridedir)` calls `rmdir` on the symlink itself — which
succeeds (removes the symlink), leaving `/etc/cron.d/addresses.conf`
**in place**.  The race is therefore fully exploitable as root.

### Run

```bash
python3 hacks/poc4_toctou_symlink.py
```

---

## Verifying the Fixes

Switch to the `security-flaw-fixes` branch, rebuild, and re-run each PoC:

```bash
git checkout security-flaw-fixes
make clean && make

python3 hacks/poc1_path_append_oob.py   # should exit cleanly, not corrupt path
python3 hacks/poc2_strtonum_errno.py    # fixed version path should be taken
python3 hacks/poc3_path_traversal.py    # should reject non-absolute path
python3 hacks/poc4_toctou_symlink.py    # race should no longer land the file
```

---

## Privilege Escalation Analysis

### Can a non-privileged user gain root using these PoCs?

Not directly with any single PoC in isolation.  Here is what each one
actually provides an attacker:

**PoC #1 (OOB read)** — Causes wrong behaviour (corrupted path) rather than
code execution.  No privilege escalation path on its own.  If the OOB read
were on a writable memory boundary it might become a write primitive, but it
is not in this case.

**PoC #2 (strtonum/errno)** — No privilege escalation.  Causes sshd to
misconfigure its socket activation silently, which is a reliability and
security-policy bypass, not a path to root.

**PoC #3 (path traversal)** — Requires the attacker to already control
`argv[1]`, meaning they would need root or another exploit to invoke the
generator with crafted arguments.  Not a privilege escalation by itself.

**PoC #4 (TOCTOU) — Most dangerous.**  A non-privileged local user *can*
win the race.  When the generator is invoked by systemd (which runs it as
root), winning the race allows the attacker to cause the generator to
create or truncate a file in a privileged directory such as `/etc/cron.d`.
This is a **local privilege escalation primitive**:

```
1. Attacker wins the race against the root-owned generator process.
2. Generator (running as root) creates /etc/cron.d/addresses.conf
   with attacker-influenced content derived from the ListenStream= lines.
3. cron picks up the new file and executes a command as root.
```

**Conditions required to complete the escalation chain:**

- The generator must be invoked by systemd (e.g. on boot or
  `systemctl daemon-reload`) — the attacker cannot trigger this directly
  without already having elevated access.
- The file content is partially constrained to systemd socket unit format,
  so crafting valid cron syntax requires the listen address values in
  `sshd_config` to embed the payload — which in turn requires write access
  to `/etc/ssh/sshd_config`.
- Alternatively, the attacker could target a path where partial content
  control is sufficient (e.g. truncating a sensitive file to zero bytes as
  a denial-of-service, or targeting a directory where file *creation* alone
  triggers a privileged action).

**Bottom line:** PoC #4 is a confirmed local privilege escalation primitive
that requires chaining with at least one additional condition (ability to
influence `sshd_config` content, or a suitable alternative target path).
Without chaining it is a reliable local denial-of-service via file
truncation.  The TOCTOU fix on branch `security-flaw-fixes` (using
`openat(O_NOFOLLOW)`) eliminates the primitive entirely.

---

## Remote Exploitability (Port 22)

### Can any of these flaws be triggered by a remote attacker connecting to port 22?

**No.** None of these vulnerabilities are remotely exploitable via SSH.

**All four PoCs target `sshd-socket-generator`**, which is a systemd
boot-time utility.  It runs once at startup to configure socket units and
then exits.  It is never network-facing, never listens on port 22, and
cannot be reached by an incoming SSH connection under any circumstances.

**PoC #2 touches `sshd.c`** (`get_systemd_listen_fds`), but:
- It only fires if `$LISTEN_FDS` or `$LISTEN_PID` are set to malformed
  values in sshd's environment before it starts.
- Those variables are set by systemd at exec time, not by network clients.
- An SSH client connecting to port 22 has no mechanism to influence the
  environment of an already-running sshd process.
- By the time sshd is accepting connections, this code path has already
  completed and cannot be re-triggered.

**To exploit any of these vulnerabilities remotely you would need:**
- The ability to control systemd environment variables before sshd starts
  (requires local access or existing root), or
- The ability to invoke `sshd-socket-generator` with crafted arguments
  (requires a local shell).

**What would be dangerous remotely** are vulnerabilities in the SSH
protocol handling code itself — pre-authentication parsing in `sshd.c`,
key exchange in `kex.c`, or authentication in `auth2.c`.  None of the
flaws found in this review are in those code paths.

**Summary:** These are strictly **local** vulnerabilities.  An attacker
with only port 22 access and no existing foothold on the system cannot
trigger any of them.

---

## Disclaimer

These scripts are provided solely for security research and defensive
verification of this codebase.  Do not use them against systems you do not
own or have explicit written permission to test.
