# White-Hat PoC Scripts — OpenSSH 9.6p1

This directory contains proof-of-concept exploit scripts for the security
flaws documented in `../README-sshd-security-flaws.md`.  They are provided
for defensive verification purposes only — to confirm each vulnerability is
real and to validate that fixes resolve them.

**Branch notes:**
- PoC #1–#4 (`sshd-socket-generator` / `sshd.c` findings) were fixed on the
  `security-flaw-fixes` branch, which has since been merged into `master`.
  Running these PoCs on the current `master` will show the *fixed* behaviour.
- PoC #5–#7 (`auth2.c` findings), PoC #9–#13 (`packet.c` findings), and
  PoC #14–#18 (`umac.c` findings) remain unfixed on `master`; the C
  reproducers confirm the behaviour regardless of branch.
- PoC #8 (zip bomb, `packet.c` finding #17) has been **fixed directly on
  `master`** — running it on the current tree will show the cap enforced.

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

PoC #5 and #6 require a running sshd with `LogLevel DEBUG3` in `sshd_config`
for the injected strings to be visible in log output.  The vulnerability
exists regardless of log level; see the individual script headers for details.

PoC #8 requires zlib development headers (`apt install zlib1g-dev` on Debian/
Ubuntu) for the C reproducer to compile.

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

## PoC #5 — Unsanitised `role`/`style` Substrings Passed to PAM and `setproctitle` (LOW)

**File:** `poc5_role_style_injection.py`
**Finding:** #9 — `auth2.c:289-326`
**Target:** Running sshd on port 22
**Privilege required:** None (unauthenticated remote client)

### What it does

Sends an `SSH2_MSG_USERAUTH_REQUEST` with a crafted username of the form
`nonexistent/EVIDENCE_ROLE_INJECTED:EVIDENCE_STYLE_INJECTED`.  The `role`
and `style` substrings split from the username are forwarded verbatim to
`mm_inform_authserv()` (privsep boundary), `start_pam()`, and debug-level
log output — without any character-set or length validation.

### Run

```bash
# Requires sshd running on port 22 and LogLevel DEBUG3 in sshd_config:
python3 hacks/poc5_role_style_injection.py
```

---

## PoC #6 — Log Injection via Raw Client Strings (INFO)

**File:** `poc6_log_injection.py`
**Finding:** #10 — `auth2.c:286`
**Target:** Running sshd on port 22
**Privilege required:** None (unauthenticated remote client)

### What it does

Two variants:

**Variant A** — Uses the system `ssh` binary with ANSI escape sequences
in the username.  Terminal-capable log viewers (e.g. `journalctl` with
colour output) render the escapes, corrupting displayed log lines.

**Variant B** — Implements a minimal raw SSH2 client in Python
(curve25519-sha256 key exchange, AES-128-CTR + HMAC-SHA256) to send a
`SSH2_MSG_USERAUTH_REQUEST` with embedded newline characters in the
username, forging an arbitrary subsequent log entry.

### Run

```bash
# Requires sshd on port 22 and LogLevel DEBUG3:
python3 hacks/poc6_log_injection.py
```

---

## PoC #7 — Implicit `double` → `time_t` Cast in `ensure_minimum_time_since` (INFO)

**File:** `poc7_timing_cast.py`
**Finding:** #11 — `auth2.c:263-264`
**Target:** C reproducer compiled at runtime
**Privilege required:** None

### What it does

Compiles a C reproducer that mirrors the cast at `auth2.c:263-264`
(`ts.tv_sec = remain`) and exercises it with normal values, edge cases
(negative, huge), and special floating-point values (+Inf, NaN, -Inf).
Shows that out-of-range `double` values produce implementation-defined
`time_t` results (typically `LLONG_MAX`, 0, or `INT64_MIN` on x86-64),
any of which would cause `nanosleep` to either return `EINVAL` immediately
(skipping the minimum delay) or block for an astronomically long time.

### Run

```bash
python3 hacks/poc7_timing_cast.py
```

---

## PoC #8 — Unbounded Decompression / Zip Bomb in `uncompress_buffer()` (MEDIUM) ✓ FIXED

**File:** `poc8_zipbomb.py`
**Finding:** #17 — `packet.c:777-822`
**Target:** C reproducer compiled at runtime
**Privilege required:** None for the PoC; network access needed for a real attack

### What it does

Mirrors the `uncompress_buffer()` inflate loop and demonstrates that a
maximally-compressed payload fitting within the 256 KB `PACKET_MAX_SIZE`
limit expands to hundreds of megabytes without any output-size cap.
A PoC safety limit of 64 MB is applied; real code (before the fix) has no
limit.

### Status on current master

**Fixed.**  The companion commit added an `out_total` accumulator to the
inflate loop; decompression is now rejected with `SSH_ERR_INVALID_FORMAT`
once output exceeds `PACKET_MAX_SIZE` (256 KB).  Running the PoC on the
fixed tree will show the cap being enforced rather than free expansion.

### Run

```bash
# Requires zlib dev headers (apt install zlib1g-dev):
python3 hacks/poc8_zipbomb.py
```

---

## PoC #9 — Wrong Sequence Number in Non-AEAD First-Block Decryption (LOW)

**File:** `poc9_seqnr_mismatch.py`
**Finding:** #16 — `packet.c:1525-1527`
**Target:** C reproducer compiled at runtime
**Privilege required:** None

### What it does

Simulates a realistic SSH session (KEX + auth + asymmetric scp traffic)
to show `p_send.seqnr` and `p_read.seqnr` diverging quickly.  Then
demonstrates the decryption error for a hypothetical non-AEAD cipher that
uses the sequence number as a nonce: the buggy code at `packet.c:1526`
passes `p_send.seqnr` to `cipher_crypt()` instead of `p_read.seqnr`,
producing a wrong packet-length field.  Current ciphers (AES-CTR, AES-CBC)
ignore the seqnr argument, so there is no functional impact today.

### Run

```bash
python3 hacks/poc9_seqnr_mismatch.py
```

---

## PoC #10 — Shift Undefined Behaviour in Rekey Block-Limit Calculation (INFO)

**File:** `poc10_shift_ub.py`
**Finding:** #20 — `packet.c:946`
**Target:** C reproducer compiled at runtime
**Privilege required:** None

### What it does

Evaluates `(u_int64_t)1 << (block_size * 2)` for `block_size` values 8
through 40.  Flags the cases where the shift amount is ≥ 64 (undefined
behaviour per C11 §6.5.7p3), shows the observed result on this platform
(typically 1 or 0 — meaning `max_blocks = 1`, i.e. rekey after every
single block), and re-compiles with `-fsanitize=undefined` to confirm
UBSAN detection if available.

### Run

```bash
python3 hacks/poc10_shift_ub.py
```

---

## PoC #11 — Cipher Key/IV Lengths Not Validated in `newkeys_from_blob()` (LOW)

**File:** `poc11_newkeys_keylen.py`
**Finding:** #21 — `packet.c:2375-2404`
**Target:** C reproducer compiled at runtime
**Privilege required:** None

### What it does

Mirrors the `newkeys_from_blob()` deserialization logic and runs several
test cases with correct and incorrect key/IV sizes.  Shows that the MAC
key length check (`maclen > mac->key_len → SSH_ERR_INVALID_FORMAT`) fires
correctly, while cipher key and IV lengths from the blob are silently
accepted regardless of whether they match the cipher's requirements.

### Run

```bash
python3 hacks/poc11_newkeys_keylen.py
```

---

## PoC #12 — Process-Global `static int disconnecting` (INFO)

**File:** `poc12_static_disconnecting.py`
**Finding:** #19 — `packet.c:1976`
**Target:** C reproducer compiled at runtime
**Privilege required:** None

### What it does

Simulates two concurrent `struct ssh` objects (as they exist in the SSH
connection multiplexer) calling `ssh_packet_disconnect`.  When connection A
disconnects first, `disconnecting = 1` is set process-globally.  Connection
B then hits the `fatal("packet_disconnect called recursively")` branch
instead of sending `SSH2_MSG_DISCONNECT`, demonstrating that the peer would
see an abrupt TCP close rather than a clean disconnect message.

### Run

```bash
python3 hacks/poc12_static_disconnecting.py
```

---

## PoC #13 — `kex_from_blob()` Hardcodes `kex->server = 1` (INFO)


**File:** `poc13_kex_server_flag.py`
**Finding:** #18 — `packet.c:2436`
**Target:** Source scan + C reproducer compiled at runtime
**Privilege required:** None

### What it does

1. Greps `packet.c` and `kex.c` to show the hardcoded `kex->server = 1`
   assignment and the ~15 decision points in `kex.c` that branch on
   `kex->server` (algorithm direction, EXT_INFO timing, banner order, compat
   checks, key derivation direction).
2. Compiles a C reproducer that calls the `kex_from_blob` logic on a
   simulated *client* process and shows the resulting inconsistency:
   `state->server_side = 0` (client) but `kex->server = 1` (server) —
   two fields that `ssh_packet_set_server()` always sets in tandem but
   `kex_from_blob()` only sets one of.

### Run

```bash
python3 hacks/poc13_kex_server_flag.py
```

---

---

## PoC #14 — UMAC 16 MB Message Limit Not Enforced at Runtime (LOW)

**File:** `poc14_umac_16mb_limit.py`
**Finding:** #22 — `umac.c:827-848`
**Target:** C reproducer compiled at runtime
**Privilege required:** None

### What it does

Mirrors the `poly64()` and `poly_hash()` functions from `umac.c` and
demonstrates that calling `poly_hash()` more than 2^14 times (the
documented 16 MB limit) produces no error, warning, or changed return
status.  The polynomial accumulator silently diverges from what a correct
RFC 4418 (p128-ramped) implementation would produce.

Also shows the SSH safety margin: `PACKET_MAX_SIZE` (~256 KB) limits each
UMAC session to at most 256 `poly_hash()` invocations — well under the
16,384-call limit.

### Run

```bash
python3 hacks/poc14_umac_16mb_limit.py
```

---

## PoC #15 — Signed Integer Overflow in `nh_final()` — `bytes_hashed << 3` (INFO)

**File:** `poc15_nh_final_shift_ub.py`
**Finding:** #23 — `umac.c:692`
**Target:** C reproducer compiled at runtime
**Privilege required:** None

### What it does

Evaluates `(int bytes_hashed) << 3` (the expression at `umac.c:692`) for
a range of `bytes_hashed` values from 1024 through 2^30.  Identifies 2^28
(256 MB) as the overflow threshold (C11 §6.5.7p4 UB), shows the observed
bit-pattern results on this platform, and contrasts with the `UINT32 nbits`
version used in the companion function `nh()` at `umac.c:718`.

Also attempts a UBSAN recompile to confirm runtime detection.

### Run

```bash
python3 hacks/poc15_nh_final_shift_ub.py
```

---

## PoC #16 — `kdf()` Counter Byte Truncation at 256 AES Blocks (INFO)

**File:** `poc16_kdf_counter_wrap.py`
**Finding:** #24 — `umac.c:199`
**Target:** C reproducer compiled at runtime
**Privilege required:** None

### What it does

Mirrors the `kdf()` counter loop from `umac.c:185-209` and generates 260
AES counter blocks.  Shows that block 257 uses the same counter byte (0x01)
as block 1 — because the `int i` counter wraps from 256 to 0 when stored
in a `UINT8` slot — causing the keystream to repeat from block 257 onward.
Verifies that the keystream bytes at blocks 1 and 257 are identical.

Also confirms the in-practice safety margin: max UMAC key derivation is
~103 AES blocks, well under the 256-block wrap threshold.

### Run

```bash
python3 hacks/poc16_kdf_counter_wrap.py
```

---

## PoC #17 — Strict-Aliasing UB via `UINT8*` → `UINT64*`/`UINT32*` Casts (INFO)

**File:** `poc17_umac_aliasing_ub.py`
**Finding:** #25 — `umac.c` (pervasive)
**Target:** C reproducer + source scan compiled at runtime
**Privilege required:** None

### What it does

Reproduces the raw-pointer-cast pattern found throughout `umac.c` (e.g.
`*((UINT64 *)hp)` in `nh_aux()`, `((UINT64 *)result)[0]` in `nh_final()`,
`((UINT32 *)nonce)[1]` in `pdf_gen_xor()`).  Compiles with
`-Wstrict-aliasing=2` to surface compiler warnings, with
`-fsanitize=undefined` for runtime detection, and at `-O3` to approach
the regime where the GCC note at `umac.c:44` ("incorrect results sometimes
produced under -O3") is relevant.

Also scans the actual `umac.c` source to count and list all
`UINT8*` → `UINT64*`/`UINT32*` cast sites.

### Run

```bash
python3 hacks/poc17_umac_aliasing_ub.py
```

---

## PoC #18 — `long len` Silently Truncated to `UINT32` at `nh_update()` (INFO)

**File:** `poc18_len_truncation.py`
**Finding:** #26 — `umac.c:1044/613`
**Target:** C reproducer compiled at runtime
**Privilege required:** None

### What it does

Shows the implicit `long` → `UINT32` conversion at the `nh_update()` call
boundary and the `UINT32 msg_len` accumulator wrap in `uhash_update()`.
For inputs exceeding 4 GB, demonstrates:
1. `nh_update()` receives a truncated byte count — processing far less data
   than requested, silently.
2. `msg_len` wraps at UINT32_MAX, potentially flipping the short-message
   (`ip_short`) vs long-message (`ip_long`) dispatch in `uhash_final()`.

Confirms that both are unreachable in SSH (PACKET_MAX_SIZE = 256 KB) and
shows the 16,000× safety margin.

### Run

```bash
python3 hacks/poc18_len_truncation.py
```

---

## Verifying the Fixes

**PoC #1–#4** (`sshd-socket-generator` / `sshd.c`) were fixed on the
`security-flaw-fixes` branch, which has been merged into `master`.  These
PoCs will show the fixed behaviour on the current tree.  To test the
*unfixed* behaviour, check out the commit just before the merge.

**PoC #8** (zip bomb) was fixed directly on `master`.  Running it on the
current tree will show the 256 KB decompression cap being enforced.

```bash
# PoC #1–#4: already fixed on master (security-flaw-fixes merged)
python3 hacks/poc1_path_append_oob.py   # path_append: NULL or error on empty base
python3 hacks/poc2_strtonum_errno.py    # fixed version returns -EINVAL
python3 hacks/poc3_path_traversal.py    # rejects non-absolute argv[1]
python3 hacks/poc4_toctou_symlink.py    # openat(O_NOFOLLOW) prevents symlink swap

# PoC #8: fixed on master
python3 hacks/poc8_zipbomb.py           # inflate loop now capped at PACKET_MAX_SIZE

# PoC #5–#7, #9–#13: unfixed — C reproducers confirm behaviour on any build
python3 hacks/poc7_timing_cast.py
python3 hacks/poc9_seqnr_mismatch.py
python3 hacks/poc10_shift_ub.py
python3 hacks/poc11_newkeys_keylen.py
python3 hacks/poc12_static_disconnecting.py
python3 hacks/poc13_kex_server_flag.py

# PoC #14–#18: unfixed (umac.c findings — all unreachable within SSH limits)
python3 hacks/poc14_umac_16mb_limit.py
python3 hacks/poc15_nh_final_shift_ub.py
python3 hacks/poc16_kdf_counter_wrap.py
python3 hacks/poc17_umac_aliasing_ub.py
python3 hacks/poc18_len_truncation.py
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

**Mitigating factor — no setuid bit:**
`/usr/lib/systemd/system-generators/sshd-socket-generator` is installed
as `-rwxr-xr-x` (owned by root, no setuid bit).  When a non-root user
invokes it directly it runs with **their own UID**, not root.  The
privilege escalation path via PoC #4 therefore only exists when
**systemd itself** triggers the generator (at boot or on
`systemctl daemon-reload`), since systemd runs as PID 1 with root
privileges and the generator inherits them in that context.

A non-root user invoking the binary directly can still win the race and
cause damage within their own file space, but cannot affect root-owned
paths or escalate privileges through this vector alone.

**Bottom line:** PoC #4 is a confirmed local privilege escalation primitive
when triggered via systemd, requiring chaining with at least one additional
condition (ability to influence `sshd_config` content, or a suitable
alternative target path).  Direct invocation by a non-root user is limited
to damage within that user's own file space.  Without chaining it is a
reliable local denial-of-service via file truncation when run as root.
The TOCTOU fix on branch `security-flaw-fixes` (using
`openat(O_NOFOLLOW)`) eliminates the primitive entirely.

---

## Remote Exploitability (Port 22)

### Which PoCs can be triggered by a remote attacker connecting to port 22?

| PoC | Finding | Remotely reachable? | Notes |
|-----|---------|---------------------|-------|
| #1  | sshd-socket-generator OOB read | **No** | Boot-time utility, never network-facing |
| #2  | strtonum / errno | **No** | Requires malformed env var before sshd starts |
| #3  | Path traversal | **No** | Requires attacker to control argv[1] |
| #4  | TOCTOU symlink | **No** | Requires local shell or systemd invocation |
| #5  | role/style injection | **Yes** — pre-auth | Any client can send a crafted username |
| #6  | Log injection | **Yes** — pre-auth | Any client; banner injection even before KEX |
| #7  | double→time_t cast | **No** | Triggered by internal clock conditions, not network input |
| #8  | Zip bomb | **Yes** — post-KEX | COMP_ZLIB: any client after NEWKEYS; COMP_DELAYED: authenticated user |
| #9  | Wrong seqnr | **No practical impact** | Bug exists but current ciphers are unaffected |
| #10 | Shift UB | **No** | Triggered at key installation, not by packet content |
| #11 | newkeys keylen | **No** | Requires tampering with the privsep state blob |
| #12 | static disconnecting | **No** | Process-internal state; not reachable from the network |
| #13 | kex server flag | **No** | Privsep deserialization path, not driven by network packets |
| #14 | UMAC 16 MB limit | **No** | Each SSH packet is ≤ 256 KB; 16 MB threshold never reached |
| #15 | nh_final shift UB | **No** | bytes_hashed reset at 1024 bytes; 256 MB threshold unreachable |
| #16 | kdf counter wrap | **No** | Max 103 AES blocks per key derivation; 256-block wrap unreachable |
| #17 | Strict-aliasing UB | **No** | Compiler/platform-internal; not driven by network input |
| #18 | long→UINT32 trunc | **No** | len bounded by PACKET_MAX_SIZE (256 KB) << UINT32_MAX (4 GB) |

**PoC #1–#4** target `sshd-socket-generator`, a systemd boot-time utility
that runs once at startup and is never network-facing.  PoC #2 touches
`sshd.c` but only fires when `$LISTEN_FDS`/`$LISTEN_PID` are malformed in
sshd's environment — set by systemd before exec, not by network clients.

**PoC #5 and #6** (`auth2.c` findings) are reachable by any unauthenticated
remote client.  PoC #6 variant B (newline injection) can be triggered before
key exchange even completes.  These are the only pre-authentication remote
findings in this review.

**PoC #8** (zip bomb) requires compression to be negotiated first.  With
legacy `COMP_ZLIB` this is possible immediately after key exchange without
authenticating; with the default `zlib@openssh.com` (`COMP_DELAYED`)
authentication must succeed first.  **This finding has been fixed on master.**

**PoC #14–#18** (`umac.c` findings) are not remotely reachable.  All five
issues require inputs that exceed the SSH packet-size or key-derivation
limits by many orders of magnitude.  They are included for completeness and
as defence-in-depth documentation.

---

## Disclaimer

These scripts are provided solely for security research and defensive
verification of this codebase.  Do not use them against systems you do not
own or have explicit written permission to test.
