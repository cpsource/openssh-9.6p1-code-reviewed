# Security Flaw Review — OpenSSH 9.6p1 (Modified)

This document records findings from a source-level security review of the
sshd-related code in this tree, with particular focus on the new
`sshd-socket-generator.c` file, the systemd socket-activation additions
to `sshd.c`, the SSH2 user-authentication dispatcher in `auth2.c`, the
key exchange layer in `kex.c`, the transport packet layer in `packet.c`,
and the UMAC message-authentication implementation in `umac.c`.

Severity ratings: **CRITICAL / HIGH / MEDIUM / LOW / INFO**

---

## 1. Out-of-Bounds Read in `path_append()` When Base Is Empty

**File:** `sshd-socket-generator.c:136`
**Severity:** HIGH

```c
len_base = strnlen(base, PATH_MAX);          // returns 0 for ""
add_slash = base[len_base - 1] != '/';       // base[-1] — OOB read
```

If `base` is an empty string, `len_base` is 0 and `base[0 - 1]` reads one
byte before the start of the buffer. On a typical x86-64 stack or heap layout
this reads garbage and produces an arbitrary `add_slash` value, causing
`calloc` to allocate the wrong size and `memcpy` to produce a malformed path.

`base` comes ultimately from `argv[1]` (the systemd generator destination
directory). A caller passing `""` as the first argument triggers this without
any privileges.

**Recommendation:** Guard with `if (len_base == 0) return NULL;` before
accessing `base[len_base - 1]`.

---

## 2. `strtonum` Failure Returns `-errno`, but `strtonum` Does Not Set `errno`

**File:** `sshd.c:1053-1054` and `sshd.c:1064-1065`
**Severity:** HIGH

```c
listen_pid = (pid_t)strtonum(listen_pid_str, 2, INT_MAX, &errstr);
if (errstr != NULL)
        return -errno;          /* BUG: strtonum does not set errno */
...
listen_fds = (int)strtonum(listen_fds_str, 1,
    INT_MAX - SYSTEMD_LISTEN_FDS_START, &errstr);
if (errstr != NULL)
        return -errno;          /* BUG: same */
```

`strtonum(3)` signals errors through its `errstr` output parameter, not
through `errno`. When `strtonum` fails, `errno` retains whatever value it had
from a previous syscall (often 0).

If `errno == 0` at the time of failure, `get_systemd_listen_fds()` returns 0
instead of a negative error code. The caller at line 1864-1868 treats a
non-negative return as "N fds were passed by systemd":

```c
r = get_systemd_listen_fds();
if (r < 0)
        fatal("Failed to get systemd socket fds: %s", strerror(-r));
systemd_num_listen_fds = r;       /* set to 0 — silent wrong behaviour */
```

With `systemd_num_listen_fds = 0`, sshd silently skips socket activation and
falls through to bind its own listening sockets. An attacker who can set a
malformed `$LISTEN_FDS` or `$LISTEN_PID` environment variable can therefore
cause sshd to ignore the systemd-provided sockets and open new ones —
potentially on different addresses or ports than intended.

**Recommendation:** Return a fixed error code such as `-EINVAL` when
`errstr != NULL`.

---

## 3. Path Traversal via Unvalidated `argv[1]` (Destination Directory)

**File:** `sshd-socket-generator.c:327, 343`
**Severity:** MEDIUM

```c
destdir = argv[1];                          // no validation
...
r = write_systemd_socket_file(destdir);     // creates files under destdir
```

`write_systemd_socket_file` creates `<destdir>/ssh.socket.d/addresses.conf`
using `mkdir` and `fopen`. No check is performed to ensure `destdir` is an
expected path (e.g. within `/run` or `/etc/systemd`). Passing
`../../../etc/cron.d` or any other attacker-controlled absolute path would
cause the generator to create or overwrite an arbitrary file with
attacker-influenced content (the `[Socket] ListenStream=...` lines derived
from the sshd config).

Systemd generators are normally invoked by PID 1 with fixed argument paths,
but the generator binary is world-executable and can be invoked manually.

**Recommendation:** Validate that `destdir` is an absolute path and, where
possible, that it begins with one of the expected generator output directories.

---

## 4. TOCTOU Race Between `mkdir` and `fopen` (Symlink Attack)

**File:** `sshd-socket-generator.c:192-203`
**Severity:** MEDIUM

```c
if (mkdir(overridedir, 0755) < 0 && errno != EEXIST) { ... }

conf = path_append(overridedir, "addresses.conf");
...
f = fopen(conf, "we");
```

Between the `mkdir` call and the `fopen` call, a local attacker can:
1. Remove or replace `overridedir` with a symlink to an arbitrary directory.
2. Pre-place a symlink at `<overridedir>/addresses.conf` pointing to any file.

`fopen(conf, "we")` does not use `O_NOFOLLOW` and will follow symlinks,
creating or truncating the symlink target. The `e` mode flag only adds
`O_CLOEXEC`; it provides no protection against symlink attacks.

The generator typically runs as root when invoked by systemd (PID 1), so a
successful race allows an attacker to truncate or overwrite an arbitrary file
owned by root.

**Mitigating factor — no setuid bit:**
The binary is installed as `-rwxr-xr-x` (no setuid bit).  When invoked
directly by a non-root user it runs with that user's UID, not root.  The
privilege escalation path therefore only exists when systemd triggers the
generator at boot or on `systemctl daemon-reload`.  A non-root user invoking
the binary directly can still win the race but is limited to damage within
their own file space.

**Recommendation:** Use `openat(dirfd, "addresses.conf", O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC, 0644)` with a directory fd obtained via `open(overridedir, O_DIRECTORY|O_NOFOLLOW)` to eliminate the TOCTOU window.

---

## 5. `parse_sshd_config_options()` Ignores Return Values of Config Functions

**File:** `sshd-socket-generator.c:304-315`
**Severity:** MEDIUM

```c
static int parse_sshd_config_options() {
        cfg = sshbuf_new();
        if (!cfg)
                return -ENOMEM;

        initialize_server_options(&options);
        load_server_config(_PATH_SERVER_CONFIG_FILE, cfg);      /* unchecked */
        parse_server_config(&options, _PATH_SERVER_CONFIG_FILE,
            cfg, &includes, NULL, 0);                           /* unchecked */
        fill_default_server_options(&options);

        return 0;
}
```

`load_server_config` and `parse_server_config` can fail (e.g. if the config
file is missing, unreadable, or syntactically invalid). Their return values
are silently discarded. If they fail, `options` may be in a partially
initialised state, and the generator could write a `addresses.conf` derived
from garbage or default values — potentially altering which addresses the
sshd socket listens on.

**Recommendation:** Check return values and propagate errors appropriately.

---

## 6. Missing Null Terminator After `memcpy` in `listen_stream_set_append()`

**File:** `sshd-socket-generator.c:105`
**Severity:** LOW

```c
memcpy(set[i], listen_stream, n);
return 0;
```

No explicit null terminator is written after the copied bytes. The code relies
on the zero-initialisation of `listen_streams` (`listen_stream_set
listen_streams = {}`) to provide termination. This is correct for the first
write to each slot, but is a fragile assumption: if the initialisation were
ever removed or the array reused, strings printed via `fprintf(f, "%s\n", ...)`
at line 283 would be unterminated.

**Recommendation:** Add `set[i][n] = '\0';` explicitly after the `memcpy` to
make the invariant self-evident and robust against future refactoring.

---

## 7. `listen_stream_set_len()` Assumes Contiguous Slots

**File:** `sshd-socket-generator.c:113-127`
**Severity:** LOW

```c
for (int i = 0; i < MAX_LISTEN_STREAMS; i++) {
        if (strnlen(set[i], MAX_LISTEN_STREAM_LEN) > 0)
                r++;
        else
                break;          /* stops at first empty slot */
}
```

The length function breaks on the first empty slot, assuming all non-empty
entries are stored contiguously. If the deduplication path in
`listen_stream_set_append()` (the early `return 0` on a matching entry, line
100) were ever followed by an insert at a later empty slot due to a logic
change, some entries would not be counted and would not be written to the
output file — silently producing an incomplete configuration.

The current code happens to always produce contiguous entries, but the
correctness of `listen_stream_set_len` is not locally obvious.

**Recommendation:** Count all non-empty slots rather than breaking early, or
document the contiguity invariant explicitly.

---

## 8. Typos in User-Facing Error Messages

**File:** `sshd-socket-generator.c:331, 345`
**Severity:** INFO

```c
fprintf(stderr, "Faild to parse sshd config: %s\n", strerror(-r));
// "Faild" → "Failed"

fprintf(stderr, "No custom listen addresses configured. "
    "Will not generated anything.\n");
// "generated" → "generate"
```

Incorrect grammar/spelling in error messages reduces operator confidence and
can complicate log parsing.

---

## 9. Unsanitised `role` and `style` Substrings Passed to PAM and `setproctitle`

**File:** `auth2.c:289-295, 323-326`
**Severity:** LOW

```c
if ((role = strchr(user, '/')) != NULL)
    *role++ = 0;
if ((style = strchr(user, ':')) != NULL)
    *style++ = 0;
else if (role && (style = strchr(role, ':')) != NULL)
    *style++ = '\0';
...
authctxt->style = style ? xstrdup(style) : NULL;
authctxt->role  = role  ? xstrdup(role)  : NULL;
if (use_privsep)
    mm_inform_authserv(service, style, role);
```

The `user` field in an `SSH2_MSG_USERAUTH_REQUEST` packet is accepted from
the remote client without restriction. Before the user is validated, the code
splits it on `/` and `:` to extract optional `role` and `style` substrings.
These substrings are stored verbatim and forwarded to:

- `mm_inform_authserv()` — crosses the privilege-separation boundary into the
  monitor process.
- `start_pam(ssh)` — passed as the PAM service style; a crafted value could
  influence PAM module selection on misconfigured systems.
- `setproctitle()` (line 320) — visible in `ps` output; a crafted string
  could inject misleading process titles.
- `debug()` logging (line 286) — raw client bytes appear in sshd log output
  before any validation, enabling log injection (see finding #10).

No length or character-set validation is performed on `role` or `style`
before any of these uses. The fields are bounded by the overall SSH packet
size limit, so there is no heap overflow, but the lack of sanitisation is
a defence-in-depth gap.

**Recommendation:** Validate that `role` and `style` contain only printable,
non-whitespace ASCII before storing or forwarding them. Reject or truncate
values that contain control characters, newlines, or are unreasonably long.

---

## 10. Raw Client Strings Logged Before Validation (Log Injection)

**File:** `auth2.c:286`
**Severity:** INFO

```c
debug("userauth-request for user %s service %s method %s", user, service, method);
```

`user`, `service`, and `method` are client-supplied strings read directly
from the SSH packet and logged verbatim before any validation. An attacker
can embed ANSI escape sequences or newline characters to:

- Forge spurious log lines (e.g. fake "Accepted publickey" entries).
- Corrupt structured log parsers (syslog, journald, SIEM tools) that split
  on newlines.
- Trigger terminal emulator escape-sequence processing if an administrator
  tails the log in a terminal.

OpenSSH's `debug()` path does not sanitise control characters. The `service`
and `method` values are subject to the same issue.

**Recommendation:** Strip or escape control characters (especially `\n`,
`\r`, and ESC) from client-supplied strings before passing them to any
logging function.

---

## 11. Implicit `double` → `time_t` Cast in `ensure_minimum_time_since`

**File:** `auth2.c:263-264`
**Severity:** INFO

```c
ts.tv_sec  = remain;                              /* double → time_t, unchecked */
ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
```

`remain` is a `double` computed as `seconds - elapsed`. The assignment to
`ts.tv_sec` (type `time_t`, a signed integer) is an implicit narrowing
conversion. If `remain` is negative or larger than `TIME_T_MAX`, the
conversion has implementation-defined behaviour (C11 §6.3.1.4).

The `while` loop at line 260 doubles `seconds` until `remain >= 0`, so
`remain` should always be non-negative when `nanosleep` is called. However,
the `MAX_FAIL_DELAY_SECONDS` early-return at line 253 means very long
authentication methods bypass the loop entirely and go straight to the cast.
In pathological clock conditions (e.g. `monotime_double()` returning a very
large value due to NTP step or VM migration) `elapsed` could exceed
`MAX_FAIL_DELAY_SECONDS` while `remain` computed later is still negative,
leading to a large `ts.tv_sec` value.

**Recommendation:** Clamp `remain` to `[0, MAX_FAIL_DELAY_SECONDS]` before
assigning to `ts.tv_sec`, or use an explicit cast with a range check.

---

## 12. GSS Algorithm Lookup Uses Prefix Match (`strncmp`) Instead of Exact Match

**File:** `kex.c:180-188`
**Severity:** LOW

```c
for (k = kexalgs; k->name != NULL; k++) {
    if (strcmp(k->name, name) == 0)              /* exact match */
        return k;
}
for (k = gss_kexalgs; k->name != NULL; k++) {
    if (strncmp(k->name, name, strlen(k->name)) == 0)   /* prefix match only */
        return k;
}
```

Non-GSS algorithm names are looked up with `strcmp` (exact match). GSS
algorithm names are looked up with `strncmp(table_entry, proposed,
strlen(table_entry))` — which matches any proposed name that *begins with* a
known GSS table entry.  For example, a peer proposing
`gss-gex-sha1-<OID>GARBAGE` would match the `gss-gex-sha1-<OID>` entry.

The matched `kexalg` struct provides the `kex_type` used to dispatch the
actual GSSAPI key exchange handler, while `kex->name` is set from the
negotiated string returned by `match_list`.  In GSSAPI exchanges the
mechanism OID is base64-decoded from the algorithm name suffix; a crafted
suffix that extends a valid OID with extra bytes will produce a different
(invalid) OID, likely causing the GSSAPI exchange to fail — but the
mismatch between the lookup type and the name in `kex->name` is an
unexpected inconsistency that could have more impactful consequences as
the code evolves or with future GSS algorithm additions.

GSSAPI support must be compiled in (`--with-kerberos5`) and enabled in
`sshd_config` for this path to be reachable.

**Recommendation:** Use `strcmp` for GSS algorithm lookup as well.  Let the
GSSAPI layer handle OID extraction from the full, exact algorithm name.

---

## 13. Control Characters in SSH Version Banner Not Sanitised (Log Injection)

**File:** `kex.c:1616-1654`
**Severity:** LOW

```c
if (c == '\r') { expect_nl = 1; continue; }
if (c == '\n') break;
if (c == '\0' || expect_nl) {
    verbose_f("banner line contains invalid characters");
    goto invalid;
}
/* All other bytes — including ESC, \x01–\x1f — are silently accepted */
if ((r = sshbuf_put_u8(peer_version, c)) != 0) { ... }
```

The per-character banner parser rejects only null bytes and bytes that
follow `\r` without a `\n`.  All other control characters — including ANSI
escape sequences (`\x1b[...`) and `\x01`–`\x1f` — are stored verbatim and
subsequently logged:

```c
debug_f("banner line %zu: %s", n, cp);          // pre-banner lines
debug("Remote protocol version %d.%d, remote software version %.100s",
    remote_major, remote_minor, remote_version); // version addendum
```

This is the same log-injection class as finding #10 (`auth2.c:286`) but
triggered even earlier — before key exchange begins — by any connecting
client or, from the client's perspective, by any server.  An attacker can
embed ANSI terminal codes to misrender log output in colour-capable viewers,
or embed newlines in pre-banner lines to forge subsequent log entries.

**Recommendation:** Reject or escape any byte outside `0x20`–`0x7e` (printable
ASCII) when reading the peer version banner, in addition to the existing
null-byte check.

---

## 14. `proposals_match` Permanently Mutates Proposal Strings

**File:** `kex.c:1194-1197`
**Severity:** INFO

```c
static int
proposals_match(char *my[PROPOSAL_MAX], char *peer[PROPOSAL_MAX])
{
    ...
    for (idx = &check[0]; *idx != -1; idx++) {
        if ((p = strchr(my[*idx], ',')) != NULL)
            *p = '\0';      /* truncates my[PROPOSAL_KEX_ALGS] in place */
        if ((p = strchr(peer[*idx], ',')) != NULL)
            *p = '\0';      /* truncates peer[PROPOSAL_KEX_ALGS] in place */
        if (strcmp(my[*idx], peer[*idx]) != 0) { ... }
    }
}
```

To isolate the first algorithm from each name-list for comparison,
`proposals_match` writes a null byte over the first comma in the KEX and
host-key proposal strings.  This is a destructive, permanent modification
of the caller's data.

Currently harmless — the proposals are freed immediately after the call
(`kex_prop_free(my)` / `kex_prop_free(peer)` at lines 1342–1343) and
`proposals_match` is called only once per handshake.  However, if the call
site were ever refactored to reuse or log the proposal arrays after this
call, the truncated strings would silently produce incorrect output (e.g.
showing only the first algorithm in diagnostics, or failing to match a
second algorithm during re-key negotiation).

**Recommendation:** Operate on a local copy, or use `strncmp` with a
computed length (`strcspn(str, ",")`) rather than mutating the caller's
string.

---

## 15. No Length Cap on `server-sig-algs` EXT_INFO Value

**File:** `kex.c:745-746`
**Severity:** INFO

```c
free(ssh->kex->server_sig_algs);
ssh->kex->server_sig_algs = xstrdup((const char *)value);
```

The `server-sig-algs` extension value received from the server in
`SSH2_MSG_EXT_INFO` is stored without imposing any length limit beyond the
SSH packet size (~32 KB per packet, up to 256 MB total with `MaxPacket`).
This string is subsequently consumed by `has_any_alg()` → `match_list()`
every time the client evaluates algorithm preferences during authentication
and key exchange.  `match_list` iterates over both its arguments character
by character, so a 32 KB `server-sig-algs` string results in O(n·m) work
per algorithm selection call.

A malicious server can also send up to 1024 extension entries per
`SSH2_MSG_EXT_INFO` message (enforced at `kex.c:800`); combined with the
unbounded value storage, this creates a client-side CPU-exhaustion surface
for a rogue server.

**Recommendation:** Cap `server-sig-algs` at a reasonable maximum (e.g. 4 KB)
and return `SSH_ERR_INVALID_FORMAT` if the value exceeds it.

---

## 16. Wrong Sequence Number in Non-AEAD First-Block Decryption

**File:** `packet.c:1525-1527`
**Severity:** LOW

```c
if ((r = cipher_crypt(state->receive_context,
    state->p_send.seqnr, cp, sshbuf_ptr(state->input),   /* ← p_send, not p_read */
    block_size, 0, 0)) != 0)
    goto out;
```

When decrypting the first cipher block of an incoming non-AEAD packet to
extract the packet length, `cipher_crypt` is called with
`state->p_send.seqnr` — the **outbound** sequence counter — rather than
`state->p_read.seqnr`, which is the **inbound** counter used everywhere
else in the same function (line 1593).

**Impact today:** No functional corruption occurs with the current cipher
suite.  AES-CBC and AES-CTR implementations ignore the `seqnr` argument
entirely; chacha20-poly1305 (the only SSH2 cipher that uses the seqnr as a
nonce) takes the AEAD code path where `cipher_get_length()` is used
instead, so it never reaches this branch.  The values of `p_send.seqnr`
and `p_read.seqnr` will also typically differ, meaning any future non-AEAD
cipher that does use the seqnr would silently decrypt the first block with
the wrong nonce — producing garbage packet lengths without a clear error
indication.

**Recommendation:** Replace `state->p_send.seqnr` with
`state->p_read.seqnr` at line 1526.

---

## 17. Unbounded Decompression in `uncompress_buffer()` (Zip Bomb)

**File:** `packet.c:777-822`
**Severity:** MEDIUM

```c
for (;;) {
    ssh->state->compression_in_stream.next_out = buf;
    ssh->state->compression_in_stream.avail_out = sizeof(buf);  /* 4096 bytes */
    status = inflate(..., Z_SYNC_FLUSH);
    switch (status) {
    case Z_OK:
        sshbuf_put(out, buf, sizeof(buf) - ...avail_out);  /* no output cap */
        break;
    case Z_BUF_ERROR:
        return 0;   /* only exit: zlib says "done" */
    ...
    }
}
```

The `inflate()` loop appends decompressed data to `out` indefinitely.
There is no limit on the total decompressed output size.

Incoming encrypted packets are capped at `PACKET_MAX_SIZE` = 256 KB
(line 106), but that limit applies to the ciphertext, not the plaintext.
A 256 KB maximally-compressed payload can expand to hundreds of megabytes.
A malicious peer that has completed key exchange can therefore trigger a
memory-exhaustion condition with a single packet.

**Trigger window:** `COMP_DELAYED` compression (`zlib@openssh.com`)
activates after authentication; legacy `COMP_ZLIB` activates immediately
after key exchange without requiring authentication.

**Recommendation:** Track the total bytes written to `out` inside the
loop and return `SSH_ERR_INVALID_FORMAT` when the total exceeds a
reasonable bound (e.g. `PACKET_MAX_SIZE * 8` or a configurable constant).

---

## 18. `kex_from_blob()` Hardcodes `kex->server = 1` Without Documentation

**File:** `packet.c:2436`
**Severity:** INFO

```c
kex->server = 1;   /* unconditional, regardless of actual role */
kex->done = 1;
```

`kex_from_blob()` deserialises the key-exchange state from the privilege-
separation blob.  It unconditionally sets `kex->server = 1` with no
comment, assertion, or parameter to indicate that this is intentionally
server-only.

In the current call graph this is always correct: `kex_from_blob` is
only reached via `ssh_packet_set_state()`, which is only called in the
monitor (always the server side).  However, the function has no guard
that prevents future use in a client-side privsep or multiplexer context.
If `kex_from_blob` were reused there, the client's kex struct would be
silently misconfigured as a server, corrupting algorithm dispatch and
session setup without a clear error.

**Recommendation:** Either pass the role as a parameter to `kex_from_blob`
(e.g. `int is_server`) and assign it there, or add an assertion that
the call site is always the server side.

---

## 19. `ssh_packet_disconnect()` Uses a Process-Global `static int disconnecting`

**File:** `packet.c:1976`
**Severity:** INFO

```c
void ssh_packet_disconnect(struct ssh *ssh, const char *fmt, ...)
{
    static int disconnecting = 0;   /* process-global, not per-connection */
    if (disconnecting)
        fatal("packet_disconnect called recursively.");
    disconnecting = 1;
    ...
    cleanup_exit(255);
}
```

The recursion guard is a process-global static variable, not a member of
`struct session_state`.  In any context where multiple `struct ssh`
objects exist in the same process (the ssh connection multiplexer, future
multi-connection daemon designs), calling `ssh_packet_disconnect` on any
one connection permanently sets `disconnecting = 1` for the entire process.
A subsequent legitimate disconnect call for a *different* connection would
hit `fatal("packet_disconnect called recursively.")` instead of sending the
proper `SSH2_MSG_DISCONNECT` message and closing cleanly.

In current OpenSSH sshd usage the function always calls `cleanup_exit(255)`
before returning, so the guard is never "left set" in practice.  The
pattern is nonetheless unsafe for any multi-connection reuse of this code.

**Recommendation:** Move `disconnecting` into `struct session_state` as a
per-connection flag.

---

## 20. Potential Shift UB in Rekey Block-Limit Calculation

**File:** `packet.c:946`
**Severity:** INFO

```c
if (enc->block_size >= 16)
    *max_blocks = (u_int64_t)1 << (enc->block_size * 2);
```

For `enc->block_size = 32` the shift amount would be 64, which is
**undefined behaviour** in C (C11 §6.5.7p3: the shift amount must be less
than the width of the promoted left operand — 64 bits for `u_int64_t`).

No standard SSH2 cipher has a 32-byte block size (AES uses 16 bytes), so
this is not reachable in practice today.  The `>= 16` guard does not
prevent a future cipher registration with a larger block size from silently
invoking UB, and compilers are permitted to assume this path is unreachable,
potentially misoptimising surrounding code.

**Recommendation:** Add an explicit upper-bound guard:
```c
if (enc->block_size >= 16 && (enc->block_size * 2) < 64)
    *max_blocks = (u_int64_t)1 << (enc->block_size * 2);
else
    *max_blocks = UINT64_MAX;   /* effectively unlimited; rely on rekey_limit */
```

---

## 21. `newkeys_from_blob()` Validates MAC Key Length but Not Cipher Key/IV Lengths

**File:** `packet.c:2375-2404`
**Severity:** LOW

```c
if ((r = sshbuf_get_string(b, &enc->key, &keylen)) != 0 ||
    (r = sshbuf_get_string(b, &enc->iv,  &ivlen))  != 0)
    goto out;
...
/* MAC key IS validated: */
if (maclen > mac->key_len) { r = SSH_ERR_INVALID_FORMAT; goto out; }
mac->key_len = maclen;

/* Cipher key and IV are NOT validated: */
enc->key_len = keylen;   /* taken blindly from the blob */
enc->iv_len  = ivlen;    /* taken blindly from the blob */
```

The MAC key length deserialized from the privsep blob is cross-checked
against the expected `mac->key_len` for the negotiated MAC algorithm.
The cipher key and IV lengths are not checked against the cipher's
expected sizes — they are stored and later forwarded to `cipher_init()`
directly.  A mismatch results in silent key truncation or extension; the
error (if any) surfaces only at cipher initialisation time, not at blob-
parse time.

**Attack surface:** The state blob is written by the privileged monitor
process and consumed in `ssh_packet_set_state()` during the privsep
handoff.  Tampering requires compromising the network child, which is a
high bar.  This is nonetheless a defence-in-depth gap given that the MAC
key receives validation the cipher keys do not.

**Recommendation:** After resolving the cipher name with `cipher_by_name`,
validate key and IV lengths:
```c
if (keylen != cipher_keylen(enc->cipher) ||
    ivlen  != cipher_ivlen(enc->cipher)) {
    r = SSH_ERR_INVALID_FORMAT;
    goto out;
}
```

---

## 22. UMAC 16 MB Message Limit Not Enforced at Runtime

**File:** `umac.c:827-848` (`poly_hash()`)
**Severity:** LOW

```c
/* umac.c:827-831 — documented but never enforced */
/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * implementation does not handle all ramp levels. Because we don't handle
 * the ramp up to p128 modulus in this implementation, we are limited to
 * 2^14 poly_hash() invocations per stream (for a total capacity of 2^24
 * bytes input to UMAC per tag, ie. 16MB).
 */
static void poly_hash(uhash_ctx_t hc, UINT32 data_in[])
{
    /* called once per 1024-byte chunk — no invocation counter, no guard */
```

UMAC RFC 4418 §4.1 specifies a ramped polynomial scheme that transitions
from a p64 modulus (for short messages) to a p128 modulus (for messages
over 16 MB).  This implementation only handles the p64 stage.  After
2^14 calls to `poly_hash()` (one per 1024-byte NH block, totalling 16 MB),
the polynomial accumulator cycles beyond the p64 domain silently, producing
a structurally valid but cryptographically wrong MAC tag — with no error
return, no assertion, and no counter to detect the overflow.

**In SSH:** each SSH packet is independently capped at `PACKET_MAX_SIZE`
(~256 KB), and each packet gets its own `umac_final()` call, so individual
UMAC sessions never approach 16 MB.  The limit is not reachable in practice.

**Risk:** no assertion or runtime check documents the invariant that keeps
this safe.  If UMAC were reused with a message stream that exceeds 16 MB
(e.g. in a future bulk-data path or an external caller linking against this
code), the wrong MAC would be produced silently — potentially allowing a MAC
forgery without any error indication.

**Recommendation:** Add a runtime guard in `uhash_update()`:
```c
if (ctx->msg_len + len > (1UL << 24))
    return SSH_ERR_INVALID_FORMAT;   /* or fatal() */
```

---

## 23. Signed Integer Overflow in `nh_final()` — `bytes_hashed << 3`

**File:** `umac.c:692`
**Severity:** INFO

```c
/* nh_ctx.bytes_hashed is declared 'int' (line 325) */
nbits = (hc->bytes_hashed << 3);   /* UB if bytes_hashed > 2^28 */
```

Left-shifting a `signed int` into or past the sign bit is undefined
behaviour (C11 §6.5.7p4).  If `bytes_hashed` exceeded 2^28 (256 MB),
`bytes_hashed * 8` would overflow a 32-bit signed integer.  The result is
then added to all NH state accumulators, corrupting the hash output.

**In practice** `bytes_hashed` is reset by `nh_reset()` after each 1024-byte
block (called from `nh_final()`), so its value never exceeds 1024.  The UB
is unreachable given SSH packet-size constraints.

Compare with `nh()` (line 718): `UINT32 nbits = (unpadded_len << 3)` —
the same computation performed on an *unsigned* type, which is well-defined.
The inconsistency in type choice between the two code paths is the root issue.

**Recommendation:** Declare `bytes_hashed` as `UINT32` (matching its
initialiser and all its arithmetic counterparts), or cast before shifting:
```c
nbits = ((UINT32)hc->bytes_hashed << 3);
```

---

## 24. `kdf()` Counter Byte Truncation — Silent Wrap at 256 AES Blocks

**File:** `umac.c:199`
**Severity:** INFO

```c
static void kdf(void *bufp, aes_int_key key, UINT8 ndx, int nbytes)
{
    UINT8 in_buf[AES_BLOCK_LEN] = {0};
    int i;
    in_buf[AES_BLOCK_LEN-1] = i = 1;

    while (nbytes >= AES_BLOCK_LEN) {
        aes_encryption(in_buf, out_buf, key);
        in_buf[AES_BLOCK_LEN-1] = ++i;   /* int → UINT8: wraps at i=256 */
        nbytes -= AES_BLOCK_LEN;
```

The AES counter is maintained as an `int` variable `i` but stored in a
single `UINT8` array slot.  The assignment `in_buf[AES_BLOCK_LEN-1] = ++i`
silently truncates the `int` to 8 bits.  When `i` reaches 256 (after 256
AES encryptions / 4096 bytes derived), the stored counter byte wraps back
to 0, causing the counter-mode keystream to repeat from the beginning.
A repeated keystream reveals the XOR of the two messages encrypted at the
same counter position — in a KDF context, this means derived key material
could partially repeat.

**In practice** the maximum `nbytes` ever requested is
`(8 * STREAMS + 4) * sizeof(UINT64)` = 352 bytes (for `STREAMS = 4`), which
requires only ~22 AES encryptions.  The wrap is unreachable.

**Recommendation:** Use a `UINT8` loop counter with an explicit static
assert, or add a defensive check:
```c
static_assert(/* max nbytes across all kdf callers */ <= 256 * AES_BLOCK_LEN,
              "kdf counter would wrap");
```

---

## 25. Pervasive Strict-Aliasing UB via `UINT8*` → `UINT64*`/`UINT32*` Casts

**File:** `umac.c` throughout (e.g. lines 258–278, 346, 362, 380, 483–487, 693–701, 720–728)
**Severity:** INFO

```c
/* pdf_gen_xor() — nonce is const UINT8* */
*(UINT32 *)t.tmp_nonce_lo = ((const UINT32 *)nonce)[1];

/* nh_aux() — hp is void* passed from a UINT8 buffer */
h = *((UINT64 *)hp);

/* nh_final() — result is UINT8* */
((UINT64 *)result)[0] = ((UINT64 *)hc->state)[0] + nbits;
```

Accessing a `UINT8` array through `UINT64*` or `UINT32*` pointers violates
the C11 strict-aliasing rule (§6.5p7): a stored value may only be accessed
by a pointer to a compatible type, a character type, or a union member.
Under `-O2` or higher, GCC and Clang are permitted to assume that accesses
through incompatible pointer types cannot alias, and may reorder or eliminate
such loads and stores.

The union trick (`union { UINT8 tmp_nonce_lo[4]; UINT32 align; }`) is used
correctly in `pdf_gen_xor` for the nonce comparison, but the XOR output
operations and the `nh_aux`/`nh_final` paths use raw casts without a union
wrapper, which is not sanctioned by the standard even on aligned buffers.

**In practice** this is harmless on x86-64 with current GCC/Clang — the
pointer casts survive optimisation without incorrect reordering.  The
`FORCE_C_ONLY` comment at line 64 and the GCC `-O3` correctness note at
line 44 ("incorrect results are sometimes produced") suggest the original
author was aware that aggressive optimisation interacts poorly with this
code.

**Recommendation:** Replace raw pointer casts with `memcpy` for
portability and strict-aliasing correctness, or use `__attribute__((may_alias))` on
the pointer types used for multi-byte loads.

---

## 26. `long len` Silently Truncated to `UINT32` at `nh_update()` Boundary

**File:** `umac.c:1044` (`uhash_update()`), `umac.c:613` (`nh_update()`)
**Severity:** INFO

```c
/* umac_update() and uhash_update() both take 'long len' */
int umac_update(struct umac_ctx *ctx, const u_char *input, long len)
    → uhash_update(uhash_ctx_t ctx, const u_char *input, long len)
        → nh_update(nh_ctx *hc, const UINT8 *buf, UINT32 nbytes)  /* truncation here */
```

The public-facing `umac_update()` and internal `uhash_update()` accept a
`long len`, but the inner `nh_update()` takes a `UINT32 nbytes` parameter.
The conversion from `long` to `UINT32` at the `nh_update()` call site is
implicit and silent.  If `len` were greater than `UINT32_MAX` (4 GB),
`nbytes` would be the low 32 bits of `len` — processing far less data than
requested — and the resulting MAC would be computed over a truncated message
without any error indication.

**In SSH:** packets are bounded by `PACKET_MAX_SIZE` (~256 KB), making the
truncation unreachable.  The type inconsistency across the three call-stack
levels (`long` → `long` → `UINT32`) is nonetheless a latent hazard if any
future code path passes a larger buffer.

**Recommendation:** Change `nh_update()`'s `nbytes` parameter to `size_t`
(matching the standard convention for buffer lengths), add a bounds check
in `uhash_update()`:
```c
if (len > (1UL << 24))
    return SSH_ERR_INVALID_FORMAT;
```
or add a `static_assert` that `PACKET_MAX_SIZE < UINT32_MAX` to document
the assumed invariant.

---

## Summary

| # | File | Severity | Remote? | Priv-esc? | Description |
|---|------|----------|---------|-----------|-------------|
| 1 | sshd-socket-generator.c:136 | **HIGH** | No | No (no setuid) | OOB read in `path_append()` on empty base |
| 2 | sshd.c:1054,1065 | **HIGH** | No | No | `strtonum` failure returns `-errno`; errno not set by strtonum |
| 3 | sshd-socket-generator.c:327 | **MEDIUM** | No | No (no setuid) | No validation of `argv[1]` destination path — path traversal |
| 4 | sshd-socket-generator.c:192-203 | **MEDIUM** | No | **Yes, if via systemd** | TOCTOU race / symlink attack between `mkdir` and `fopen` |
| 5 | sshd-socket-generator.c:310-311 | **MEDIUM** | No | No | Return values of `load_server_config`/`parse_server_config` ignored (false positive — both are void) |
| 6 | sshd-socket-generator.c:105 | **LOW** | No | No | No explicit null terminator after `memcpy` |
| 7 | sshd-socket-generator.c:123 | **LOW** | No | No | `listen_stream_set_len` breaks on first empty slot — fragile |
| 8 | sshd-socket-generator.c:331,345 | **INFO** | No | No | Typos in error messages |
| 9 | auth2.c:289-326 | **LOW** | **Yes** | No | Unsanitised `role`/`style` from client passed to PAM and `setproctitle` |
| 10 | auth2.c:286 | **INFO** | **Yes** | No | Raw client strings logged before validation — log injection |
| 11 | auth2.c:263-264 | **INFO** | No | No | Implicit `double`→`time_t` cast in timing delay; unchecked for out-of-range |
| 12 | kex.c:185 | **LOW** | **Yes (if GSSAPI)** | No | GSS algorithm lookup uses `strncmp` prefix match; crafted names with extra suffixes match known entries |
| 13 | kex.c:1622 | **LOW** | **Yes** | No | Control characters in SSH version banner not filtered; log injection before key exchange |
| 14 | kex.c:1194 | **INFO** | No | No | `proposals_match` permanently mutates proposal strings — latent correctness hazard |
| 15 | kex.c:746 | **INFO** | **Yes (client)** | No | No length cap on `server-sig-algs` EXT_INFO value; malicious server can induce O(n·m) algorithm-matching work |
| 16 | packet.c:1526 | **LOW** | **Yes** | No | Wrong seqnr (`p_send` vs `p_read`) in non-AEAD first-block decryption |
| 17 | packet.c:777-820 | **MEDIUM** | **Yes** | No | No decompression output size limit in `uncompress_buffer()` — zip bomb / memory exhaustion |
| 18 | packet.c:2436 | **INFO** | No | No | `kex_from_blob()` hardcodes `kex->server = 1`; unsafe if ever used in non-server context |
| 19 | packet.c:1976 | **INFO** | No | No | `static int disconnecting` is process-global, not per-connection — unsafe for multi-connection reuse |
| 20 | packet.c:946 | **INFO** | No | No | Shift UB: `1 << (block_size*2)` is undefined for `block_size >= 32` |
| 21 | packet.c:2375-2404 | **LOW** | No | No | MAC key length validated in `newkeys_from_blob()`; cipher key/IV lengths are not |
| 22 | umac.c:833 (`poly_hash`) | **LOW** | No | No | 16 MB UMAC message limit documented but not enforced — silent wrong-MAC above threshold |
| 23 | umac.c:692 (`nh_final`) | **INFO** | No | No | `bytes_hashed << 3` signed-int UB for inputs > 256 MB |
| 24 | umac.c:199 (`kdf`) | **INFO** | No | No | KDF counter stored in `UINT8` without explicit cast — silent wrap at 256 AES blocks |
| 25 | umac.c (pervasive) | **INFO** | No | No | `UINT8*` → `UINT64*`/`UINT32*` type-punning violates strict-aliasing rule |
| 26 | umac.c:1044/613 | **INFO** | No | No | `long len` silently truncated to `UINT32` at `nh_update()` boundary |

**Remote exploitability:** Findings 1–8 are not reachable via port 22 —
they affect `sshd-socket-generator` (a boot-time utility) or a startup-only
code path in `sshd.c`.  Findings 9, 10, 12, 13, 16, and 17 are reachable
by any connecting client.  Finding 13 is the earliest — reachable before
key exchange begins.  Finding 17 requires key exchange (and for
`zlib@openssh.com`, authentication) to be complete first.  Finding 15
affects SSH clients connecting to a malicious server.  Findings 22–26
(`umac.c`) are not remotely reachable: the 16 MB threshold (finding 22)
and the type issues (findings 23–26) are never triggered within SSH's
PACKET_MAX_SIZE limit.

**Privilege escalation:** No finding enables direct privilege escalation.
Finding #4 (TOCTOU) is a privilege-escalation primitive only when systemd
triggers the generator as root and requires chaining with at least one
additional condition.  The `sshd-socket-generator` binary is installed
without a setuid bit (`-rwxr-xr-x`).

---

## Man-in-the-Middle Attack Analysis

This section documents SSH's resistance to man-in-the-middle (MITM) attacks
at the protocol level, the conditions under which that resistance fails, and
the recommended mitigations.  Unlike the numbered findings above, this is a
deployment and configuration concern rather than a code-level bug.

### How SSH resists MITM

SSH authenticates the **server to the client** using asymmetric cryptography.
On every connection the server signs a challenge with its private host key
(`/etc/ssh/ssh_host_ed25519_key`, etc.).  The client verifies that signature
against the corresponding public key it has previously recorded in
`~/.ssh/known_hosts`.  If the key has changed, the client refuses to connect:

```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
```

An on-path attacker who does not possess the server's private host key
**cannot** forge the signature.  All session traffic is then protected by an
ephemeral ECDH session key (curve25519-sha256 by default) negotiated over the
authenticated channel, so passive interception of recorded traffic is also
infeasible.

### Where SSH is vulnerable to MITM

#### 1. Trust On First Use (TOFU) — the primary attack window

On the **first ever connection** to a host the client has nothing in
`known_hosts` to compare against.  It prompts:

```
The authenticity of host 'example.com (203.0.113.5)' can't be established.
ED25519 key fingerprint is SHA256:abc123...xyzXYZ.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

If the user types `yes` without verifying the fingerprint out-of-band, an
on-path attacker can silently substitute their own public key.  The client
stores the attacker's key, and all future sessions are transparently proxied
with no indication of compromise.  **This is the canonical SSH MITM attack —
it works exactly once, on the first connection.**

Affected code path: `sshconnect.c` → `verify_host_key()` → `check_host_key()`
→ `get_hostfile_hostname_ipaddr()`.  The interactive prompt that most users
accept without thought is the sole defence at this point.

#### 2. `StrictHostKeyChecking no` — MITM on every connection

```
# In ~/.ssh/config or /etc/ssh/ssh_config:
Host *
    StrictHostKeyChecking no
```

With this setting the client silently accepts any host key — including one
substituted by an attacker — on every connection, not just the first.  This
configuration is extremely common in CI/CD pipelines, Docker images, and
automation scripts where the convenience of non-interactive operation is
prioritised over security.

`StrictHostKeyChecking accept-new` is a slightly safer variant: it accepts
new keys silently but refuses to connect if a *stored* key changes.  It
still leaves the first-connection window open.

#### 3. `UserKnownHostsFile /dev/null`

```
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no user@host
```

Discards all learned host keys.  Every connection behaves as a first
connection; the TOFU window is permanently open.  Common in throwaway
containers and test environments.

#### 4. DNS or ARP spoofing before the first connection

If an attacker controls the DNS resolution or ARP responses that route the
client's first TCP connection, they can direct the client to their own server,
serve their own host key, and have it stored legitimately in `known_hosts`.
All subsequent connections to that hostname (via the spoofed key) are then
silently proxied.

#### 5. Host key compromise

If an attacker obtains the server's private host key (from
`/etc/ssh/ssh_host_*_key`) they can impersonate the server to any client that
has already stored the corresponding public key.  File permissions on these
keys are `0600` root-only, but they are copied into VM images, leaked in
container layers, or backed up insecurely with some regularity.

### Mitigations

#### Mitigation 1: Verify fingerprints out-of-band (eliminates TOFU)

Before accepting a new host key, compare the displayed fingerprint to one
obtained through a channel the attacker cannot influence — for example, the
cloud provider's serial console, an IPMI interface, or a configuration
management system that provisioned the server:

```bash
# On the server — display its fingerprints
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub

# On the client — verify the fingerprint shown by ssh matches
```

This is operationally awkward at scale but is the baseline defence.

#### Mitigation 2: Pre-populate `known_hosts` at provisioning time

Inject the correct host public key into `~/.ssh/known_hosts` (or the system
`/etc/ssh/ssh_known_hosts`) before the first user connection, using a trusted
out-of-band channel such as cloud-init, Ansible, or Terraform:

```bash
# Collect the host key directly from the server at provisioning time
# (only safe if done over a trusted channel or extracted from a signed image)
ssh-keyscan -t ed25519 example.com >> ~/.ssh/known_hosts

# Or copy directly from the server filesystem:
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub   # verify fingerprint first
cat /etc/ssh/ssh_host_ed25519_key.pub | \
    ssh-keygen -H -f /dev/stdin >> ~/.ssh/known_hosts
```

Note that `ssh-keyscan` over an untrusted network has the same TOFU problem
as an interactive connection — it must be run over a channel the attacker
cannot reach.

#### Mitigation 3: SSHFP DNS records with DNSSEC

SSHFP (RFC 4255) allows host key fingerprints to be published in DNS and
automatically validated by the SSH client.  **DNSSEC is required** — without
it an attacker who can spoof DNS can also spoof SSHFP records.

```bash
# On the server — generate SSHFP records to add to your zone
ssh-keygen -r example.com -f /etc/ssh/ssh_host_ed25519_key.pub
# Output: example.com IN SSHFP 4 1 <sha1>
#         example.com IN SSHFP 4 2 <sha256>

# Add to DNS zone file, sign with DNSSEC (zone must be DNSSEC-signed)
```

```
# In sshd_config / ssh_config — enable client-side SSHFP verification
VerifyHostKeyDNS yes
```

With this configuration and a DNSSEC-signed zone, the client automatically
validates the host key against DNS before prompting — eliminating the TOFU
window for any host with an SSHFP record.

#### Mitigation 4: SSH host certificates (strongest — eliminates TOFU entirely)

> **Full implementation guide: [`ca/README-cert.md`](ca/README-cert.md)**
> CA management scripts are in the [`ca/`](ca/) directory.


OpenSSH supports CA-signed host certificates.  The server presents a
certificate signed by a trusted CA; the client trusts the CA rather than
individual host keys.  This eliminates the TOFU window, enables instant
key rotation, and allows certificate revocation.

```bash
# Step 1 — Create a CA (done once, CA private key kept offline)
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ca -C "Host CA"

# Step 2 — Sign each server's host key with the CA
ssh-keygen -s /etc/ssh/ssh_host_ca \
    -I "example.com host key" \
    -h \                               # -h = host certificate (not user)
    -n "example.com,203.0.113.5" \     # valid hostnames / IPs
    -V +52w \                          # valid for 1 year
    /etc/ssh/ssh_host_ed25519_key.pub
# Produces: /etc/ssh/ssh_host_ed25519_key-cert.pub
```

```
# sshd_config — present the certificate
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

```
# ~/.ssh/known_hosts — trust the CA for the entire domain
@cert-authority *.example.com ssh-ed25519 AAAA...  (CA public key)
```

Any server presenting a valid CA-signed certificate for the connecting
hostname is trusted **without a TOFU prompt**.  Rotating host keys no longer
breaks clients; a compromised key is remediated by issuing a new certificate
and revoking the old one via a `RevokedKeys` file or KRL.

#### Mitigation 5: Never use `StrictHostKeyChecking no` in production

| Setting | Behaviour | Safe? |
|---------|-----------|-------|
| `StrictHostKeyChecking yes` | Refuses any unknown or changed key | **Yes** — use with pre-populated known_hosts |
| `StrictHostKeyChecking accept-new` | Silently accepts new keys; refuses changed keys | Partially — first connection still unprotected |
| `StrictHostKeyChecking no` | Silently accepts all keys, including changed ones | **No** |
| `UserKnownHostsFile /dev/null` | Discards all host keys | **No** |

### Attack surface summary

| Scenario | Vulnerable? | Mitigation |
|----------|-------------|------------|
| First connection to any new host | **Yes** (TOFU) | Out-of-band fingerprint verification; host certificates; SSHFP+DNSSEC |
| Established connection (host key already verified) | **No** | Protocol is cryptographically sound post-verification |
| `StrictHostKeyChecking no` configured | **Yes, always** | Remove this setting; use `yes` or `accept-new` |
| `UserKnownHostsFile /dev/null` | **Yes, always** | Remove this setting |
| DNS or ARP spoofing before first connection | **Yes** | SSHFP+DNSSEC; host certificates; out-of-band fingerprint check |
| Server host key compromised | **Yes** | Protect `/etc/ssh/ssh_host_*_key` (0600 root); use short-lived CA-signed certificates |
| Client `known_hosts` tampered | **Yes** | Protect `~/.ssh/known_hosts`; use system-wide `/etc/ssh/ssh_known_hosts` |

### Relationship to findings in this document

Finding **#15** (`kex.c:746` — no length cap on `server-sig-algs`) is the
closest code-level finding to a MITM concern: a malicious server can induce
O(n·m) algorithm-matching work on the client.  However it requires the
client to have already connected to a malicious server — i.e. MITM has
already succeeded at the host verification step.

Finding **#13** (`kex.c:1622` — log injection via version banner) is
reachable before key exchange and can be used to obscure MITM indicators
from administrators monitoring logs.

All other findings in this document are either post-authentication or
internal to a correctly established session; they do not directly enable
MITM and are not affected by whether host key verification is configured
correctly.
