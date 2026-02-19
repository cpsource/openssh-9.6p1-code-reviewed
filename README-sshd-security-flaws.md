# Security Flaw Review — OpenSSH 9.6p1 (Modified)

This document records findings from a source-level security review of the
sshd-related code in this tree, with particular focus on the new
`sshd-socket-generator.c` file, the systemd socket-activation additions
to `sshd.c`, and the SSH2 user-authentication dispatcher in `auth2.c`.

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

**Remote exploitability:** Findings 1–8 are not reachable via port 22 —
they affect `sshd-socket-generator` (a boot-time utility) or a startup-only
code path in `sshd.c`.  Findings 9, 10, 12, and 13 are reachable by any
unauthenticated remote client.  Finding 13 is reachable before key exchange
begins — earlier in the connection lifecycle than any other finding.
Finding 15 affects SSH clients connecting to a malicious server.

**Privilege escalation:** No finding enables direct privilege escalation.
Finding #4 (TOCTOU) is a privilege-escalation primitive only when systemd
triggers the generator as root and requires chaining with at least one
additional condition.  The `sshd-socket-generator` binary is installed
without a setuid bit (`-rwxr-xr-x`).
