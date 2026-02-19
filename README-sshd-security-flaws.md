# Security Flaw Review — OpenSSH 9.6p1 (Modified)

This document records findings from a source-level security review of the
sshd-related code in this tree, with particular focus on the new
`sshd-socket-generator.c` file and the systemd socket-activation additions
to `sshd.c`.

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

Because the generator typically runs as root (invoked by systemd), a
successful race allows an attacker to truncate or overwrite an arbitrary file
owned by root.

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

## Summary

| # | File | Severity | Description |
|---|------|----------|-------------|
| 1 | sshd-socket-generator.c:136 | **HIGH** | OOB read in `path_append()` on empty base |
| 2 | sshd.c:1054,1065 | **HIGH** | `strtonum` failure returns `-errno`; errno not set by strtonum |
| 3 | sshd-socket-generator.c:327 | **MEDIUM** | No validation of `argv[1]` destination path — path traversal |
| 4 | sshd-socket-generator.c:192-203 | **MEDIUM** | TOCTOU race / symlink attack between `mkdir` and `fopen` |
| 5 | sshd-socket-generator.c:310-311 | **MEDIUM** | Return values of `load_server_config`/`parse_server_config` ignored |
| 6 | sshd-socket-generator.c:105 | **LOW** | No explicit null terminator after `memcpy` |
| 7 | sshd-socket-generator.c:123 | **LOW** | `listen_stream_set_len` breaks on first empty slot — fragile |
| 8 | sshd-socket-generator.c:331,345 | **INFO** | Typos in error messages |
