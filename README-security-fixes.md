# Security Fixes — OpenSSH 9.6p1

This document describes the fixes applied on branch `security-flaw-fixes` in
response to the findings in `README-sshd-security-flaws.md`.

One finding (#5 — ignored return values of `load_server_config` /
`parse_server_config`) was determined to be a false positive: both functions
return `void` and call `fatal()` internally on error, so no fix was required.

---

## Fix 1 — Out-of-Bounds Read in `path_append()` (HIGH)

**Finding:** #1 in README-sshd-security-flaws.md
**File:** `sshd-socket-generator.c`

### Problem

```c
len_base = strnlen(base, PATH_MAX);
add_slash = base[len_base - 1] != '/';   /* OOB when len_base == 0 */
```

When `base` is an empty string `strnlen` returns 0 and the code reads
`base[-1]` — one byte before the buffer — causing undefined behaviour.
`base` originates from `argv[1]`, which is attacker-controlled.

### Fix

```c
len_base = strnlen(base, PATH_MAX);
if (len_base == 0)
        return NULL;
add_slash = base[len_base - 1] != '/';
```

An early return of `NULL` on an empty base path is handled correctly by all
callers, which already check the return value for `NULL`.

---

## Fix 2 — `strtonum` Failure Returns `-errno` Instead of `-EINVAL` (HIGH)

**Finding:** #2 in README-sshd-security-flaws.md
**File:** `sshd.c`

### Problem

```c
listen_pid = (pid_t)strtonum(listen_pid_str, 2, INT_MAX, &errstr);
if (errstr != NULL)
        return -errno;   /* BUG: strtonum does not set errno */
```

`strtonum(3)` signals errors via its `errstr` output parameter and does
**not** set `errno`. When `strtonum` fails and `errno` is 0 (common at that
point in startup), the function returns 0 instead of a negative error code.
The caller treats a non-negative return as a valid fd count:

```c
r = get_systemd_listen_fds();
if (r < 0)
        fatal(...);
systemd_num_listen_fds = r;   /* silently set to 0 */
```

With `systemd_num_listen_fds = 0`, sshd skips socket activation entirely and
opens its own listening sockets — potentially on different addresses or ports
than intended by the systemd unit, and without the socket options systemd
would have configured.

The same bug appears on both the `LISTEN_PID` and `LISTEN_FDS` parsing paths.

### Fix

```c
if (errstr != NULL)
        return -EINVAL;
```

Applied to both `strtonum` call sites in `get_systemd_listen_fds()`.

---

## Fix 3 — Path Traversal via Unvalidated `argv[1]` (MEDIUM)

**Finding:** #3 in README-sshd-security-flaws.md
**File:** `sshd-socket-generator.c`

### Problem

```c
destdir = argv[1];
r = write_systemd_socket_file(destdir);   /* creates files under destdir */
```

No validation was performed on `destdir`. Passing a relative path such as
`../../../etc/cron.d` causes the generator to create
`../../../etc/cron.d/ssh.socket.d/addresses.conf` — an arbitrary file whose
content is partially influenced by the sshd config. The generator binary is
world-executable.

### Fix

```c
if (destdir[0] != '/') {
        fprintf(stderr, "Destination directory must be an absolute path.\n");
        return EXIT_FAILURE;
}
```

Relative paths are rejected before any file-system operations are attempted.

---

## Fix 4 — TOCTOU / Symlink Attack Between `mkdir` and File Creation (MEDIUM)

**Finding:** #4 in README-sshd-security-flaws.md
**File:** `sshd-socket-generator.c`

### Problem

```c
mkdir(overridedir, 0755);          /* step 1 */
...
f = fopen(conf, "we");             /* step 2 — follows symlinks */
```

Between step 1 and step 2 a local attacker can:
- Replace `overridedir` with a symlink to an arbitrary directory, causing the
  subsequent file creation to land in the wrong location.
- Pre-place a symlink at `<overridedir>/addresses.conf` pointing to any file.

`fopen` with mode `"we"` adds `O_CLOEXEC` but does **not** add `O_NOFOLLOW`,
so both attacks succeed. Because the generator runs as root, a successful race
allows truncation or overwrite of an arbitrary root-owned file.

### Fix

Replaced `fopen` with a two-step approach using `open(2)` and `openat(2)`,
both with `O_NOFOLLOW`:

```c
/* Open the directory — fails if overridedir was replaced with a symlink */
dirfd = open(overridedir,
    O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);

/* Create the file relative to dirfd — fails if a symlink was pre-placed */
conffd = openat(dirfd, "addresses.conf",
    O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC, 0644);

f = fdopen(conffd, "w");
```

Both `dirfd` and `conffd` are tracked and closed in the `out:` cleanup block.

---

## Fix 5 — Missing Null Terminator After `memcpy` (LOW)

**Finding:** #6 in README-sshd-security-flaws.md
**File:** `sshd-socket-generator.c`

### Problem

```c
memcpy(set[i], listen_stream, n);
return 0;   /* no null terminator written */
```

The code relied implicitly on the zero-initialisation of the
`listen_streams` array to provide null termination. If that initialisation
were ever removed or the array repurposed, strings passed to
`fprintf(f, "%s\n", listen_streams[i])` would be unterminated.

### Fix

```c
memcpy(set[i], listen_stream, n);
set[i][n] = '\0';
```

The terminator is now written explicitly, making the invariant
self-documenting and robust against future refactoring.

---

## Fix 6 — `listen_stream_set_len()` Breaks on First Empty Slot (LOW)

**Finding:** #7 in README-sshd-security-flaws.md
**File:** `sshd-socket-generator.c`

### Problem

```c
for (int i = 0; i < MAX_LISTEN_STREAMS; i++) {
        if (strnlen(set[i], MAX_LISTEN_STREAM_LEN) > 0)
                r++;
        else
                break;   /* stops at first empty slot */
}
```

The early `break` assumes entries are always stored in a contiguous run
starting at slot 0. This is currently true, but the assumption is fragile:
any future change to `listen_stream_set_append` that causes non-contiguous
storage (e.g. skipping a slot after deduplication) would silently under-count
entries, resulting in incomplete socket configuration being written.

### Fix

```c
for (int i = 0; i < MAX_LISTEN_STREAMS; i++) {
        if (strnlen(set[i], MAX_LISTEN_STREAM_LEN) > 0)
                r++;
}
```

All slots are now checked unconditionally.

---

## Fix 7 — Typos in Error Messages (INFO)

**Finding:** #8 in README-sshd-security-flaws.md
**File:** `sshd-socket-generator.c`

| Line | Before | After |
|------|--------|-------|
| 331 | `"Faild to parse sshd config"` | `"Failed to parse sshd config"` |
| 345 | `"Will not generated anything."` | `"Will not generate anything."` |

---

## False Positive — Finding #5 (Ignored Config Function Return Values)

**Finding:** #5 in README-sshd-security-flaws.md
**File:** `sshd-socket-generator.c`

The finding suggested that `load_server_config()` and `parse_server_config()`
return values were ignored. On inspection both functions are declared `void`
in `servconf.h` — they call `fatal()` internally on error and never return a
status code. No fix was required or applied.
