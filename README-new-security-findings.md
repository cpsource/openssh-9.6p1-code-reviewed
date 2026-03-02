# New Security Findings — OpenSSH 9.6p1

This document records findings from an independent source-level security review
of the core `ssh` / `sshd` code. All findings were verified directly against
the source.  Previously-documented findings (see `README-sshd-security-flaws.md`)
and their corresponding fixes (`README-security-fixes.md`) are confirmed applied
and are not repeated here.

Severity ratings: **CRITICAL / HIGH / MEDIUM / LOW / INFO**

---

## Finding 1 — Wrong Sequence Number in First-Block Decryption

**File:** `packet.c:1539`
**Severity:** LOW (latent bug; no security impact against current cipher suite)

### Code

```c
/* non-AEAD path: decrypt first block to extract packlen */
if ((r = cipher_crypt(state->receive_context,
    state->p_send.seqnr,          /* BUG: should be p_read.seqnr */
    cp, sshbuf_ptr(state->input),
    block_size, 0, 0)) != 0)
    goto out;
```

### Description

When decrypting an incoming packet's first block (used to read the 4-byte
packet length), the code passes the **send** sequence number
(`state->p_send.seqnr`) to `cipher_crypt()` instead of the **receive**
sequence number (`state->p_read.seqnr`).  This is a receive operation using
the receive context; the wrong directional counter is used.

### Why There Is No Current Security Impact

`cipher_crypt()` only consumes the `seqnr` argument for ChaCha20-Poly1305
(`CFLAG_CHACHAPOLY`).  For that cipher `cipher_authlen() != 0`, so `authlen`
is set non-zero at line 1504, which forces `aadlen = 4` at line 1509.  When
`aadlen != 0` the early AEAD branch at line 1511 is taken and the code never
reaches line 1539.  For all remaining ciphers — AES-CBC, AES-CTR — the seqnr
parameter inside `cipher_crypt()` is completely ignored.  AES-GCM likewise has
`authlen != 0` and skips line 1539.

### Risk

Any future cipher that (a) uses `seqnr` for encryption/decryption and (b) has
`authlen == 0` (i.e. is not AEAD in the OpenSSH sense) would silently receive
the wrong nonce on every incoming packet, breaking its cryptographic integrity
guarantees without any compile-time or runtime warning.

### Recommendation

Change `state->p_send.seqnr` to `state->p_read.seqnr` at line 1539.

---

## Finding 2 — Integer Underflow in `need` Computation

**File:** `packet.c:1568`
**Severity:** LOW (integer underflow confirmed; mitigated by an existing runtime guard)

### Code

```c
u_int need;        /* declared at line 1483 */
...
/* non-AEAD branch */
need = 4 + state->packlen - block_size;   /* can wrap when packlen < block_size - 4 */
...
if (need % block_size != 0) {             /* line 1572 — catches the wrap */
    logit("padding error: need %d block %d mod %d", need, block_size, need % block_size);
    return ssh_packet_start_discard(ssh, enc, mac, 0, PACKET_MAX_SIZE - block_size);
}
```

### Description

`need` is declared `u_int` (unsigned).  `packlen` is validated to be at least 5
(line 1543), but for AES-128 (`block_size = 16`) a `packlen` value in the range
5–11 produces `4 + packlen - block_size < 0`, which as an unsigned subtraction
wraps to approximately `UINT_MAX - k`.  The underflow is real.

### Why It Is Mitigated

The modulo check immediately following the computation (line 1572) catches all
underflowing cases for all current cipher block sizes:

- **AES-128/256** (`block_size = 16`): `packlen` 5–11 → wrapped `need` values
  are never divisible by 16 → always routed to `ssh_packet_start_discard`.
- **3DES** (`block_size = 8`): minimum valid `packlen = 5` → `need = 1`, which
  is not divisible by 8 → caught.

For `packlen = 12` with AES (`need = 0`), the result is mathematically valid —
zero additional bytes are needed because the entire packet fit in the first
block.

### Risk

The integer underflow is real but currently fully contained by the modulo guard.
A future code refactor that removes, moves, or reorders that guard would
immediately expose a path where `sshbuf_reserve()` is called with an allocation
request of ≈ `UINT_MAX` bytes, causing instant DoS.

### Recommendation

Add an explicit guard before the subtraction:

```c
if (4 + state->packlen < block_size) {
    /* entire payload fits in first block; need = 0 */
    need = 0;
} else {
    need = 4 + state->packlen - block_size;
}
```

This makes the intent explicit and eliminates reliance on the modulo check to
catch the underflow.

---

## Finding 3 — Integer Overflow in Channel Window-Exceeded Counter

**File:** `channels.c:3410`
**Severity:** MEDIUM (post-auth denial of service; requires sustained exploitation)

### Code

```c
/* channel_data_input_confirm(), channels.c */
if (win_len > c->local_window) {
    /* u_int += (size_t - u_int): wraps after > UINT_MAX bytes of excess */
    c->local_window_exceeded += win_len - c->local_window;
    logit("channel %d: rcvd too much data %zu, win %u/%u (excess %u)",
        c->self, win_len, c->local_window, c->local_window_max,
        c->local_window_exceeded);
    c->local_window = 0;
    /* Allow 10% grace before bringing the hammer down */
    if (c->local_window_exceeded > (c->local_window_max / 10)) {
        ssh_packet_disconnect(ssh, "channel %d: peer ignored "
            "channel window", c->self);
    }
} else {
    c->local_window -= win_len;
    c->local_window_exceeded = 0;   /* reset only when within window */
}
```

### Description

`local_window_exceeded` is `u_int` (unsigned 32-bit).  An authenticated peer
that repeatedly sends data packets exceeding the local channel window
accumulates this counter across calls.  If the attacker carefully sizes each
burst so that the running total approaches `UINT_MAX` without a single
in-window packet (which would reset the counter to 0 at line 3422), the counter
wraps back toward zero.

Once wrapped, `c->local_window_exceeded` is again small, the 10%-grace check
at line 3416 fails to trigger `ssh_packet_disconnect`, and the attacker may
continue feeding unbounded data into the channel's `c->output` buffer without
enforcement.

### Impact

An authenticated attacker can exhaust sshd's memory by continuously violating
the channel flow-control window without ever being disconnected, as long as they
avoid sending any in-window packet that would reset the counter.

`local_window_max` is typically 2 MB, so `UINT_MAX / (local_window_max / 10)`
≈ 21,474 window-exceeding packets are needed to wrap the counter.  The attacker
must also keep each burst below `local_window_max / 10` to stay under the grace
threshold on every individual check.

### Recommendation

Use a saturating add or clamp the counter at `UINT_MAX`:

```c
u_int excess = (win_len > c->local_window) ? win_len - c->local_window : 0;
if (c->local_window_exceeded <= UINT_MAX - excess)
    c->local_window_exceeded += excess;
else
    c->local_window_exceeded = UINT_MAX;   /* saturate — never wraps */
```

Alternatively, promote `local_window_exceeded` to `u_int64_t`.

---

## Finding 4 — Dead / Unreachable Underflow Guard in Padding Calculation

**File:** `packet.c:1153–1156`
**Severity:** LOW (dead code; misleading comment)

### Code

```c
tmp = (len + padlen) % state->extra_pad;
/* Check whether pad calculation below will underflow */
if (tmp > state->extra_pad)           /* ← this condition can NEVER be true */
    return SSH_ERR_INVALID_ARGUMENT;
pad = state->extra_pad - tmp;
```

### Description

`tmp` is assigned the result of `X % state->extra_pad`.  By the mathematical
definition of the modulo operation, the result satisfies `0 <= tmp < extra_pad`
strictly — the remainder is always less than the divisor.

The guard `if (tmp > state->extra_pad)` is therefore **unreachable dead code**:
it can never evaluate to true.  The accompanying comment ("Check whether pad
calculation below will underflow") is also misleading, because the subtraction
`pad = extra_pad - tmp` is already unconditionally safe given the modulo
invariant.

### Risk

No immediate security impact.  The concern is that the dead guard provides
false assurance that an underflow check is in place.  Any reader — or future
maintainer — may conclude that `pad = extra_pad - tmp` is protected, without
realising the guard is inert.  If `extra_pad` were ever reachable as zero (a
divide-by-zero in the modulo), the real protection would be the `ROUNDUP`
overflow check at lines 1148–1152, not this guard.

### Recommendation

Remove the dead guard and replace the comment with an accurate one, or replace
the guard with one that actually fires under the intended condition:

```c
tmp = (len + padlen) % state->extra_pad;
/* tmp < extra_pad by modulo definition; subtraction is always safe */
pad = state->extra_pad - tmp;
```

---

## Finding 5 — Unsigned Underflow in Closed-Channel Data Receipt

**File:** `channels.c:3398–3400`
**Severity:** LOW (edge case; channel is already in a closing state)

### Code

```c
if (c->ostate != CHAN_OUTPUT_OPEN) {
    c->local_window -= win_len;    /* u_int underflow if win_len > local_window */
    c->local_consumed += win_len;
    return 0;
}
```

### Description

When a channel's output state is not `CHAN_OUTPUT_OPEN` (the channel is
closing or closed), incoming data is "fake consumed" for window bookkeeping —
the data is discarded rather than buffered.  `local_window` is `u_int`;
if `win_len > local_window`, the subtraction wraps to a large value near
`UINT_MAX`.

The wrapped `local_window` value inflates subsequent window-update calculations,
potentially causing the server to advertise far more window space to the peer
than was actually available.  This could induce the peer to send additional data
into the already-closing channel.

Since the channel is in a closing state and data is discarded (not buffered),
memory consumption is not directly affected.  The primary impact is malformed
`WINDOW_ADJUST` advertisements and potential unexpected protocol behaviour
during connection teardown.

### Recommendation

Guard the subtraction:

```c
if (c->ostate != CHAN_OUTPUT_OPEN) {
    c->local_window = (win_len > c->local_window) ? 0 : c->local_window - win_len;
    c->local_consumed += win_len;
    return 0;
}
```

---

## Finding 6 — Unquoted Shell Path in RC File Execution

**File:** `session.c:1216`
**Severity:** LOW (requires admin-controlled field to contain shell metacharacter)

### Code

```c
xasprintf(&cmd, "%s -c '%s %s'", shell, _PATH_BSHELL, user_rc);
...
f = popen(cmd, "w");
```

where:

```c
xasprintf(&user_rc, "%s/%s", s->pw->pw_dir, _PATH_SSH_USER_RC);
/* e.g. user_rc = "/home/alice/.ssh/rc" */
```

### Description

`user_rc` is constructed from `pw->pw_dir` (the user's home directory, sourced
from the password database).  It is embedded inside single quotes in the shell
command string.  If `pw->pw_dir` contains a single-quote character — for
example `/home/o'brien` — the quoting is broken:

```bash
/bin/bash -c '/bin/sh /home/o'brien/.ssh/rc'
#                              ^ closes the single-quoted string early
```

Everything after that unintended closing quote is interpreted as unquoted shell
syntax, allowing injection of arbitrary commands.  `shell` (from `pw->pw_shell`)
is similarly unquoted in the leading `%s` position and would be affected if it
contains spaces or shell metacharacters.

### Mitigating Factors

- `pw->pw_dir` and `pw->pw_shell` are set by the system administrator (root),
  not by the connecting client.
- The guard at line 1213 skips `user_rc` execution when
  `options.adm_forced_command != NULL` or `s->is_subsystem`, so any
  `ForceCommand` directive prevents this path entirely.
- If triggered, injected commands run with the **authenticated user's**
  privileges, not root's.

### Risk

On deployments that allow unusual characters in home directory paths — common
with LDAP-backed user databases where naming conventions may permit apostrophes
— an authenticated user could execute unintended shell commands during login.

### Recommendation

Shell-escape (or reject) `pw->pw_dir` and `pw->pw_shell` before embedding them
in a command string, or use `execve()` directly with an argument vector instead
of constructing a shell command string.

---

## Man-in-the-Middle Attack Analysis

### Short Answer

**Not by default for known hosts, but yes under specific conditions.**  SSH has
strong cryptographic MITM protection, but it is conditional — the security
depends entirely on whether the client has previously verified the server's host
key.

### How SSH Defeats MITM (When Working Correctly)

The protection lives in the key exchange.  After the Diffie-Hellman handshake,
the server **signs the session hash** with its private host key:

```
Client                     MITM                     Server
  |                          |                          |
  |<--- DH key exchange ----->|<--- DH key exchange ---->|
  |                          |  (two separate sessions)  |
  |<--- server signature -----|                          |
  |  (signed with MITM key,   |                          |
  |   NOT server's real key)  |                          |
```

The client verifies that signature against `~/.ssh/known_hosts`.  If the MITM
does not possess the real server's private key it **cannot produce a valid
signature** for the client's session hash.  This is cryptographically sound and
is what makes SSH fundamentally resistant to MITM when host keys are known.

### When MITM Is Possible

#### 1. First Connection — The TOFU Problem

On the very first connection to a host the key is unknown.  The code defines
four modes (`readconf.h:230-233`):

```c
#define SSH_STRICT_HOSTKEY_OFF   0   /* accept silently, never verify */
#define SSH_STRICT_HOSTKEY_NEW   1   /* auto-accept new, reject changed */
#define SSH_STRICT_HOSTKEY_YES   2   /* refuse if not already known */
#define SSH_STRICT_HOSTKEY_ASK   3   /* ask user on first connection (default) */
```

In the default `ask` mode (`sshconnect.c:1150-1196`) the user is prompted:

```c
} else if (options.strict_host_key_checking == SSH_STRICT_HOSTKEY_ASK) {
    xasprintf(&msg1,
        "The authenticity of host '%.200s (%s)' can't be established", host, ip);
    ...
    xextendf(&msg1, "\n",
        "Are you sure you want to continue connecting (yes/no/[fingerprint])? ");
    confirmed = confirm(msg1, fp);
    if (!confirmed)
        goto fail;
    hostkey_trusted = 1; /* user explicitly confirmed */
```

This is a **MITM window**.  A user who accepts the prompt without verifying the
fingerprint out-of-band has accepted a potentially attacker-controlled key.
This is the classic **Trust On First Use (TOFU)** problem — a social-engineering
risk, not a protocol weakness.

#### 2. `StrictHostKeyChecking no` / `off` — Disables Verification

With `StrictHostKeyChecking off` the client never refuses on host-key mismatch.
The code adds damage control by disabling credential-bearing features
(`sshconnect.c:1313-1352`):

```c
if (options.password_authentication) {
    error("Password authentication is disabled to avoid "
          "man-in-the-middle attacks.");
    options.password_authentication = 0;
}
if (options.kbd_interactive_authentication) {
    error("Keyboard-interactive authentication is disabled"
          " to avoid man-in-the-middle attacks.");
    options.kbd_interactive_authentication = 0;
}
if (options.forward_agent) {
    error("Agent forwarding is disabled to avoid "
          "man-in-the-middle attacks.");
    options.forward_agent = 0;
}
if (options.forward_x11)          { ... options.forward_x11 = 0; }
if (options.num_local_forwards > 0 ||
    options.num_remote_forwards > 0) { ... }
if (options.tun_open != SSH_TUNMODE_NO) { ... }
```

Password auth, keyboard-interactive auth, agent forwarding, X11 forwarding,
port forwarding and tunnel forwarding are all cancelled.  However, **public-key
authentication still proceeds**, so a private-key challenge-response is
observable by the MITM (though they cannot use it without the private key
itself).

#### 3. Terrapin Attack — CVE-2023-48795 (Fixed in This Release)

Before 9.6p1, an active MITM could **manipulate the unencrypted handshake**
before session keys are established, specifically by injecting or removing
messages during the banner exchange.  This allowed truncating the `EXT_INFO`
negotiation, stripping extension capabilities (such as `server-sig-algs`
restrictions).

This tree contains the **strict KEX** fix (`kex.c:1240-1257`):

```c
kex->kex_strict = kexalgs_contains(peer, "kex-strict-c-v00@openssh.com");
if (kex->kex_strict) {
    debug3_f("will use strict KEX ordering");
    if (seq != 0)
        ssh_packet_disconnect(ssh,
            "strict KEX violation: KEXINIT was not the first packet");
}
```

Any unexpected packet during key exchange is now a fatal disconnect
(`kex.c:546-548`):

```c
if ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
    ssh_packet_disconnect(ssh, "strict KEX violation: "
        "unexpected packet type %u (seqnr %u)", type, seq);
}
```

**Both peers must advertise strict KEX for it to activate.**  A MITM could
attempt to downgrade by stripping the `kex-strict-*` algorithms from the
KEXINIT, but doing so would be detectable as a MAC/integrity failure once
session keys are established.

#### 4. DNS Spoofing Detection

The code cross-checks the hostname and the IP address against `known_hosts`
separately when `CheckHostIP yes` is set (the default).  A mismatch triggers a
prominent warning (`sshconnect.c:1272-1279`):

```c
error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
error("The %s host key for %s has changed,", type, host);
error("and the key for the corresponding IP address %s", ip);
```

When strict checking is enabled, a changed key causes an immediate abort
(`sshconnect.c:1306-1310`):

```c
if (options.strict_host_key_checking != SSH_STRICT_HOSTKEY_OFF) {
    error("Host key for %.200s has changed and you have "
          "requested strict checking.", host);
    goto fail;
}
```

### Stronger Protections Available

| Mechanism | How It Helps | Configuration |
|---|---|---|
| `StrictHostKeyChecking yes` | Refuses any connection to a host not already in `known_hosts`; eliminates TOFU entirely for new hosts | `~/.ssh/config` |
| CA-signed host certificates | Trust the CA key instead of individual host keys; one `@cert-authority` line covers an entire fleet | `@cert-authority` in `known_hosts` |
| SSHFP DNS records + DNSSEC | Validates host key fingerprint via DNS before connecting | `VerifyHostKeyDNS yes` |
| `CheckHostIP yes` | Cross-checks hostname and IP separately to detect DNS spoofing | Enabled by default |

### Summary

| Scenario | MITM Possible? |
|---|---|
| Known host, correct key, `StrictHostKeyChecking yes` or `ask` | **No** — cryptographically defeated |
| First connection, user verifies fingerprint out-of-band | **No** — if verified correctly |
| First connection, user blindly accepts prompt | **Yes** — TOFU problem |
| `StrictHostKeyChecking no` / `off` | **Yes** — by design; credential forwarding is auto-disabled as mitigation |
| Terrapin attack (pre-9.6p1, ChaCha20-Poly1305 or CBC+EtM) | **Yes** (fixed in this release via strict KEX) |
| CA-signed host certificates | **No** — strongest available option; eliminates TOFU |

The cryptographic core of SSH is sound.  The practical MITM risk is almost
entirely a **key management and user behaviour problem**, not a protocol
weakness — with the notable historical exception of Terrapin (CVE-2023-48795),
which was a genuine protocol-level flaw now resolved in 9.6p1.

---

## False Positives Cleared

The following issues were raised during analysis and verified to be non-issues:

| Claim | Verdict |
|---|---|
| `received_sigterm` signal-handler race | **False positive** — correctly declared `volatile sig_atomic_t` (sshd.c:224–225); `ppoll` with signal mask handles the rest |
| `session_id2` NULL dereference in `monitor_apply_keystate` (monitor.c:1780) | **False positive** — the length-mismatch `fatal()` at line 1776 fires first when `session_id2 == NULL` because `session_id2_len` is 0 while the kex session_id is always non-empty |
| Off-by-one / infinite loop in `safely_chroot()` (session.c:1322) | **False positive** — `cp` is set to NULL by the `strchr()` in the loop condition on the last path component; the loop terminates correctly |
| `startup_pipes` free-slot invariant (sshd.c:1438) | **False positive** — `drop_connection()` returning false guarantees `startups < max_startups`, which maintains at least one free slot |
| `authctxt->pw` NULL dereference after `fakepw()` (monitor.c) | **False positive** — `fakepw()` returns a pointer to a static `struct passwd` object and never returns NULL |

---

## Denial-of-Service Attack Analysis

This section maps the concrete DoS attack surfaces present in the codebase,
ordered from most to least severe.  Each vector is grounded in the source.

---

### DoS Vector 1 — Pre-Auth Connection Slot Exhaustion

**Files:** `sshd.c:834-853`, `servconf.c:407-412`
**Requires:** Network access only (unauthenticated)

#### How It Works

Every incoming TCP connection spawns a child process and consumes one slot in
the `startup_pipes` array before authentication completes.  The defaults are
(`servconf.c:407-412`):

```c
options->max_startups       = 100;   /* hard ceiling */
options->max_startups_begin = 10;    /* throttle starts here */
options->max_startups_rate  = 30;    /* 30 % drop probability at begin */
options->login_grace_time   = 120;   /* seconds per unauthenticated child */
```

The throttle is probabilistic, not a hard cut-off:

```c
static int
should_drop_connection(int startups)
{
    if (startups < options.max_startups_begin)  /* < 10: always accept */
        return 0;
    if (startups >= options.max_startups)       /* >= 100: always drop */
        return 1;
    p  = 100 - options.max_startups_rate;       /* 70 */
    p *= startups - options.max_startups_begin; /* linear ramp */
    p /= options.max_startups - options.max_startups_begin;
    p += options.max_startups_rate;             /* 30 % base */
    r = arc4random_uniform(100);
    return (r < p) ? 1 : 0;
}
```

An attacker that opens and holds 100 TCP connections — without sending a single
byte — blocks all new legitimate connections for up to 120 seconds per wave.
Each connection consumes one file descriptor, one process (via fork), and a
small amount of memory.  With `LoginGraceTime 120` (default), the attacker only
needs to refresh ~100 connections every two minutes to maintain a permanent
blackout.  A single host with a modest connection rate can sustain this.

#### Per-Source Limit Is Disabled by Default

```c
if (options->per_source_max_startups == -1)
    options->per_source_max_startups = INT_MAX;   /* no limit */
```

`PerSourceMaxStartups` defaults to unlimited.  An attacker from a single IP
address faces no additional throttle beyond the global `MaxStartups`.

#### Mitigation

```
MaxStartups        10:30:60    # tighter ceiling
LoginGraceTime     30          # cut unauthenticated hold time
PerSourceMaxStartups 3         # per-source limit
PerSourceNetBlockSize 32/128   # apply limit per /32 IPv4 or /128 IPv6
```

---

### DoS Vector 2 — CPU Exhaustion via Diffie-Hellman Key Exchange

**Files:** `dh.c:159-240`, `kexgexs.c:75-106`, `dh.h:56-57`
**Requires:** Network access only (unauthenticated)

#### How It Works

An unauthenticated client can request a `diffie-hellman-group-exchange-sha256`
key exchange and demand the maximum group size:

```c
#define DH_GRP_MIN   2048
#define DH_GRP_MAX   8192
```

The server must then:

1. **Scan the entire `/etc/ssh/moduli` file twice** (`dh.c:175-211`) to select
   a suitable group — a linear file I/O pass per connection.
2. **Generate a fresh DH keypair** for the selected group (`dh.c:284-309`).
   An 8192-bit DH key generation is orders of magnitude more expensive than a
   2048-bit one.

```c
/* kexgexs.c:89-92 — attacker controls min/nbits/max within DH_GRP_MIN..MAX */
min = MAXIMUM(DH_GRP_MIN, min);
max = MINIMUM(DH_GRP_MAX, max);
nbits = MAXIMUM(DH_GRP_MIN, nbits);
nbits = MINIMUM(DH_GRP_MAX, nbits);
kex->dh = PRIVSEP(choose_dh(min, nbits, max));   /* expensive */
```

Each of the 100 concurrent `MaxStartups` slots can be used to drive a
continuous stream of DH-GEX requests at 8192-bit group size, pegging CPU on
the privilege-separated monitor process.  The `LoginGraceTime` clock does not
start until after the initial key exchange, so each slot's 120-second window
spans many re-key cycles.

#### Mitigation

```
KexAlgorithms -diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1
```

Removing DH-GEX forces clients to use fixed-group or ECDH/Curve25519 key
exchange, which has bounded and much lower server-side cost.

---

### DoS Vector 3 — Channel Memory Exhaustion (Post-Auth, Finding 3 Interaction)

**Files:** `channels.c:467-478`, `channels.h:267`, `channels.h:222-225`
**Requires:** Authenticated access

#### How It Works

After authentication, a single connection can open up to:

```c
#define CHANNELS_MAX_CHANNELS  (16 * 1024)   /* 16 384 channels */
```

Each channel carries a default receive window of:

```c
#define CHAN_SES_PACKET_DEFAULT  (32 * 1024)           /*  32 KB */
#define CHAN_SES_WINDOW_DEFAULT  (64 * CHAN_SES_PACKET_DEFAULT) /* 2 MB */
```

Channels are backed by `sshbuf` output buffers that grow to accommodate
incoming data.  An authenticated attacker with 10 multiplexed sessions
(the `MaxSessions 10` default) can open channels across all sessions.
Combining this with **Finding 3** (the `local_window_exceeded` counter
overflow), the attacker can feed data into a channel's `c->output` buffer
indefinitely after wrapping the overflow guard — consuming memory without bound
until the sshd child is OOM-killed.

Without Finding 3, the channel output buffer is also still a large allocation
surface: 16 384 channels × 2 MB window = up to **32 GB of output buffer
address space** addressable per connection in theory, constrained only by
physical memory and `MaxSessions`.

#### Mitigation

Apply the fix for Finding 3 (saturating add on `local_window_exceeded`).
Also consider:

```
MaxSessions        2          # reduce channel multiplexing
```

---

### DoS Vector 4 — Packet Discard MAC Computation on Bad CBC Packets

**Files:** `packet.c:406-428`, `packet.c:1572-1576`
**Requires:** Network access only (unauthenticated, if CBC cipher is negotiated)

#### How It Works

When a packet with an invalid length or padding arrives over a CBC cipher, the
server does **not** disconnect immediately.  Instead it calls
`ssh_packet_start_discard()`, which continues draining and computing the MAC
over the bad packet to avoid a timing oracle (`packet.c:417-423`):

```c
/*
 * Record number of bytes over which the mac has already
 * been computed in order to minimize timing attacks.
 */
if (mac && mac->enabled) {
    state->packet_discard_mac = mac;
    state->packet_discard_mac_already = mac_already;
}
state->packet_discard = discard - sshbuf_len(state->input);
```

The MAC is computed over up to `PACKET_MAX_SIZE` (256 KB) of garbage data.
An attacker sending a continuous stream of malformed maximum-size CBC packets
forces the server to run a full HMAC-SHA2 computation over 256 KB per bad
packet, while the attacker sends minimal data.  This is an asymmetric CPU
amplification: the attacker's cost is bandwidth; the server's cost is
cryptographic computation.

Note: the discard path only applies to CBC-mode ciphers.  Removing CBC from
the server's cipher list eliminates this vector entirely.

#### Mitigation

```
Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com
```

Restricting to AEAD-only ciphers means all invalid packets trigger an immediate
`ssh_packet_disconnect` rather than the slow discard path.

---

### DoS Vector 5 — Compression (Post-Auth; Bomb Mitigated, CPU Not)

**Files:** `packet.c:795-813`, `servconf.c:388-392`
**Requires:** Authenticated access (compression is `delayed` by default)

#### How It Works

Compression is enabled after authentication by default (`COMP_DELAYED`).  The
decompression bomb is explicitly guarded (`packet.c:804-812`):

```c
/*
 * Limit decompressed output to PACKET_MAX_SIZE to prevent a zip-bomb:
 * a maximally-compressed packet (up to PACKET_MAX_SIZE bytes of
 * ciphertext) could otherwise expand to gigabytes of plaintext.
 */
if (out_total > PACKET_MAX_SIZE) {
    ssh->state->compression_in_failures++;
    return SSH_ERR_INVALID_FORMAT;
}
```

The memory bomb is contained.  However, the **CPU cost of repeated zlib
inflation calls** is not bounded per unit time — only per packet.  An
authenticated attacker sending a high volume of maximally-compressible packets
at the 256 KB limit can create sustained CPU pressure on the sshd child
handling their session.  This is a low-severity per-session issue but
meaningful in multi-tenant environments.

#### Mitigation

```
Compression no
```

---

### Summary of DoS Vectors

| # | Vector | Auth Required | Severity | Primary Defence |
|---|--------|---------------|----------|-----------------|
| 1 | Connection slot exhaustion (MaxStartups) | No | **HIGH** | `MaxStartups 10:30:60`, `LoginGraceTime 30`, `PerSourceMaxStartups 3` |
| 2 | CPU via DH-GEX 8192-bit key exchange | No | **HIGH** | Remove `diffie-hellman-group-exchange-*` from `KexAlgorithms` |
| 3 | Channel memory exhaustion + Finding 3 overflow | Yes | **MEDIUM** | Fix Finding 3; reduce `MaxSessions` |
| 4 | MAC computation on bad CBC packets | No | **MEDIUM** | AEAD-only `Ciphers` list |
| 5 | zlib CPU pressure | Yes | LOW | `Compression no` |

### Hardened Configuration Summary

```
# sshd_config DoS hardening

LoginGraceTime      30
MaxStartups         10:30:60
MaxAuthTries        3
MaxSessions         2
PerSourceMaxStartups  3
PerSourceNetBlockSize 32/128

KexAlgorithms       curve25519-sha256,curve25519-sha256@libssh.org,\
                    ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521

Ciphers             chacha20-poly1305@openssh.com,\
                    aes128-gcm@openssh.com,aes256-gcm@openssh.com

Compression         no
```

Network-level controls (firewall rate-limiting, `connlimit` in iptables/nftables,
or a TCP proxy such as sslh/haproxy) provide an additional layer of protection
that the sshd process itself cannot supply.
