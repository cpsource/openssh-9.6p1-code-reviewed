#!/usr/bin/env python3
"""
PoC #7 — Implicit double→time_t Cast in ensure_minimum_time_since()
=====================================================================
Finding : INFO  (README-sshd-security-flaws.md #11)
File    : auth2.c:263-264
Branch  : master

Vulnerability
-------------
After a failed authentication attempt, sshd enforces a minimum delay to
blunt timing-oracle attacks:

    static void
    ensure_minimum_time_since(double start, double seconds)
    {
        struct timespec ts;
        double elapsed = monotime_double() - start, req = seconds, remain;

        if (elapsed > MAX_FAIL_DELAY_SECONDS) {   // line 253
            return;
        }

        while ((remain = seconds - elapsed) < 0.0)
            seconds *= 2;

        ts.tv_sec  = remain;                      // line 263 — implicit cast
        ts.tv_nsec = (remain - ts.tv_sec) * 1000000000;
        nanosleep(&ts, NULL);
    }

The assignment `ts.tv_sec = remain` converts a `double` to `time_t`
(a signed integer type, typically 64-bit on Linux) without any bounds check.
Per C11 §6.3.1.4, converting a floating-point value to an integer type
when the value is outside the representable range is *implementation-defined
behaviour* (UB in some readings).

Problematic scenario
--------------------
`elapsed` is computed as  monotime_double() - start.  If `elapsed` exceeds
MAX_FAIL_DELAY_SECONDS (5.0) the function returns immediately — but the
early-return guard runs BEFORE the while-loop.  There is a narrow window
where:

  1. The early-return condition is false (elapsed <= 5.0).
  2. After the early-return check, something makes `elapsed` appear very
     large (e.g. VM live-migration or NTP step between the two
     monotime_double() calls), causing `remain` to be negative after the
     while-loop guard.
  3. The while-loop doubles `seconds` until remain >= 0, but if `elapsed`
     is astronomically large this loop runs until `seconds` overflows
     double precision (infinity), and `remain = infinity - elapsed` is
     still infinity or NaN.
  4. `ts.tv_sec = +Inf` or `ts.tv_sec = NaN` → implementation-defined
     conversion on the platform, potentially a very large sleep.

More concretely, the C standard defines the conversion of an out-of-range
double to a signed integer as UB/implementation-defined.  On x86-64 with
GCC, converting a large positive double to time_t clamps to LLONG_MAX or
wraps, neither of which is checked.  Converting NaN gives 0 or INT64_MIN.

This PoC demonstrates the cast behaviour with a C reproducer.
"""

import os
import sys
import subprocess
import tempfile

C_REPRODUCER = r"""
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

/*
 * Mirror the vulnerable assignment from auth2.c:263-264.
 * Cast various double values to time_t and print results.
 */
static void show_cast(const char *label, double remain)
{
    struct timespec ts;
    ts.tv_sec  = (time_t)remain;   /* same implicit cast as auth2.c:263 */
    ts.tv_nsec = (long)((remain - (double)ts.tv_sec) * 1000000000);

    printf("  remain = %-20s  ->  tv_sec = %lld, tv_nsec = %ld\n",
           label, (long long)ts.tv_sec, ts.tv_nsec);
}

int main(void)
{
    printf("=== double → time_t cast behaviour (auth2.c:263) ===\n\n");

    printf("Normal values (expected to work correctly):\n");
    show_cast("0.005 (5 ms)",      0.005);
    show_cast("1.0   (1 s)",       1.0);
    show_cast("4.999 (just ok)",   4.999);

    printf("\nEdge / out-of-range values (implementation-defined):\n");
    show_cast("-0.001 (negative)", -0.001);
    show_cast("1e18   (huge)",     1e18);
    show_cast("1e300  (overflow)", 1e300);

    double inf = 1.0 / 0.0;   /* +Inf */
    double nan = 0.0 / 0.0;   /* NaN  */
    show_cast("+Inf",  inf);
    show_cast("NaN",   nan);
    show_cast("-Inf", -inf);

    printf("\n");
    printf("sizeof(time_t) = %zu bytes on this platform\n", sizeof(time_t));
    printf("INT64_MAX      = %lld\n", (long long)INT64_MAX);

    printf("\n=== Scenario that can trigger the out-of-range cast ===\n\n");
    /*
     * Simulate what happens when `elapsed` is already > `seconds` at
     * the point the while-loop starts:
     *   - The loop doubles `seconds` until remain >= 0
     *   - If elapsed is huge, seconds can overflow double to +Inf
     *   - Then remain = +Inf - elapsed = +Inf (or NaN)
     */
    double seconds = 0.005;  /* MIN_FAIL_DELAY_SECONDS */
    double elapsed = 1e308;  /* artificially huge elapsed time */

    /* The early-return guard would fire for elapsed > 5.0 in real code,
       but if the guard were somehow bypassed (or elapsed grew between the
       check and the loop): */
    int iterations = 0;
    double remain;
    while ((remain = seconds - elapsed) < 0.0) {
        seconds *= 2;
        iterations++;
        if (isinf(seconds) || iterations > 2000) break;
    }
    printf("After %d doublings: seconds=%.3g, remain=%.3g\n",
           iterations, seconds, remain);

    struct timespec ts;
    ts.tv_sec  = (time_t)remain;
    ts.tv_nsec = isinf(remain) || isnan(remain) ? 0
                 : (long)((remain - (double)ts.tv_sec) * 1000000000);
    printf("Resulting nanosleep: tv_sec=%lld, tv_nsec=%ld\n",
           (long long)ts.tv_sec, ts.tv_nsec);

    if ((long long)ts.tv_sec < 0) {
        printf("[+] ISSUE: tv_sec is negative — nanosleep returns EINVAL immediately.\n");
        printf("    The minimum-delay guarantee is silently skipped.\n");
    } else if ((long long)ts.tv_sec > 3600) {
        printf("[+] ISSUE: tv_sec is very large — nanosleep would stall sshd for\n");
        printf("    %lld seconds (effective DoS of the connection slot).\n",
               (long long)ts.tv_sec);
    } else if (isinf(remain) || isnan(remain)) {
        printf("[+] ISSUE: remain is %s — cast behaviour is implementation-defined.\n",
               isinf(remain) ? "Inf" : "NaN");
    } else {
        printf("[-] On this platform the loop terminated before overflow.\n");
        printf("    The early-return guard (elapsed > 5.0) would catch this\n");
        printf("    in normal operation.  The cast is still unchecked.\n");
    }

    printf("\n=== Mitigation ===\n");
    printf("Clamp remain before the cast:\n");
    printf("  if (remain < 0.0) remain = 0.0;\n");
    printf("  if (remain > MAX_FAIL_DELAY_SECONDS) remain = MAX_FAIL_DELAY_SECONDS;\n");
    printf("  ts.tv_sec  = (time_t)remain;\n");
    printf("  ts.tv_nsec = (long)((remain - ts.tv_sec) * 1e9);\n");

    return 0;
}
"""


def main():
    print("=" * 60)
    print("PoC #7 — double→time_t implicit cast in ensure_minimum_time_since")
    print("=" * 60)
    print()
    print("[*] This PoC compiles a C reproducer that mirrors the cast at")
    print("    auth2.c:263-264 and exercises it with normal, edge-case,")
    print("    and out-of-range double values.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        src  = os.path.join(tmpdir, "poc7.c")
        bin_ = os.path.join(tmpdir, "poc7")

        with open(src, "w") as f:
            f.write(C_REPRODUCER)

        r = subprocess.run(
            ["cc", "-o", bin_, src, "-lm", "-Wall"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"[!] Compilation failed:\n{r.stderr}")
            sys.exit(1)
        print("[*] Compiled reproducer OK")
        print()

        r = subprocess.run([bin_], capture_output=True, text=True)
        print(r.stdout)
        if r.stderr:
            print(r.stderr)

    print("[*] Context in auth2.c:")
    print("    The early-return guard at line 253 (elapsed > MAX_FAIL_DELAY_SECONDS)")
    print("    prevents the worst cases in normal operation.  However:")
    print("    1. The guard and the cast are separate — future refactoring could")
    print("       separate them further, leaving the cast unguarded.")
    print("    2. On systems where monotime_double() can step backwards or jump")
    print("       (VM live-migration, clock sync) the invariants can break.")
    print("    3. The C standard gives no guarantee about the result of casting")
    print("       an out-of-range double to time_t; relying on implementation")
    print("       behaviour is fragile across architectures and compilers.")
    print()
    print("[*] Fix: clamp `remain` to [0, MAX_FAIL_DELAY_SECONDS] with an explicit")
    print("    range check and use isfinite() before the cast.")


if __name__ == "__main__":
    main()
