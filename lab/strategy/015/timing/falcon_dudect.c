// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
//
// falcon_dudect.c: record 015, lab step 4. A dudect-style timing test of FN-DSA signing
// (liboqs Falcon-padded-1024), in C, against the installed library.
//
//   cc -O2 -I$OQS/include falcon_dudect.c -L$OQS/lib -loqs -lm -o falcon_dudect
//   ./falcon_dudect <test> <measurements>
//
// Each test times OQS_SIG_falcon_padded_1024_sign over two classes, interleaved at random,
// and reports Welch's t over the raw timings and over percentile crops (the dudect method).
// Both classes copy their key and message into the same buffers before every call, so cache
// placement does not differ between them.
//
//   key       class 0: one fixed secret key;  class 1: a key drawn from a pool of fresh keys.
//             Same fixed message for both. Asks: does signing time depend on the key's values?
//   keypair   class 0: key A;  class 1: key B (two fixed keys). Key-specific difference.
//   message   one fixed key; class 0: a fixed message;  class 1: a random message.
//   control   the key test with a planted leak: class 0 spins for PLANT ns after signing.
//             It must be detected, or the harness cannot see what it claims to look for.
//
// The timer is mach_absolute_time on macOS (24 MHz on Apple silicon, ~42 ns) and
// CLOCK_MONOTONIC_RAW elsewhere: coarse against one instruction, fine against a signing call
// of about 400 microseconds.
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#define PK OQS_SIG_falcon_padded_1024_length_public_key
#define SK OQS_SIG_falcon_padded_1024_length_secret_key
#define SIG OQS_SIG_falcon_padded_1024_length_signature
#define MLEN 64
#define POOL 128
#define NCROP 6

#if defined(__APPLE__)
#include <mach/mach_time.h>
// cntvct_el0 read directly from user space is not usable here (measured: reported 1 GHz and the
// difference wrapped), so the timer is mach_absolute_time, which the OS calibrates.
static inline uint64_t ticks(void) { __asm__ volatile("" ::: "memory"); return mach_absolute_time(); }
static double tick_ns(void) { mach_timebase_info_data_t tb; mach_timebase_info(&tb); return (double)tb.numer / tb.denom; }
#else
#include <time.h>
static inline uint64_t ticks(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static double tick_ns(void) { return 1.0; }
#endif

typedef struct { double n, mean, m2; } welch;
static void push(welch *w, double x) {
    w->n += 1; double d = x - w->mean; w->mean += d / w->n; w->m2 += d * (x - w->mean);
}
static double tstat(const welch *a, const welch *b) {
    if (a->n < 2 || b->n < 2) return 0;
    double va = a->m2 / (a->n - 1), vb = b->m2 / (b->n - 1);
    return (a->mean - b->mean) / sqrt(va / a->n + vb / b->n);
}
static int cmp(const void *x, const void *y) {
    double a = *(const double *)x, b = *(const double *)y; return (a > b) - (a < b);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s key|keypair|message|control N\n", argv[0]); return 2; }
    const char *test = argv[1];
    long n = atol(argv[2]);
    int control = !strcmp(test, "control");
    int keypair = !strcmp(test, "keypair");
    int message = !strcmp(test, "message");
    if (!control && !keypair && !message && strcmp(test, "key")) { fprintf(stderr, "unknown test\n"); return 2; }
    double plant_ns = getenv("PLANT_NS") ? atof(getenv("PLANT_NS")) : 2000.0;

    static uint8_t pool[POOL][SK], fixed[SK], other[SK], pk[PK], sk[SK], sig[SIG], msg[MLEN], fmsg[MLEN];
    if (OQS_SIG_falcon_padded_1024_keypair(pk, fixed) != OQS_SUCCESS) return 3;
    if (OQS_SIG_falcon_padded_1024_keypair(pk, other) != OQS_SUCCESS) return 3;
    for (int i = 0; i < POOL; i++)
        if (OQS_SIG_falcon_padded_1024_keypair(pk, pool[i]) != OQS_SUCCESS) return 3;
    OQS_randombytes(fmsg, MLEN);

    double *t = malloc(sizeof(double) * n);
    uint8_t *cls = malloc(n);
    uint8_t coin[1];
    double ns = tick_ns();
    for (long i = 0; i < n; i++) {
        OQS_randombytes(coin, 1);
        int c = coin[0] & 1;
        cls[i] = (uint8_t)c;
        if (message) {
            memcpy(sk, fixed, SK);
            if (c) OQS_randombytes(msg, MLEN); else memcpy(msg, fmsg, MLEN);
        } else if (keypair) {
            memcpy(sk, c ? other : fixed, SK);
            memcpy(msg, fmsg, MLEN);
        } else {
            OQS_randombytes(coin, 1);
            memcpy(sk, c ? pool[coin[0] % POOL] : fixed, SK);
            memcpy(msg, fmsg, MLEN);
        }
        size_t slen = SIG;
        uint64_t a = ticks();
        if (OQS_SIG_falcon_padded_1024_sign(sig, &slen, msg, MLEN, sk) != OQS_SUCCESS) return 4;
        if (control && c == 0) { uint64_t end = ticks() + (uint64_t)(plant_ns / ns); while (ticks() < end) {} }
        uint64_t b = ticks();
        t[i] = (double)(b - a) * ns;
    }

    // dudect crops: keep measurements under the p-th percentile, p = 1 - 0.5^(10(k+1)/NCROP).
    double *s = malloc(sizeof(double) * n);
    memcpy(s, t, sizeof(double) * n);
    qsort(s, n, sizeof(double), cmp);
    printf("test=%s n=%ld median_ns=%.0f p10=%.0f p90=%.0f timer_ns=%.1f", test, n, s[n / 2], s[n / 10], s[9 * n / 10], ns);
    if (control) printf(" plant_ns=%.0f", plant_ns);
    printf("\n");
    double worst = 0;
    for (int k = -1; k < NCROP; k++) {
        double cut = INFINITY;
        if (k >= 0) {
            double p = 1 - pow(0.5, 10.0 * (k + 1) / NCROP);
            cut = s[(long)(p * (n - 1))];
        }
        welch w[2] = {{0}};
        for (long i = 0; i < n; i++) if (t[i] < cut) push(&w[cls[i]], t[i]);
        double tv = tstat(&w[0], &w[1]);
        if (fabs(tv) > fabs(worst)) worst = tv;
        char label[16];
        snprintf(label, sizeof label, k < 0 ? "none" : "p%.4f", k < 0 ? 0 : 1 - pow(0.5, 10.0 * (k + 1) / NCROP));
        printf("  crop=%-9s n0=%-7.0f n1=%-7.0f mean0=%-9.0f mean1=%-9.0f t=%+.2f\n",
               label, w[0].n, w[1].n, w[0].mean, w[1].mean, tv);
    }
    printf("max|t|=%.2f verdict=%s\n", fabs(worst), fabs(worst) > 10 ? "LEAK" : fabs(worst) > 4.5 ? "PROBABLE" : "NONE-DETECTED");
    return 0;
}
