/*
 * routezero_cvss.c — Lightweight CVSS v3.1 score calculator
 * Part of the RouteZero attack-path analysis engine.
 *
 * Build:  gcc -o routezero_cvss tools/routezero_cvss.c -lm -Wall -Wextra
 * Usage:  ./routezero_cvss <AV> <AC> <PR> <UI> <S> <C> <I> <A>
 *
 * Metric values follow CVSS v3.1 shorthand:
 *   AV  : N(etwork) | A(djacent) | L(ocal) | P(hysical)
 *   AC  : L(ow) | H(igh)
 *   PR  : N(one) | L(ow) | H(igh)
 *   UI  : N(one) | R(equired)
 *   S   : U(nchanged) | C(hanged)
 *   C/I/A: N(one) | L(ow) | H(igh)
 *
 * Example:
 *   ./routezero_cvss N L N N C H H H
 *   => Base Score: 10.0  Severity: CRITICAL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ── CVSS v3.1 metric weights ────────────────────────────────────────────── */

static double av_weight(const char *v) {
    if (strcmp(v, "N") == 0) return 0.85;
    if (strcmp(v, "A") == 0) return 0.62;
    if (strcmp(v, "L") == 0) return 0.55;
    if (strcmp(v, "P") == 0) return 0.20;
    fprintf(stderr, "Unknown AV value: %s\n", v); exit(1);
}

static double ac_weight(const char *v) {
    if (strcmp(v, "L") == 0) return 0.77;
    if (strcmp(v, "H") == 0) return 0.44;
    fprintf(stderr, "Unknown AC value: %s\n", v); exit(1);
}

static double pr_weight(const char *v, int scope_changed) {
    if (strcmp(v, "N") == 0) return 0.85;
    if (strcmp(v, "L") == 0) return scope_changed ? 0.68 : 0.62;
    if (strcmp(v, "H") == 0) return scope_changed ? 0.50 : 0.27;
    fprintf(stderr, "Unknown PR value: %s\n", v); exit(1);
}

static double ui_weight(const char *v) {
    if (strcmp(v, "N") == 0) return 0.85;
    if (strcmp(v, "R") == 0) return 0.62;
    fprintf(stderr, "Unknown UI value: %s\n", v); exit(1);
}

static double cia_weight(const char *v) {
    if (strcmp(v, "N") == 0) return 0.00;
    if (strcmp(v, "L") == 0) return 0.22;
    if (strcmp(v, "H") == 0) return 0.56;
    fprintf(stderr, "Unknown C/I/A value: %s\n", v); exit(1);
}

/* ── Severity label ──────────────────────────────────────────────────────── */

static const char *severity(double score) {
    if (score == 0.0)        return "NONE";
    if (score < 4.0)         return "LOW";
    if (score < 7.0)         return "MEDIUM";
    if (score < 9.0)         return "HIGH";
    return "CRITICAL";
}

/* ── Round up to 1 decimal per spec ─────────────────────────────────────── */

static double roundup1(double x) {
    double int_part = floor(x * 10.0 + 1e-10);
    return int_part / 10.0;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc != 9) {
        fprintf(stderr,
            "Usage: %s <AV> <AC> <PR> <UI> <S> <C> <I> <A>\n"
            "  AV : N|A|L|P   AC : L|H   PR : N|L|H\n"
            "  UI : N|R        S  : U|C   C/I/A : N|L|H\n"
            "Example: %s N L N N C H H H\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *av = argv[1];
    const char *ac = argv[2];
    const char *pr = argv[3];
    const char *ui = argv[4];
    const char *sc = argv[5];   /* Scope */
    const char *c  = argv[6];
    const char *i  = argv[7];
    const char *a  = argv[8];

    int scope_changed = (strcmp(sc, "C") == 0);

    double AV = av_weight(av);
    double AC = ac_weight(ac);
    double PR = pr_weight(pr, scope_changed);
    double UI = ui_weight(ui);
    double C  = cia_weight(c);
    double I  = cia_weight(i);
    double A  = cia_weight(a);

    /* Exploitability sub-score */
    double exploitability = 8.22 * AV * AC * PR * UI;

    /* ISC base */
    double isc_base = 1.0 - (1.0 - C) * (1.0 - I) * (1.0 - A);

    /* Impact sub-score */
    double impact;
    if (!scope_changed) {
        impact = 6.42 * isc_base;
    } else {
        impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15.0);
    }

    /* Base score */
    double base_score;
    if (impact <= 0.0) {
        base_score = 0.0;
    } else if (!scope_changed) {
        base_score = roundup1(fmin(impact + exploitability, 10.0));
    } else {
        base_score = roundup1(fmin(1.08 * (impact + exploitability), 10.0));
    }

    /* Output */
    printf("RouteZero CVSS v3.1 Calculator\n");
    printf("================================\n");
    printf("Vector: AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s\n",
           av, ac, pr, ui, sc, c, i, a);
    printf("Exploitability Sub-score : %.2f\n", exploitability);
    printf("Impact Sub-score         : %.2f\n", impact);
    printf("Base Score               : %.1f\n", base_score);
    printf("Severity                 : %s\n",   severity(base_score));

    return 0;
}
