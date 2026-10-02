/*
 * test_license.c — A 16-byte license key checker for testing symbolic execution.
 *
 * Format: XXXX-XXXX-XXXX-XXXX  (dashes at positions 4, 9, 14)
 * Valid key: "K9mZ-4wR2-Xp7B-3nLf"
 *
 * The checks are designed to create many branching paths so angr takes
 * several seconds to explore, exercising the progress-reporting feature.
 *
 * Build: cc -O0 -o test_license test_license.c
 */

#include <stdio.h>
#include <string.h>

static int is_upper(char c) { return c >= 'A' && c <= 'Z'; }
static int is_lower(char c) { return c >= 'a' && c <= 'z'; }
static int is_digit(char c) { return c >= '0' && c <= '9'; }

/*
 * Each 4-char group has a pattern: upper, digit, lower, upper/lower
 * with inter-character arithmetic constraints.
 */
static int check_group1(const char *g) {
    /* Group 1: "K9mZ" */
    if (!is_upper(g[0])) return 0;
    if (!is_digit(g[1])) return 0;
    if (!is_lower(g[2])) return 0;
    if (!is_upper(g[3])) return 0;

    if (g[0] != 'K') return 0;
    if (g[1] - '0' != 9) return 0;
    if ((g[2] ^ 0x05) != 'h') return 0;          /* m ^ 0x05 = 0x68 = 'h' */
    if (g[3] + g[0] != 'K' + 'Z') return 0;      /* Z + K = 165 */
    return 1;
}

static int check_group2(const char *g) {
    /* Group 2: "4wR2" */
    if (!is_digit(g[0])) return 0;
    if (!is_lower(g[1])) return 0;
    if (!is_upper(g[2])) return 0;
    if (!is_digit(g[3])) return 0;

    if (g[0] != '4') return 0;
    if (g[1] - 'a' != 22) return 0;               /* 'w' - 'a' = 22 */
    if ((g[2] & 0x1F) != 18) return 0;            /* 'R' & 0x1F = 18 */
    if (g[3] * 2 != 100) return 0;                 /* '2' = 50, 50*2 = 100 */
    return 1;
}

static int check_group3(const char *g) {
    /* Group 3: "Xp7B" */
    if (!is_upper(g[0])) return 0;
    if (!is_lower(g[1])) return 0;
    if (!is_digit(g[2])) return 0;
    if (!is_upper(g[3])) return 0;

    if (g[0] - 'A' != 23) return 0;               /* 'X' - 'A' = 23 */
    if ((g[1] ^ g[0]) != 0x28) return 0;          /* 'p' ^ 'X' = 0x28 */
    if (g[2] != '7') return 0;
    if (g[3] + 1 != 'C') return 0;                /* 'B' + 1 = 'C' */
    return 1;
}

static int check_group4(const char *g) {
    /* Group 4: "3nLf" */
    if (!is_digit(g[0])) return 0;
    if (!is_lower(g[1])) return 0;
    if (!is_upper(g[2])) return 0;
    if (!is_lower(g[3])) return 0;

    if (g[0] + 1 != '4') return 0;                /* '3' + 1 = '4' */
    if (g[1] != 'n') return 0;
    if (g[2] - 'A' != 11) return 0;               /* 'L' - 'A' = 11 */
    if ((g[3] ^ 0x01) != 'g') return 0;           /* 'f' ^ 0x01 = 'g' */
    return 1;
}

/*
 * Cross-group checksum: sum of all non-dash characters mod 256 must equal a
 * known value. This ties the groups together so angr can't solve them
 * independently without propagating constraints.
 */
static int check_checksum(const char *key) {
    unsigned sum = 0;
    for (int i = 0; i < 19; i++) {
        if (key[i] != '-')
            sum += (unsigned char)key[i];
    }
    /* sum of "K9mZ4wR2Xp7B3nLf" = 75+57+109+90+52+119+82+50+88+112+55+66+51+110+76+102 = 1294
       1294 % 256 = 14 */
    return (sum % 256) == 14;
}

int validate_license(const char *key) {
    if (strlen(key) < 19) return 0;

    /* Check dash positions */
    if (key[4] != '-') return 0;
    if (key[9] != '-') return 0;
    if (key[14] != '-') return 0;

    if (!check_group1(key + 0)) return 0;
    if (!check_group2(key + 5)) return 0;
    if (!check_group3(key + 10)) return 0;
    if (!check_group4(key + 15)) return 0;

    if (!check_checksum(key)) return 0;

    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <license-key>\n", argv[0]);
        printf("Format: XXXX-XXXX-XXXX-XXXX\n");
        return 1;
    }

    if (validate_license(argv[1])) {
        printf("License valid!\n");
        return 0;
    } else {
        printf("Invalid license.\n");
        return 1;
    }
}
