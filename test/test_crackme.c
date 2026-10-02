#include <stdio.h>
#include <string.h>

int check_password(const char *input) {
    if (input[0] != 'P') return 0;
    if (input[1] != '4') return 0;
    if ((input[2] ^ 0x42) != 0x10) return 0;
    if (input[3] + 0x20 != 0x87) return 0;
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    if (strlen(argv[1]) < 4) {
        printf("Wrong!\n");
        return 1;
    }

    if (check_password(argv[1])) {
        printf("Correct!\n");
        return 0;
    } else {
        printf("Wrong!\n");
        return 1;
    }
}
