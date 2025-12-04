#include <stdio.h>

void vuln() {
    char buf[16];
    printf("Final input: ");
    gets(buf);     // VULNERABLE
    printf("You entered: %s\n", buf);
}

int main() {
    char a[16], b[16], c[16];

    printf("Input A: ");
    fgets(a, sizeof(a), stdin);

    printf("Input B: ");
    fgets(b, sizeof(b), stdin);

    printf("Input C: ");
    fgets(c, sizeof(c), stdin);

    vuln();
    return 0;
}