// buff overflow vulnerability in stdio
#include <stdio.h>
#include <string.h>
void vulnerable_function() {
    char buffer[10];
    printf("Enter some text: ");
    // Vulnerable to buffer overflow
    gets(buffer);
    printf("You entered: %s\n", buffer);
}
int main() {
    vulnerable_function();
    return 0;
}