#include <stdio.h>
#include <string.h>



int main() {
    char input1;

    printf("Input1");
    scanf(" %c", &input1); // The space before %c tells scanf to ignore leading whitespace
    char input2;
    printf("Input2");
    scanf(" %c", &input2);

    while ((getchar()) != '\n'); // Clear the input buffer

    printf("Input3");
    char buffer[10];
    gets(buffer);
    printf("You entered: %s\n", buffer);

    return 0;
}