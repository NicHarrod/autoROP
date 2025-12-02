#include <stdio.h>
#include <string.h>

int main() {
    char input1;

    printf("Input1: ");
    scanf(" %c", &input1);

    char input2;
    printf("Input2: ");
    scanf(" %c", &input2);

    // Clear the input buffer withoAut getchar()
    scanf("%*[^\n]");
    scanf("%*c");

    printf("Input3: ");
    char buffer[10];
    gets(buffer);   // unsafe
    printf("You entered: %s\n", buffer);

    return 0;
}
