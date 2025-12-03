#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 10

int main() {
    char input1[BUFFER_SIZE];
    char input2[BUFFER_SIZE];
    char input3[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];

    // Taking safe inputs for the first three strings
    printf("Enter first string (max 9 characters): ");
    if (fgets(input1, sizeof(input1), stdin) != NULL) {
        input1[strcspn(input1, "\n")] = '\0'; // Remove newline character
    }

    printf("Enter second string (max 9 characters): ");
    if (fgets(input2, sizeof(input2), stdin) != NULL) {
        input2[strcspn(input2, "\n")] = '\0'; // Remove newline character
    }

    printf("Enter third string (max 9 characters): ");
    if (fgets(input3, sizeof(input3), stdin) != NULL) {
        input3[strcspn(input3, "\n")] = '\0'; // Remove newline character
    }

    // Display the safe inputs
    printf("\nYou entered:\n");
    printf("Input 1: %s\n", input1);
    printf("Input 2: %s\n", input2);
    printf("Input 3: %s\n", input3);

    // Now, an unsafe call to gets()
    printf("\nNow entering data into the unsafe buffer...\n");
    printf("Enter data (this could overflow the buffer!): ");
    gets(buffer); // Unsafe call to gets

    // Display the unsafe input (potentially causing overflow)
    printf("\nYou entered (unsafe): %s\n", buffer);

    return 0;
}
