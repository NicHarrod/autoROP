#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char buffer[10];
    

    printf("Enter payload : ");
    
    // Vulnerable to buffer overflow
    // gets() reads until a newline, ignoring the size of 'buffer'
    gets(buffer);
    
    printf("You entered: %s\n", buffer);
    printf("Function completed.\n");
}

int main() {
    char input;

    printf("Initiate sequence? (y/n): ");
    scanf(" %c", &input); // The space before %c tells scanf to ignore leading whitespace

    if (input == 'y') {
        printf("Confirm execute? (enter 'n' to proceed): ");
        scanf(" %c", &input);

        if (input == 'n') {
            // CRITICAL: We must clear the input buffer.
            // When you typed 'n' and hit Enter, the 'n' was read by scanf, 
            // but the '\n' (newline) is still sitting in the input stream.
            // gets() will see that newline and terminate immediately unless we eat it first.
            int c;
            while ((c = getchar()) != '\n' && c != EOF); 

            // Now call the function
            vulnerable_function();
        } else {
            printf("Sequence aborted. You did not enter 'n'.\n");
        }
    } else {
        printf("Sequence aborted. You did not enter 'y'.\n");
    }

    return 0;
}