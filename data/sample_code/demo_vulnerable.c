#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *password = "demo-only-secret-123";

int process_input(char *user_input) {
    char buffer[8];
    strcpy(buffer, user_input);  // candidate unbounded copy
    system(user_input);          // candidate command injection surface
    int values[2] = {10, 20};
    int result = values[4];      // candidate out-of-bounds access
    // TODO: validate input and handle errors
    FILE *fp = fopen("example.txt", "r");
    return result;
}
