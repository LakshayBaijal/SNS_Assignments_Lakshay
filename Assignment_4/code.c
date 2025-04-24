#include <stdio.h>
#include <string.h>
#include <unistd.h>

void process_packet(char *payload) {
    char msg[128];
    strcpy(msg, payload);
    printf("Log Entry: %s\n", msg);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Error: Expected single input parameter.\n");
        return 1;
    }
    printf("Initializing subsystem...\n");
    process_packet(argv[1]);
    printf("Subsystem shutdown sequence initiated.\n");
    return 0;
}
