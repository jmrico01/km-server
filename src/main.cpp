#include <stdio.h>
#include <sys/socket.h>

int main(int argc, char* argv[])
{
    printf("Hello, sailor\n");

    int sockFD = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFD < 0) {
        fprintf(stderr, "Failed to open socket\n");
        return 1;
    }
}