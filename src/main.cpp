#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT_HTTP 8080
#define PORT_HTTPS 8181

#define LISTEN_BACKLOG_SIZE 5

#define CONNECTION_BUFFER_SIZE 65536

bool done = false;

void SignalHandler(int s)
{
	printf("Caught signal %d\n", s);
	done = true;
}

int main(int argc, char* argv[])
{
	char buffer[CONNECTION_BUFFER_SIZE];

	struct sigaction sigIntHandler;

	sigIntHandler.sa_handler = SignalHandler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);

    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        fprintf(stderr, "Failed to open socket\n");
        return 1;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT_HTTP);

    if (bind(socketFD, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "Failed to bind server addr with port %d to socket\n", PORT_HTTP);
        return 1;
    }

    if (listen(socketFD, LISTEN_BACKLOG_SIZE) < 0) {
        fprintf(stderr, "Failed to listen to socket on port %d\n", PORT_HTTP);
        return 1;
    }

    printf("Server listening on port %d\n", PORT_HTTP);

	sockaddr_in clientAddr;
	socklen_t clientAddrLen = sizeof(clientAddr);
	int clientSocketFD, n;
	while (!done) {
		clientSocketFD = accept(socketFD, (sockaddr*)&clientAddr, &clientAddrLen);
		if (clientSocketFD < 0) {
			fprintf(stderr, "Failed to accept client connection\n");
			break;
		}

		printf("Received client connection, message:\n\n");

		bool readSuccess = true;
		while (true) {
			n = read(clientSocketFD, buffer, CONNECTION_BUFFER_SIZE);
			if (n == 0) {
				break;
			}
			else if (n < 0) {
				fprintf(stderr, "Failed to read from client socket\n");
				readSuccess = false;
				break;
			}

			printf("%.*s", n, buffer);
			break; // Early exit, probably should only be reading header first anyway
		}
		printf("\n\n");
		printf("Finished reading message\n");
		if (!readSuccess) {
			close(clientSocketFD);
			break;
		}

		/*n = write(clientSocketFD, "Hello, sailor!", 15);
		if (n < 0) {
			fprintf(stderr, "Failed to write to client socket\n");
			close(clientSocketFD);
			break;
		}
		printf("Sent response to client\n");*/

		close(clientSocketFD);
		printf("Closed connection with client\n");
	}

	close(socketFD);
	printf("Closed server socket on port %d\n", PORT_HTTP);

    return 0;
}