#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>

#define KILOBYTES(b) (b * 1024)
#define MEGABYTES(b) (KILOBYTES(b) * 1024)

#define PORT_HTTP 8080
#define PORT_HTTPS 8181

#define LISTEN_BACKLOG_SIZE 5

#define CONNECTION_BUFFER_SIZE KILOBYTES(256)

#define URI_PATH_MAX_LENGTH 1024

enum HTTPRequestMethod
{
	HTTP_REQUEST_GET,
	HTTP_REQUEST_POST,

	HTTP_REQUEST_NONE
};

enum HTTPVersion
{
	HTTP_VERSION_1_1,

	HTTP_VERSION_NONE
};

bool done = false;

void SignalHandler(int s)
{
	printf("Caught signal %d\n", s);
	done = true;
}

inline bool IsWhitespace(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

bool StringCompare(const char* str1, const char* str2, int n)
{
	for (int i = 0; i < n; i++) {
		if (str1[i] != str2[i]) {
			return false;
		}
	}

	return true;
}

void HandleGetRequest(const char* uri, int uriLength,
	char* buffer, int bufferMaxSize, int clientSocketFD)
{
	char path[URI_PATH_MAX_LENGTH];
	snprintf(path, URI_PATH_MAX_LENGTH, "public%.*s", uriLength, uri);
	printf("Loading file %s\n", path);
	int fileFD = open(path, O_RDONLY);
	if (fileFD < 0) {
		printf("Failed to open file %s\n", path);
		return;
	}

	int n = read(fileFD, buffer, bufferMaxSize);
	if (n < 0) {
		printf("Failed to read file %s\n", path);
		close(fileFD);
		return;
	}

	printf("file contents:\n%.*s\n", n, buffer);

	write(clientSocketFD, buffer, n);

	close(fileFD);
}

int main(int argc, char* argv[])
{
	if (CONNECTION_BUFFER_SIZE > SSIZE_MAX) {
        fprintf(stderr, "Buffer size too large for read(...)\n");
        return 1;
	}

	struct sigaction sigIntHandler;

	sigIntHandler.sa_handler = SignalHandler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);

	void* memory = mmap(NULL, CONNECTION_BUFFER_SIZE, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (memory == MAP_FAILED) {
        fprintf(stderr, "Failed to allocate memory for server buffer using mmap\n");
        return 1;
	}

    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        fprintf(stderr, "Failed to open socket\n");
		munmap(memory, CONNECTION_BUFFER_SIZE);
        return 1;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT_HTTP);

    if (bind(socketFD, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "Failed to bind server addr with port %d to socket\n", PORT_HTTP);
		close(socketFD);
		munmap(memory, CONNECTION_BUFFER_SIZE);
        return 1;
    }

    if (listen(socketFD, LISTEN_BACKLOG_SIZE) < 0) {
        fprintf(stderr, "Failed to listen to socket on port %d\n", PORT_HTTP);
		close(socketFD);
		munmap(memory, CONNECTION_BUFFER_SIZE);
        return 1;
    }

    printf("Server listening on port %d\n", PORT_HTTP);

	sockaddr_in clientAddr;
	socklen_t clientAddrLen = sizeof(clientAddr);
	int clientSocketFD, n;
	char* buffer = (char*)memory;

	while (!done) {
		clientSocketFD = accept(socketFD, (sockaddr*)&clientAddr, &clientAddrLen);
		if (clientSocketFD < 0) {
			fprintf(stderr, "Failed to accept client connection\n");
			break;
		}

		printf("Received client connection, message:\n\n");

		n = read(clientSocketFD, buffer, CONNECTION_BUFFER_SIZE);
		if (n < 0) {
			fprintf(stderr, "Failed to read from client socket\n");
			close(clientSocketFD);
			break;
		}
		
		printf("%.*s\n", n, buffer);

		// Parse request according to HTTP/1.1 standard
		// Source: https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
		const char* methodString = buffer;
		int firstSpace = 0;
		while (firstSpace < n && buffer[firstSpace] != ' ') {
			firstSpace++;
		}

		HTTPRequestMethod method = HTTP_REQUEST_NONE;
		if (StringCompare(methodString, "GET", 3)) {
			method = HTTP_REQUEST_GET;
		}
		else if (StringCompare(methodString, "POST", 4)) {
			method = HTTP_REQUEST_POST;
		}
		else {
			fprintf(stderr, "Unrecognized HTTP request method. Full request:\n");
			fprintf(stderr, "%.*s\n", n, buffer);
			close(clientSocketFD);
			break;
		}

		if (firstSpace + 1 >= n) {
			fprintf(stderr, "Incomplete HTTP request\n");
			close(clientSocketFD);
			break;
		}
		const char* uri = &buffer[firstSpace + 1];
		int secondSpace = firstSpace + 1;
		while (secondSpace < n && buffer[secondSpace] != ' ') {
			secondSpace++;
		}
		int uriLength = secondSpace - firstSpace - 1;

		if (secondSpace + 1 >= n) {
			fprintf(stderr, "Incomplete HTTP request\n");
			close(clientSocketFD);
			break;
		}
		const char* versionString = &buffer[secondSpace + 1];
		int lineEnd = secondSpace + 1;
		while (lineEnd < n && buffer[lineEnd] != '\r') {
			lineEnd++;
		}

		HTTPVersion version = HTTP_VERSION_NONE;
		if (StringCompare(versionString, "HTTP/1.1", 8)) {
			version = HTTP_VERSION_1_1;
		}
		else {
			fprintf(stderr, "Unrecognized HTTP version. Full request:\n");
			fprintf(stderr, "%.*s\n", n, buffer);
			close(clientSocketFD);
			break;
		}

		printf("HTTP version %d request, method %d, URI: %.*s\n",
			version, method, uriLength, uri);
		
		switch (method) {
			case HTTP_REQUEST_GET: {
				HandleGetRequest(uri, uriLength,
					buffer, CONNECTION_BUFFER_SIZE, clientSocketFD);
			} break;
			default: {
				fprintf(stderr, "Unhandled HTTP request method\n");
			} break;
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
	munmap(memory, CONNECTION_BUFFER_SIZE);
	printf("Stopped server on port %d\n", PORT_HTTP);

    return 0;
}