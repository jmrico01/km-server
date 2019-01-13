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

#define HTTP_STATUS_LINE_MAX_LENGTH 1024

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

void PrintSeparator()
{
	printf("========================================"
		"========================================\n");
}

inline bool IsWhitespace(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

int StringLength(const char* str)
{
	int length = 0;
	while (str[length] != '\0') {
		length++;
	}

	return length;
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

void WriteStatus(int clientSocketFD, int statusCode, const char* statusMsg)
{
	char statusLine[HTTP_STATUS_LINE_MAX_LENGTH];
	snprintf(statusLine, HTTP_STATUS_LINE_MAX_LENGTH,
		"HTTP/1.1 %d %s\r\n", statusCode, statusMsg);
	write(clientSocketFD, statusLine, StringLength(statusLine));
}

void HandleGetRequest(const char* uri, int uriLength,
	char* buffer, int bufferMaxSize, int clientSocketFD)
{
	char path[URI_PATH_MAX_LENGTH];
	int pathLength = snprintf(path, URI_PATH_MAX_LENGTH, "public%.*s", uriLength, uri);
	if (pathLength < 0 || pathLength >= URI_PATH_MAX_LENGTH) {
		printf("URI too long: %.*s\n", uriLength, uri);
		WriteStatus(clientSocketFD, 400, "Bad Request");
		return;
	}

	// Append index.html if necessary
	const char* indexFile = "index.html";
	int indexFileLength = StringLength(indexFile);
	if (path[pathLength - 1] == '/'
	&& pathLength + indexFileLength < URI_PATH_MAX_LENGTH) {
		for (int i = 0; i < indexFileLength; i++) {
			path[pathLength + i] = indexFile[i];
		}
		path[pathLength + indexFileLength] = '\0';
	}

	printf("Loading file %s\n", path);
	int fileFD = open(path, O_RDONLY);
	if (fileFD < 0) {
		printf("Failed to open file %s\n", path);
		WriteStatus(clientSocketFD, 404, "Not Found");
		return;
	}

	WriteStatus(clientSocketFD, 200, "OK");
	write(clientSocketFD, "\r\n", 2);

	int n;
	while (true) {
		n = read(fileFD, buffer, bufferMaxSize);
		if (n < 0) {
			// TODO Uh oh... we already sent status 200
			fprintf(stderr, "Failed to read file %s\n", path);
			close(fileFD);
			return;
		}
		if (n == 0) {
			break;
		}

		write(clientSocketFD, buffer, n);
	}

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
			continue;
		}

		PrintSeparator();
		printf("Received client connection\n");

		n = read(clientSocketFD, buffer, CONNECTION_BUFFER_SIZE);
		if (n < 0) {
			fprintf(stderr, "Failed to read from client socket\n");
			close(clientSocketFD);
			continue;
		}

		if (n == 0) {
			close(clientSocketFD);
			continue;
		}

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
			fprintf(stderr, "Length: %d\n", n);
			close(clientSocketFD);
			continue;
		}

		if (firstSpace + 1 >= n) {
			fprintf(stderr, "Incomplete HTTP request\n");
			close(clientSocketFD);
			continue;
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
			continue;
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
			continue;
		}

		printf("HTTP version %d request, method %d, URI: %.*s\n",
			version, method, uriLength, uri);
		
		switch (method) {
			case HTTP_REQUEST_GET: {
				HandleGetRequest(uri, uriLength,
					buffer, CONNECTION_BUFFER_SIZE, clientSocketFD);
				/*int fileLength = GetFileContents(uri, uriLength,
					buffer, CONNECTION_BUFFER_SIZE);

				if (fileLength < 0) {
					WriteStatus(clientSocketFD, 404, "Not Found");
					continue;
				}

				WriteStatus(clientSocketFD, 200, "OK");
				write(clientSocketFD, "\r\n", 2);
				write(clientSocketFD, buffer, fileLength);*/
			} break;
			case HTTP_REQUEST_POST: {
				printf("Implement this!\n");
			}
			default: {
				fprintf(stderr, "Unhandled HTTP request method\n");
			} break;
		}

		close(clientSocketFD);
		printf("Closed connection with client\n");
	}

	close(socketFD);
	munmap(memory, CONNECTION_BUFFER_SIZE);
	printf("Stopped server on port %d\n", PORT_HTTP);

    return 0;
}