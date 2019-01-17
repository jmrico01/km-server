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

#include <expat.h>

#define KILOBYTES(b) (b * 1024)
#define MEGABYTES(b) (KILOBYTES(b) * 1024)

#define PORT_HTTP 8080
#define PORT_HTTPS 8181

#define LISTEN_BACKLOG_SIZE 5

#define BUFFER_LENGTH MEGABYTES(1)

#define HTTP_STATUS_LINE_MAX_LENGTH 1024

#define URI_PATH_MAX_LENGTH 1024

struct ServerMemory
{
	char buffer[BUFFER_LENGTH];
};

enum HTTPRequestMethod
{
	HTTP_REQUEST_GET,
	HTTP_REQUEST_POST,

	HTTP_REQUEST_NONE
};

enum HTTPVersion
{
	HTTP_VERSION_1_0,
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

// Returns length of parsed HTTP request into buffer, or -1 on error
int ParseRequest(int clientSocketFD, char* buffer, int bufferLength,
	HTTPRequestMethod& outMethod,
	const char** outURI, int& outURILength,
	HTTPVersion& outVersion)
{
	// Read and parse request according to HTTP/1.1 standard
	// Source: https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html

	int n = read(clientSocketFD, buffer, bufferLength);
	if (n < 0) {
		fprintf(stderr, "Failed to read from client socket\n");
		return -1;
	}

	if (n == 0) {
		return -1;
	}

	const char* methodString = buffer;
	int firstSpace = 0;
	while (firstSpace < n && buffer[firstSpace] != ' ') {
		firstSpace++;
	}

	outMethod = HTTP_REQUEST_NONE;
	if (StringCompare(methodString, "GET", 3)) {
		outMethod = HTTP_REQUEST_GET;
	}
	else if (StringCompare(methodString, "POST", 4)) {
		outMethod = HTTP_REQUEST_POST;
	}
	else {
		fprintf(stderr, "Unrecognized HTTP request method. Full request:\n");
		fprintf(stderr, "%.*s\n", n, buffer);
		return -1;
	}

	if (firstSpace + 1 >= n) {
		fprintf(stderr, "Incomplete HTTP request\n");
		return -1;
	}
	*outURI = &buffer[firstSpace + 1];
	int secondSpace = firstSpace + 1;
	while (secondSpace < n && buffer[secondSpace] != ' ') {
		secondSpace++;
	}
	outURILength = secondSpace - firstSpace - 1;

	if (secondSpace + 1 >= n) {
		fprintf(stderr, "Incomplete HTTP request\n");
		return -1;
	}
	const char* versionString = &buffer[secondSpace + 1];
	int lineEnd = secondSpace + 1;
	while (lineEnd < n && buffer[lineEnd] != '\r') {
		lineEnd++;
	}

	outVersion = HTTP_VERSION_NONE;
	if (StringCompare(versionString, "HTTP/1.0", 8)) {
		outVersion = HTTP_VERSION_1_0;
	}
	else if (StringCompare(versionString, "HTTP/1.1", 8)) {
		outVersion = HTTP_VERSION_1_1;
	}
	else {
		fprintf(stderr, "Unrecognized HTTP version. Full request:\n");
		fprintf(stderr, "%.*s\n", n, buffer);
		return -1;
	}

	// TODO read HTTP headers

	return n;
}

void WriteStatus(int clientSocketFD, int statusCode, const char* statusMsg)
{
	const char* STATUS_TEMPLATE = "HTTP/1.1 %d %s\r\n";
	char statusLine[HTTP_STATUS_LINE_MAX_LENGTH];
	int n = snprintf(statusLine, HTTP_STATUS_LINE_MAX_LENGTH, STATUS_TEMPLATE, statusCode, statusMsg);
	if (n < 0 || n >= HTTP_STATUS_LINE_MAX_LENGTH) {
		fprintf(stderr, "HTTP status line too long: code %d, msg %s\n", statusCode, statusMsg);
		return;
	}

	n = write(clientSocketFD, statusLine, StringLength(statusLine));
	if (n < 0) {
		fprintf(stderr, "Failed to write status: code %d, msg %s\n", statusCode, statusMsg);
		return;
	}
	n = write(clientSocketFD, "\r\n", 2);
	if (n < 0) {
		fprintf(stderr, "Failed to CRLF for status: code %d, msg %s\n", statusCode, statusMsg);
	}
}

bool ValidateGetURI(const char* uri, int uriLength)
{
	int consecutiveDots = 0;
	for (int i = 0; i < uriLength; i++) {
		if (uri[i] == '.') {
			if (consecutiveDots > 0) {
				return false;
			}
			consecutiveDots++;
		}
		else {
			consecutiveDots = 0;
		}
	}

	return true;
}

void HandleGetRequest(const char* uri, int uriLength,
	char* buffer, int bufferLength, int clientSocketFD)
{
	if (!ValidateGetURI(uri, uriLength)) {
		printf("URI failed validation: %.*s\n", uriLength, uri);
		WriteStatus(clientSocketFD, 400, "Bad Request");
		return;
	}

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

	printf("Loading and sending file %s\n", path);
	int fileFD = open(path, O_RDONLY);
	if (fileFD < 0) {
		printf("Failed to open file %s\n", path);
		WriteStatus(clientSocketFD, 404, "Not Found");
		return;
	}

	WriteStatus(clientSocketFD, 200, "OK");

	while (true) {
		int n = read(fileFD, buffer, bufferLength);
		if (n < 0) {
			// TODO Uh oh... we already sent status 200
			fprintf(stderr, "Failed to read file %s\n", path);
			close(fileFD);
			return;
		}
		if (n == 0) {
			break;
		}

		int res = write(clientSocketFD, buffer, n);
		if (res < 0) {
			fprintf(stderr, "Failed to write file contents\n");
			return;
		}
	}

	close(fileFD);
}

void StartXML(void* data, const char* el, const char** attr)
{
	printf("start %s\n", el);

	for (int i = 0; attr[i]; i += 2) {
		printf("%s='%s'", attr[i], attr[i + 1]);
	}
}

void EndXML(void* data, const char* el)
{
	printf("end %s\n", el);
}

void DataXML(void* data, const char* content, int length)
{
	printf("%.*s\n", length, content);
}

int main(int argc, char* argv[])
{
	if (BUFFER_LENGTH > SSIZE_MAX) {
		fprintf(stderr, "Buffer size too large for read(...)\n");
		return 1;
	}

	struct sigaction sigIntHandler;

	sigIntHandler.sa_handler = SignalHandler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);

	int allocatedMemorySize = sizeof(ServerMemory);
	void* allocatedMemory = mmap(NULL, allocatedMemorySize,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1, 0);
	if (allocatedMemory == MAP_FAILED) {
		fprintf(stderr, "Failed to allocate memory for server buffer using mmap\n");
		return 1;
	}
	ServerMemory* memory = (ServerMemory*)allocatedMemory;

	int socketFD = socket(AF_INET, SOCK_STREAM, 0);
	if (socketFD < 0) {
		fprintf(stderr, "Failed to open socket\n");
		munmap(allocatedMemory, allocatedMemorySize);
		return 1;
	}

	sockaddr_in serverAddr = {};
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_port = htons(PORT_HTTP);

	if (bind(socketFD, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
		fprintf(stderr, "Failed to bind server addr with port %d to socket\n", PORT_HTTP);
		close(socketFD);
		munmap(allocatedMemory, allocatedMemorySize);
		return 1;
	}

	if (listen(socketFD, LISTEN_BACKLOG_SIZE) < 0) {
		fprintf(stderr, "Failed to listen to socket on port %d\n", PORT_HTTP);
		close(socketFD);
		munmap(allocatedMemory, allocatedMemorySize);
		return 1;
	}

	printf("Server listening on port %d\n", PORT_HTTP);

	sockaddr_in clientAddr;
	socklen_t clientAddrLen = sizeof(clientAddr);
	char* buffer = memory->buffer;

	while (!done) {
		int clientSocketFD = accept(socketFD, (sockaddr*)&clientAddr, &clientAddrLen);
		if (clientSocketFD < 0) {
			fprintf(stderr, "Failed to accept client connection\n");
			continue;
		}

		PrintSeparator();
		printf("Received client connection\n");

		HTTPRequestMethod method;
		const char* uri;
		int uriLength;
		HTTPVersion version;
		int requestLength = ParseRequest(clientSocketFD, buffer, BUFFER_LENGTH,
			method, &uri, uriLength, version);
		if (requestLength < 0) {
			close(clientSocketFD);
			continue;
		}

		printf("HTTP version %d request, method %d, URI: %.*s\n",
			version, method, uriLength, uri);
		
		switch (method) {
			case HTTP_REQUEST_GET: {
				HandleGetRequest(uri, uriLength,
					buffer, BUFFER_LENGTH, clientSocketFD);
			} break;
			case HTTP_REQUEST_POST: {
				printf("Implement this! (POST)\n");
				printf("%.*s\n", requestLength, buffer);

				XML_Parser parser = XML_ParserCreate(NULL);
				XML_SetElementHandler(parser, StartXML, EndXML);
				XML_SetCharacterDataHandler(parser, DataXML);

				int fileFD = open("data/games/saito.xml", O_RDONLY);
				if (fileFD < 0) {
					fprintf(stderr, "EROROROROROR\n");
					continue;
				}

				int n = read(fileFD, buffer, BUFFER_LENGTH);
				printf("%.*s\n", n, buffer);

				close(fileFD);

				XML_Parse(parser, buffer, n, true);

				XML_ParserFree(parser);
			}
			default: {
				fprintf(stderr, "Unhandled HTTP request method\n");
			} break;
		}

		close(clientSocketFD);
		printf("Closed connection with client\n");
	}

	close(socketFD);
	munmap(allocatedMemory, allocatedMemorySize);
	printf("Stopped server on port %d\n", PORT_HTTP);

	return 0;
}
