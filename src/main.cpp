#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <expat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <km_defines.h>
#include <km_log.h>
#include <km_string.h>

#define PORT_HTTP 8080
#define PORT_HTTPS 8181

#define LISTEN_BACKLOG_SIZE 5

#define HTTP_STATUS_LINE_MAX_LENGTH 1024

#define URI_PATH_MAX_LENGTH 64

#define DATA_MAX_FILES_PER_DIR 1024

bool done_ = false;

void PlatformFlushLogs(LogState* logState)
{
	fprintf(stderr, "TODO: implement this\n");
}

struct HTTPState
{
	static const int BUFFER_LENGTH = MEGABYTES(1);
	// FixedArray<char, BUFFER_LENGTH> buffer;
	int bufferN;
	char buffer[BUFFER_LENGTH];
	char dirFilePaths[DATA_MAX_FILES_PER_DIR][URI_PATH_MAX_LENGTH];
};

struct HTTPWriter
{
	static const uint64 BUFFER_LENGTH = MEGABYTES(16);

	uint64 bufferSize;
	char buffer[BUFFER_LENGTH];

	bool isHttps;
	int socketFD;
	SSL* ssl;

	bool Flush()
	{
		printf("Flushing %lu bytes\n", bufferSize);

		if (bufferSize == 0) {
			return true;
		}

		uint64 n = 0;
		while (n < bufferSize) {
			int written;
			if (isHttps) {
				written = SSL_write(ssl, buffer + n, bufferSize - n);
			}
			else {
				written = write(socketFD, buffer + n, bufferSize - n);
			}

			if (written < 0) {
				fprintf(stderr, "Flush error, errno %d\n", errno);
				return false;
			}
			if (written == 0) {
				break;
			}

			n += written;
		}

		if (n != bufferSize) {
			fprintf(stderr, "Incorrect number of bytes flushed (%lu, expected %lu)\n",
				n, bufferSize);
			return false;
		}

		bufferSize = 0;
		return true;
	}

	bool WriteStatus(int statusCode, const char* statusMsg)
	{
		printf("WriteStatus %d, message %s\n", statusCode, statusMsg);

		if (bufferSize != 0) {
			fprintf(stderr, "WriteStatus called with non-zero bufferSize\n");
			return false;
		}

		const char* STATUS_TEMPLATE = "HTTP/1.1 %d %s\r\n\r\n";
		int n = snprintf(buffer, BUFFER_LENGTH, STATUS_TEMPLATE, statusCode, statusMsg);
		if (n < 0 || n >= HTTP_STATUS_LINE_MAX_LENGTH) {
			fprintf(stderr, "HTTP status line too long: code %d, msg %s\n", statusCode, statusMsg);
			return false;
		}
		
		bufferSize += n;

		return true;
	}

	bool WriteStatusAndFlush(int statusCode, const char* statusMsg)
	{
		if (!WriteStatus(statusCode, statusMsg)) {
			return false;
		}
		if (!Flush()) {
			return false;
		}

		return true;
	}

	bool Write(const char* data, uint64 n)
	{
		printf("Write, %lu bytes\n", n);

		if (n == 0) {
			return true;
		}

		if (bufferSize + n > BUFFER_LENGTH) {
			uint64 n1 = BUFFER_LENGTH - bufferSize;
			if (!Write(data, n1)) {
				fprintf(stderr, "Large write #1 failed\n");
				return false;
			}
			if (!Flush()) {
				fprintf(stderr, "Large write flush failed\n");
				return false;
			}
			if (!Write(data + n1, n - n1)) {
				fprintf(stderr, "Large write #2 failed\n");
				return false;
			}
		}
		else {
			memcpy(buffer + bufferSize, data, n);
			bufferSize += n;
		}

		return true;
	}
};

struct XMLParseState
{
	static const int BUFFER_LENGTH = MEGABYTES(1);

	bool firstEntry;
	bool firstEntryData;
	bool readingEntry;
	bool readingArray;
	bool readingArrayElement;

	// TODO buffer might not be big enough?
	int bufferLength;
	char buffer[BUFFER_LENGTH];

	bool WriteContent(const char* str, int n)
	{
		if (bufferLength + n > BUFFER_LENGTH) {
			return false;
		}

		if (readingEntry) {
			// TODO fix newline expansion
			int offset = 0;
			for (int i = 0; i < n; i++) {
				if (str[i] == '\n' && (!readingArray || (readingArray && readingArrayElement))) {
					buffer[bufferLength + offset] = '\\';
					offset++;
					buffer[bufferLength + offset] = 'n';
				}
				else if (str[i] == '"') {
					buffer[bufferLength + offset] = '\\';
					offset++;
					buffer[bufferLength + offset] = '"';
				}
				else if (readingArray && readingArrayElement && str[i] == ',') {
					buffer[bufferLength + offset] = '"';
					offset++;
					buffer[bufferLength + offset] = ',';
					readingArrayElement = false;
				}
				else if (readingArray && !readingArrayElement && !IsWhitespace(str[i])) {
					buffer[bufferLength + offset] = '"';
					offset++;
					buffer[bufferLength + offset] = str[i];
					readingArrayElement = true;
				}
				else {
					buffer[bufferLength + offset] = str[i];
				}
				offset++;
			}
			bufferLength += offset;
		}
		else {
			memcpy(buffer + bufferLength, str, n);
			bufferLength += n;
		}

		return true;
	}

	bool WriteContent(const char* str)
	{
		return WriteContent(str, StringLength(str));
	}
};

struct ServerMemory
{
	HTTPState httpState;
	HTTPWriter httpWriter;
	XMLParseState xmlParseState;
};

enum HTTPRequestMethod
{
	HTTP_REQUEST_GET,
	HTTP_REQUEST_POST
};

enum HTTPVersion
{
	HTTP_VERSION_1_0,
	HTTP_VERSION_1_1
};

void SignalHandler(int s)
{
	printf("Caught signal %d\n", s);
	done_ = true;
}

void PrintSeparator()
{
	printf("========================================"
		"========================================\n");
}

bool ParseHTTPRequest(const char* request, int requestLength,
	HTTPRequestMethod* method, const char** uri, int* uriLength, HTTPVersion* version)
{
	// Read and parse request according to HTTP/1.1 standard
	// Source: https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
	const char* methodString = request;
	int firstSpace = 0;
	while (firstSpace < requestLength && request[firstSpace] != ' ') {
		firstSpace++;
	}

	if (StringCompare(methodString, "GET", 3)) {
		*method = HTTP_REQUEST_GET;
	}
	else if (StringCompare(methodString, "POST", 4)) {
		*method = HTTP_REQUEST_POST;
	}
	else {
		fprintf(stderr, "Unrecognized HTTP request method. Full request:\n");
		fprintf(stderr, "%.*s\n", requestLength, request);
		return false;
	}

	if (firstSpace + 1 >= requestLength) {
		fprintf(stderr, "Incomplete HTTP request\n");
		return false;
	}
	*uri = &request[firstSpace + 1];
	int secondSpace = firstSpace + 1;
	while (secondSpace < requestLength && request[secondSpace] != ' ') {
		secondSpace++;
	}
	*uriLength = secondSpace - firstSpace - 1;

	if (secondSpace + 1 >= requestLength) {
		fprintf(stderr, "Incomplete HTTP request\n");
		return false;
	}
	const char* versionString = &request[secondSpace + 1];
	int lineEnd = secondSpace + 1;
	while (lineEnd < requestLength && request[lineEnd] != '\r') {
		lineEnd++;
	}

	if (StringCompare(versionString, "HTTP/1.0", 8)) {
		*version = HTTP_VERSION_1_0;
	}
	else if (StringCompare(versionString, "HTTP/1.1", 8)) {
		*version = HTTP_VERSION_1_1;
	}
	else {
		fprintf(stderr, "Unrecognized HTTP version. Full request:\n");
		fprintf(stderr, "%.*s\n", requestLength, request);
		return false;
	}

	// TODO read HTTP headers

	return true;
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

bool HandleGetRequest(const char* uri, int uriLength, HTTPWriter* httpWriter)
{
	if (!ValidateGetURI(uri, uriLength)) {
		fprintf(stderr, "URI failed validation: %.*s\n", uriLength, uri);
		httpWriter->WriteStatusAndFlush(400, "Bad Request");
		return true;
	}

	const char* PUBLIC_DIR_PATH = "./public";
	const int PUBLIC_DIR_PATH_LENGTH = StringLength(PUBLIC_DIR_PATH);
	char path[URI_PATH_MAX_LENGTH];
	int pathLength = PUBLIC_DIR_PATH_LENGTH + uriLength;
	if (pathLength >= URI_PATH_MAX_LENGTH) {
		fprintf(stderr, "URI full path too long: %.*s\n", uriLength, uri);
		httpWriter->WriteStatusAndFlush(400, "Bad Request");
		return true;
	}
	memcpy(path, PUBLIC_DIR_PATH, PUBLIC_DIR_PATH_LENGTH);
	int offset = 0;
	for (int i = 0; i < uriLength; i++) {
		const char* c = uri + i;
		if (i < uriLength - 3 && *c == '%' && *(c + 1) == '2' && *(c + 2) == '0') {
			path[PUBLIC_DIR_PATH_LENGTH + offset] = ' ';
			i += 2;
		}
		else {
			path[PUBLIC_DIR_PATH_LENGTH + offset] = *c;
		}
		offset++;
	}
	path[PUBLIC_DIR_PATH_LENGTH + offset] = '\0';
	// memcpy(path + PUBLIC_DIR_PATH_LENGTH, uri, uriLength);
	// path[pathLength] = '\0';

	// Append index.html if necessary
	if (path[pathLength - 1] != '/') {
		int last = pathLength - 1;
		bool dotBeforeSlash = false;
		while (last >= 0 && path[last] != '/') {
			if (path[last] == '.') {
				dotBeforeSlash = true;
			}
			last--;
		}
		if (last != pathLength - 1 && !dotBeforeSlash) {
			if (pathLength + 1 >= URI_PATH_MAX_LENGTH) {
				fprintf(stderr, "URI + slash too long: %.*s\n", uriLength, uri);
				httpWriter->WriteStatusAndFlush(400, "Bad Request");
				return true;
			}
			path[pathLength++] = '/';
		}
	}
	if (path[pathLength - 1] == '/') {
		const char* indexFile = "index.html";
		int indexFileLength = StringLength(indexFile);
		if (pathLength + indexFileLength >= URI_PATH_MAX_LENGTH) {
			fprintf(stderr, "URI + index.html too long: %.*s\n", uriLength, uri);
			httpWriter->WriteStatusAndFlush(400, "Bad Request");
			return true;
		}
		for (int i = 0; i < indexFileLength; i++) {
			path[pathLength + i] = indexFile[i];
		}
		path[pathLength + indexFileLength] = '\0';
	}

	printf("Loading and sending file %s\n", path);
	int fileFD = open(path, O_RDONLY);
	if (fileFD < 0) {
		printf("Failed to open file %s\n", path);
		httpWriter->WriteStatusAndFlush(404, "Not Found");
		return true;
	}

	httpWriter->WriteStatusAndFlush(200, "OK");

	while (true) {
		int readBytes = read(fileFD, httpWriter->buffer, HTTPWriter::BUFFER_LENGTH);
		if (readBytes < 0) {
			fprintf(stderr, "Failed to read file %s\n", path);
			close(fileFD);
			httpWriter->Flush();
			return false;
		}
		if (readBytes == 0) {
			break;
		}

		httpWriter->bufferSize = readBytes;
		if (!httpWriter->Flush()) {
			fprintf(stderr, "Failed to write file %s to HTTP response\n", path);
			return false;
		}
	}

	close(fileFD);

	return true;
}

void StartXML(void* data, const char* el, const char** attr)
{
	XMLParseState* parseState = (XMLParseState*)data;

	if (StringLength(el) == 4 && StringCompare(el, "root", 4)) {
		parseState->WriteContent("{");
	}
	else {
		parseState->firstEntryData = true;

		if (parseState->firstEntry) {
			parseState->firstEntry = false;
		}
		else {
			parseState->WriteContent(",\n");
		}

		parseState->WriteContent("\"");
		parseState->WriteContent(el, StringLength(el));
		if (StringLength(el) == 6 && StringCompare(el, "images", 6)) {
			parseState->WriteContent("\": [");
			parseState->WriteContent("\"");
			parseState->readingArray = true;
			parseState->readingArrayElement = true;
		}
		else {
			parseState->WriteContent("\": \"");
		}

		parseState->readingEntry = true;
	}
}

void EndXML(void* data, const char* el)
{
	XMLParseState* parseState = (XMLParseState*)data;

	if (StringLength(el) == 4 && StringCompare(el, "root", 4)) {
		parseState->WriteContent("}");
	}
	else {
		parseState->readingEntry = false;
		
		int last = parseState->bufferLength - 1;
		while (last > 0 && IsWhitespace(parseState->buffer[last])) {
			last--;
		}
		while (last > 1 && parseState->buffer[last] == 'n'
		&& parseState->buffer[last - 1] == '\\') {
			last -= 2;
		}
		parseState->bufferLength = last + 1;

		if (StringLength(el) == 6 && StringCompare(el, "images", 6)) {
			parseState->WriteContent("\"");
			parseState->WriteContent("]");
			parseState->readingArray = false;
		}
		else {
			parseState->WriteContent("\"");
		}

	}
}

void DataXML(void* data, const char* content, int length)
{
	XMLParseState* parseState = (XMLParseState*)data;
	if (!parseState->readingEntry) {
		return;
	}

	int offset = 0;
	if (parseState->firstEntryData) {
		parseState->firstEntryData = false;
		while (offset < length && IsWhitespace(content[offset])) {
			offset++;
		}
	}

	parseState->WriteContent(content + offset, length - offset);
}

bool HandlePostRequest(const char* uri, int uriLength,
	HTTPState* httpState, HTTPWriter* httpWriter, XMLParseState* xmlParseState)
{
	const char* DATA_DIR_PATH = "./data";
	const int DATA_DIR_PATH_LENGTH = StringLength(DATA_DIR_PATH);

	char fullDirPath[URI_PATH_MAX_LENGTH];
	int fullDirPathLength = DATA_DIR_PATH_LENGTH + uriLength;
	if (DATA_DIR_PATH_LENGTH + uriLength >= URI_PATH_MAX_LENGTH) {
		fprintf(stderr, "Full dir path too long, URI %.*s\n", uriLength, uri);
		httpWriter->WriteStatusAndFlush(400, "Bad Request");
		return true;
	}
	memcpy(fullDirPath, DATA_DIR_PATH, DATA_DIR_PATH_LENGTH);
	memcpy(fullDirPath + DATA_DIR_PATH_LENGTH, uri, uriLength);
	if (fullDirPath[fullDirPathLength - 1] != '/') {
		fullDirPath[fullDirPathLength++] = '/'; // TODO not bounds-checking
	}
	fullDirPath[fullDirPathLength] = '\0';

	DIR* dir = opendir(fullDirPath);
	if (dir == NULL) {
		fprintf(stderr, "Failed to open data dir\n");
		httpWriter->WriteStatusAndFlush(400, "Bad Request");
		return true;
	}

	int numFiles = 0;
	dirent* dirEntry;
	while ((dirEntry = readdir(dir)) != NULL) {
		const char* name = dirEntry->d_name;
		int nameLength = StringLength(name);
		if (nameLength > 4 && StringCompare(name + nameLength - 4, ".xml", 4)) {
			char* filePath = httpState->dirFilePaths[numFiles];
			if (fullDirPathLength + nameLength >= URI_PATH_MAX_LENGTH) {
				fprintf(stderr, "Path too long for XML file %s in dir %s\n", name, fullDirPath);
				continue;
			}
			memcpy(filePath, fullDirPath, fullDirPathLength);
			memcpy(filePath + fullDirPathLength, name, nameLength);
			filePath[fullDirPathLength + nameLength] = '\0';

			numFiles++;
		}
	}

	closedir(dir);

	// URI_PATH_MAX_LENGTH
	int dirFilePathsOrder[DATA_MAX_FILES_PER_DIR];
	for (int i = 0; i < numFiles; i++) {
		dirFilePathsOrder[i] = i;
	}

	if (!httpWriter->WriteStatus(200, "OK")) {
		// TODO something?
	}
	if (!httpWriter->Write("[", 1)) {
		// TODO something?
	}

	for (int i = 0; i < numFiles; i++) {
		const char* filePath = httpState->dirFilePaths[dirFilePathsOrder[i]];
		int fileFD = open(filePath, O_RDONLY);
		if (fileFD < 0) {
			fprintf(stderr, "Error opening XML file %s\n", filePath);
			continue;
		}
		int n = read(fileFD, httpState->buffer, HTTPState::BUFFER_LENGTH);
		if (n < 0) {
			fprintf(stderr, "Failed to read from XML file %s\n", filePath);
			close(fileFD);
			continue;
		}
		close(fileFD);

		XML_Parser parser = XML_ParserCreate(NULL);
		XML_SetElementHandler(parser, StartXML, EndXML);
		XML_SetCharacterDataHandler(parser, DataXML);
		XML_SetUserData(parser, xmlParseState);
		xmlParseState->bufferLength = 0;
		xmlParseState->firstEntry = true;

		XML_Parse(parser, httpState->buffer, n, true);

		XML_ParserFree(parser);

		if (i != 0) {
			if (!httpWriter->Write(",", 1)) {
				// TODO something?
			}
		}
		
		if (!httpWriter->Write(xmlParseState->buffer, xmlParseState->bufferLength)) {
			fprintf(stderr, "Failed to write parsed file contents for %s\n", filePath);
			continue;
		}
	}

	if (!httpWriter->Write("]", 1)) {
		// TODO something?
	}

	httpWriter->Flush();

	return true;
}

bool HandleHTTPRequest(HTTPState* httpState, HTTPWriter* httpWriter, XMLParseState* xmlParseState)
{
	HTTPRequestMethod method;
	const char* uri;
	int uriLength;
	HTTPVersion version;
	if (!ParseHTTPRequest(httpState->buffer, httpState->bufferN, &method, &uri, &uriLength, &version)) {
		// TODO bleh
		return false;
	}

	printf("HTTP version %d request, method %d, URI: %.*s\n",
		version, method, uriLength, uri);
	
	httpWriter->bufferSize = 0;
	bool success = false;
	switch (method) {
		case HTTP_REQUEST_GET: {
			success = HandleGetRequest(uri, uriLength, httpWriter);
		} break;
		case HTTP_REQUEST_POST: {
			success = HandlePostRequest(uri, uriLength, httpState, httpWriter, xmlParseState);
		} break;
		default: {
			fprintf(stderr, "Unhandled HTTP request method\n");
			return false;
		} break;
	}

	if (!success) {
		fprintf(stderr, "Failed to handle HTTP request\n");
		return false;
	}

	if (httpWriter->bufferSize != 0) {
		fprintf(stderr, "Unflushed data in HTTP writer after handler\n");
		httpWriter->Flush();
	}

	return true;
}

bool OpenSocket(int port, int* outSocketFD)
{
	int socketFD = socket(AF_INET, SOCK_STREAM, 0);
	if (socketFD < 0) {
		fprintf(stderr, "Failed to open socket\n");
		return false;
	}

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_port = htons(port);

	if (bind(socketFD, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
		fprintf(stderr, "Failed to bind server addr with port %d to socket\n", port);
		close(socketFD);
		return false;
	}

	if (listen(socketFD, LISTEN_BACKLOG_SIZE) < 0) {
		fprintf(stderr, "Failed to listen to socket on port %d\n", port);
		close(socketFD);
		return false;
	}

	printf("Listening on port %d\n", port);

	*outSocketFD = socketFD;
	return true;
}

void RunServer(ServerMemory* serverMemory, int port, bool isHttps)
{
	HTTPState& httpState = serverMemory->httpState;
	HTTPWriter& httpWriter = serverMemory->httpWriter;

	if (isHttps) {
	    SSL_load_error_strings();
	    SSL_library_init();
	    OpenSSL_add_all_algorithms();
	}

	int socketFD;
	if (!OpenSocket(port, &socketFD)) {
		return;
	}
	
	httpWriter.isHttps = isHttps;

	sockaddr_in clientAddr;
	socklen_t clientAddrLen = sizeof(clientAddr);

	while (!done_) {
		int clientSocketFD = accept(socketFD, (sockaddr*)&clientAddr, &clientAddrLen);
		if (clientSocketFD < 0) {
			fprintf(stderr, "Failed to accept client connection\n");
			continue;
		}

		PrintSeparator();
		printf("Received client connection\n");

		SSL* ssl;
		int n;
		if (isHttps) {
			SSL_CTX* sslCtx = SSL_CTX_new(SSLv23_server_method());
			SSL_CTX_set_options(sslCtx, SSL_OP_SINGLE_DH_USE);

			int useCert = SSL_CTX_use_certificate_file(sslCtx, "./keys/cert.pem",
				SSL_FILETYPE_PEM);
			int usePriv = SSL_CTX_use_PrivateKey_file(sslCtx, "./keys/privkey.pem",
				SSL_FILETYPE_PEM);
			if (useCert != 1 || usePriv != 1) {
				// bleh
				printf("bad use\n");
				continue;
			}

			ssl = SSL_new(sslCtx);
			SSL_set_fd(ssl, clientSocketFD);

			int sslError = SSL_accept(ssl);
			if (sslError <= 0) {
				// bleh
				printf("accept error\n");
				ERR_print_errors_fp(stderr);
				continue;
			}

			// TODO buffer might not be big enough?
			n = SSL_read(ssl, httpState.buffer, HTTPState::BUFFER_LENGTH);
			if (n < 0) {
				fprintf(stderr, "Failed to read from client socket\n");
				continue;
			}
			if (n == 0) {
				continue;
			}
		}
		else {
			// TODO buffer might not be big enough?
			n = read(clientSocketFD, httpState.buffer, HTTPState::BUFFER_LENGTH);
			if (n < 0) {
				fprintf(stderr, "Failed to read request from client socket\n");
				continue;
			}
			if (n == 0) {
				continue;
			}
		}

		httpState.bufferN = n;
		httpWriter.socketFD = clientSocketFD;
		if (!HandleHTTPRequest(&httpState, &httpWriter, &serverMemory->xmlParseState)) {
			// bleh
		}

		if (isHttps) {
			SSL_shutdown(ssl);
			SSL_free(ssl);
		}

		close(clientSocketFD);
		printf("Closed HTTP client connection\n");
	}

	close(socketFD);
	printf("Stopped server on port %d\n", port);
}

void* HttpsServerThread(void* data)
{
	RunServer((ServerMemory*)data, PORT_HTTPS, true);
	return nullptr;
}

int main(int argc, char* argv[])
{
	if (HTTPState::BUFFER_LENGTH > SSIZE_MAX) {
		fprintf(stderr, "Buffer size too large for read(...)\n");
		return 1;
	}

	struct sigaction sigIntHandler;
	sigIntHandler.sa_handler = SignalHandler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;
	sigaction(SIGINT, &sigIntHandler, NULL);

	size_t requiredMemory = 2 * sizeof(ServerMemory) + sizeof(LogState);
	size_t pageSize = getpagesize();
	size_t requiredPages = (requiredMemory / pageSize) + 1;
	size_t allocatedMemorySize = requiredPages * pageSize;
	void* allocatedMemory = mmap(NULL, allocatedMemorySize,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1, 0);
	if (allocatedMemory == MAP_FAILED) {
		fprintf(stderr, "Failed to allocate memory for server buffer using mmap\n");
		return 1;
	}

	ServerMemory* httpMemory = (ServerMemory*)((char*)allocatedMemory);
	ServerMemory* httpsMemory = (ServerMemory*)((char*)allocatedMemory + sizeof(ServerMemory));
	printf("Allocated %zu bytes (%.03f MB) for HTTP and HTTPS servers\n", allocatedMemorySize,
		(float)allocatedMemorySize / MEGABYTES(1));

	logState_ = (LogState*)((char*)allocatedMemory + 2 * sizeof(ServerMemory));

	pthread_t thread;
	pthread_create(&thread, NULL, HttpsServerThread, (void*)httpsMemory);

	RunServer(httpMemory, PORT_HTTP, false);

	pthread_join(thread, NULL);

	munmap(allocatedMemory, allocatedMemorySize);
	printf("Server shutting down\n");

	return 0;
}

#include <km_debug.cpp>
#include <km_lib.cpp>
#include <km_log.cpp>
#include <km_string.cpp>

#define STB_SPRINTF_IMPLEMENTATION
#include <stb_sprintf.h>