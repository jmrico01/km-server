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

const uint64 DATA_MAX_FILES_PER_DIR = 1024;
const uint64 HTTP_STATUS_LINE_MAX_LENGTH = 1024;
const uint64 HTTP_CONTENT_TYPE_MAX_LENGTH = 1024;
const uint64 URI_PATH_MAX_LENGTH = 256;

bool done_ = false;

void PlatformFlushLogs(LogState* logState)
{
	fprintf(stderr, "TODO: implement this\n");
}

void SignalHandler(int s)
{
	printf("Caught signal %d\n", s);
	done_ = true;
}

enum class StaticFileType
{
	HTML = 0,
	JS,
	CSS,
	PNG,
	JPG,
	TTF,
	OTF,
	WOFF,
	WOFF2,

	OTHER
};
const char* fileTypeExtensions_[] = {
	"html",
	"js",
	"css"
	"png",
	"jpg",
	"ttf",
	"otf",
	"woff",
	"woff2"
};
const char* fileTypeContentTypes_[] = {
	"text/html; charset=UTF-8",
	"text/javascript; charset=UTF-8",
	"text/css; charset=UTF-8",
	"image/png",
	"image/jpeg",
	"font/ttf",
	"font/otf",
	"application/font-woff",
	"application/font-woff2"
};

template <uint64 BUFFER_MAX_SIZE>
struct HTTPWriter
{
	FixedArray<char, BUFFER_MAX_SIZE>* bufferPtr;
	bool isHttps;
	int socketFD;
	SSL* ssl;

	bool Flush()
	{
		printf("Flushing %lu bytes\n", bufferPtr->array.size);

		if (bufferPtr->array.size == 0) {
			return true;
		}

		uint64 n = 0;
		while (n < bufferPtr->array.size) {
			int written;
			if (isHttps) {
				written = SSL_write(ssl, bufferPtr->array.data + n, bufferPtr->array.size - n);
			}
			else {
				written = write(socketFD, bufferPtr->array.data + n, bufferPtr->array.size - n);
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

		if (n != bufferPtr->array.size) {
			fprintf(stderr, "Incorrect number of bytes flushed (%lu, expected %lu)\n",
				n, bufferPtr->array.size);
			return false;
		}

		bufferPtr->array.size = 0;
		return true;
	}

	bool WriteStatus(int statusCode, const char* statusMsg)
	{
		printf("WriteStatus %d, message %s\n", statusCode, statusMsg);

		if (bufferPtr->array.size != 0) {
			fprintf(stderr, "WriteStatus called with non-zero buffer size\n");
			return false;
		}

		const char* STATUS_TEMPLATE = "HTTP/1.1 %d %s\r\n";
		int n = snprintf(bufferPtr->array.data, BUFFER_MAX_SIZE,
			STATUS_TEMPLATE, statusCode, statusMsg);
		if (n < 0 || (uint64)n >= HTTP_STATUS_LINE_MAX_LENGTH) {
			fprintf(stderr, "HTTP status line too long: code %d, msg %s\n", statusCode, statusMsg);
			return false;
		}
		
		bufferPtr->array.size += n;

		return true;
	}

	bool WriteStatusAndEndHeader(int statusCode, const char* statusMsg)
	{
		if (!WriteStatus(statusCode, statusMsg)) {
			return false;
		}
		if (!WriteString("\r\n")) {
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

		if (bufferPtr->array.size + n > BUFFER_MAX_SIZE) {
			uint64 n1 = BUFFER_MAX_SIZE - bufferPtr->array.size;
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
			MemCopy(bufferPtr->array.data + bufferPtr->array.size, data, n);
			bufferPtr->array.size += n;
		}

		return true;
	}

	bool Write(Array<char> data)
	{
		return Write(data.data, data.size);
	}

	bool WriteString(const char* string)
	{
		uint64 stringLength = StringLength(string);
		return Write(string, stringLength);
	}
};

struct ServerMemory
{
	static const uint64 BUFFER_LENGTH = MEGABYTES(32);
	FixedArray<char, BUFFER_LENGTH> buffer;

	void Init()
	{
		buffer.Init();
	}
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

void PrintSeparator()
{
	printf("========================================"
		"========================================\n");
}

bool ValidateGetURI(const Array<char>& uri)
{
	int consecutiveDots = 0;
	for (uint64 i = 0; i < uri.size; i++) {
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

template <uint64 BUFFER_MAX_SIZE>
bool HandleGetRequest(const Array<char>& uri, HTTPWriter<BUFFER_MAX_SIZE>* httpWriter)
{
	// Serve static file
	if (!ValidateGetURI(uri)) {
		fprintf(stderr, "URI failed validation: %.*s\n", (int)uri.size, uri.data);
		httpWriter->WriteStatusAndEndHeader(400, "Bad Request");
		return true;
	}

	FixedArray<char, URI_PATH_MAX_LENGTH> filePath;
	filePath.Init();
	InitFromCString(&filePath, "./public");
	if (filePath.array.size + uri.size >= URI_PATH_MAX_LENGTH) {
		fprintf(stderr, "URI full path too long: %.*s\n", (int)uri.size, uri.data);
		httpWriter->WriteStatusAndEndHeader(400, "Bad Request");
		return true;
	}

	uint64 offset = 0;
	for (uint64 i = 0; i < uri.size; i++) {
		const char* c = uri.data + i;
		if (i < uri.size - 3 && *c == '%' && *(c + 1) == '2' && *(c + 2) == '0') {
			filePath.Append(' ');
			i += 2;
		}
		else {
			filePath.Append(*c);
		}
		offset++;
	}

	// Append index.html if necessary
	if (filePath[filePath.array.size - 1] != '/') {
		uint64 lastSlash = filePath.array.size;
		bool dotBeforeSlash = false;
		while (lastSlash != 0 && filePath[lastSlash - 1] != '/') {
			if (filePath[lastSlash - 1] == '.') {
				dotBeforeSlash = true;
			}
			lastSlash--;
		}
		if (!dotBeforeSlash) {
			if (filePath.array.size + 1 >= URI_PATH_MAX_LENGTH) {
				fprintf(stderr, "URI + slash too long: %.*s\n", (int)uri.size, uri.data);
				httpWriter->WriteStatusAndEndHeader(400, "Bad Request");
				return true;
			}
			filePath.Append('/');
		}
	}
	if (filePath[filePath.array.size - 1] == '/') {
		if (!StringAppend(&filePath, "index.html")) {
			fprintf(stderr, "URI + index.html too long: %.*s\n", (int)uri.size, uri.data);
			httpWriter->WriteStatusAndEndHeader(400, "Bad Request");
			return true;
		}
	}

	if (filePath.array.size + 1 >= URI_PATH_MAX_LENGTH) {
		fprintf(stderr, "URI + null terminator too long: %.*s\n", (int)uri.size, uri.data);
		httpWriter->WriteStatusAndEndHeader(400, "Bad Request");
		return true;
	}
	filePath.Append('\0');

	printf("Loading and sending file %s\n", filePath.array.data);
	int fileFD = open(filePath.array.data, O_RDONLY);
	if (fileFD < 0) {
		printf("Failed to open file %s\n", filePath.array.data);
		httpWriter->WriteStatusAndEndHeader(404, "Not Found");
		return true;
	}

	httpWriter->WriteStatus(200, "OK");
	httpWriter->WriteString("Connection: keep-alive\r\n");
	httpWriter->WriteString("Content-Encoding: identity\r\n");

	uint64 lastDot = GetLastOccurrence(filePath.array, '.');
	Array<char> fileExtension;
	fileExtension.data = &filePath[lastDot];
	fileExtension.size = filePath.array.size - lastDot;
	StaticFileType fileType = StaticFileType::OTHER;
	for (int i = 0; i < (int)StaticFileType::OTHER; i++) {
		if (StringCompare(fileExtension, fileTypeExtensions_[i])) {
			fileType = (StaticFileType)i;
		}
	}
	if (fileType != StaticFileType::OTHER) {
		FixedArray<char, HTTP_CONTENT_TYPE_MAX_LENGTH> contentType;
		contentType.Init();
		InitFromCString(&contentType, "Content-Type: ");
		StringAppend(&contentType, fileTypeContentTypes_[(int)fileType]);
		StringAppend(&contentType, "\r\n");
		httpWriter->Write(contentType.array);
	}

	httpWriter->WriteString("\r\n");
	httpWriter->Flush();

	while (true) {
		int readBytes = read(fileFD, httpWriter->bufferPtr->array.data, BUFFER_MAX_SIZE);
		if (readBytes < 0) {
			fprintf(stderr, "Failed to read file %s\n", filePath.array.data);
			close(fileFD);
			httpWriter->Flush();
			return false;
		}
		if (readBytes == 0) {
			break;
		}

		httpWriter->bufferPtr->array.size = readBytes;
		if (!httpWriter->Flush()) {
			fprintf(stderr, "Failed to write file %s to HTTP response\n", filePath.array.data);
			return false;
		}
	}

	close(fileFD);
	return true;
}

#if 0
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
	MemCopy(fullDirPath, DATA_DIR_PATH, DATA_DIR_PATH_LENGTH);
	MemCopy(fullDirPath + DATA_DIR_PATH_LENGTH, uri, uriLength);
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
			MemCopy(filePath, fullDirPath, fullDirPathLength);
			MemCopy(filePath + fullDirPathLength, name, nameLength);
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
#endif

bool ParseHTTPRequest(const Array<char>& request, HTTPRequestMethod* outMethod,
	HTTPVersion* outVersion, FixedArray<char, URI_PATH_MAX_LENGTH>* outUri)
{
	// Read and parse request according to HTTP/1.1 standard
	// Source: https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
	uint64 i = 0;
	while (i < request.size && request[i] != ' ') {
		i++;
	}

	Array<char> methodString;
	methodString.data = request.data;
	methodString.size = i;
	if (StringCompare(methodString, "GET")) {
		*outMethod = HTTP_REQUEST_GET;
	}
	else if (StringCompare(methodString, "POST")) {
		*outMethod = HTTP_REQUEST_POST;
	}
	else {
		fprintf(stderr, "Unrecognized HTTP request method. Full request:\n");
		fprintf(stderr, "%.*s\n", (int)request.size, request.data);
		return false;
	}

	i++;
	if (i >= request.size) {
		fprintf(stderr, "Incomplete HTTP request\n");
		return false;
	}
	uint64 uriStart = i;
	while (i < request.size && request[i] != ' ') {
		i++;
	}
	outUri->array.size = i - uriStart;
	MemCopy(outUri->array.data, &request.data[uriStart], outUri->array.size);

	i++;
	if (i >= request.size) {
		fprintf(stderr, "Incomplete HTTP request\n");
		return false;
	}
	uint64 versionStart = i;
	while (i < request.size && request[i] != '\r') {
		i++;
	}
	Array<char> versionString;
	versionString.data = &request.data[versionStart];
	versionString.size = i - versionStart;

	if (StringCompare(versionString, "HTTP/1.0")) {
		*outVersion = HTTP_VERSION_1_0;
	}
	else if (StringCompare(versionString, "HTTP/1.1")) {
		*outVersion = HTTP_VERSION_1_1;
	}
	else {
		fprintf(stderr, "Unrecognized HTTP version. Full request:\n");
		fprintf(stderr, "%.*s\n", (int)request.size, request.data);
		return false;
	}

	// TODO read HTTP headers

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

	*outSocketFD = socketFD;
	return true;
}

void RunServer(ServerMemory* serverMemory, int port, bool isHttps)
{
	if (isHttps) {
	    SSL_load_error_strings();
	    SSL_library_init();
	    OpenSSL_add_all_algorithms();
	}

	int socketFD;
	if (!OpenSocket(port, &socketFD)) {
		return;
	}
	defer(close(socketFD));

	printf("Listening on port %d\n", port);

	sockaddr_in clientAddr;
	socklen_t clientAddrLen = sizeof(clientAddr);

	while (!done_) {
		int clientSocketFD = accept(socketFD, (sockaddr*)&clientAddr, &clientAddrLen);
		if (clientSocketFD < 0) {
			fprintf(stderr, "Failed to accept client connection\n");
			continue;
		}
		defer(close(clientSocketFD));

		PrintSeparator();
		printf("Received client connection\n");

		SSL* ssl;
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
			int n = SSL_read(ssl, &serverMemory->buffer[0], ServerMemory::BUFFER_LENGTH);
			if (n < 0) {
				fprintf(stderr, "Failed to read from client socket\n");
				continue;
			}
			if (n == 0) {
				continue;
			}
			serverMemory->buffer.array.size = n;
		}
		else {
			// TODO buffer might not be big enough?
			int n = read(clientSocketFD, &serverMemory->buffer[0], ServerMemory::BUFFER_LENGTH);
			if (n < 0) {
				fprintf(stderr, "Failed to read request from client socket\n");
				continue;
			}
			if (n == 0) {
				continue;
			}
			serverMemory->buffer.array.size = n;
		}

		HTTPRequestMethod method;
		HTTPVersion version;
		FixedArray<char, URI_PATH_MAX_LENGTH> uri;
		uri.Init();
		if (!ParseHTTPRequest(serverMemory->buffer.array, &method, &version, &uri)) {
			// TODO bleh
		}
		printf("HTTP version %d request, method %d, URI: %.*s\n",
			version, method, (int)uri.array.size, uri.array.data);

		HTTPWriter<ServerMemory::BUFFER_LENGTH> httpWriter;
		serverMemory->buffer.array.size = 0;
		httpWriter.bufferPtr = &serverMemory->buffer;
		httpWriter.isHttps = isHttps;
		httpWriter.socketFD = clientSocketFD;
		httpWriter.ssl = ssl;

		bool success = false;
		switch (method) {
			case HTTP_REQUEST_GET: {
				success = HandleGetRequest(uri.array, &httpWriter);
			} break;
			case HTTP_REQUEST_POST: {
				// success = HandlePostRequest(uri, httpState, httpWriter, xmlParseState);
			} break;
			default: {
				fprintf(stderr, "Unhandled HTTP request method\n");
				continue;
			} break;
		}
		if (!success) {
			fprintf(stderr, "Failed to handle HTTP request\n");
			continue;
		}

		/*if (httpWriter.bufferSize != 0) {
			fprintf(stderr, "Unflushed data in HTTP writer after handler\n");
			httpWriter.Flush();
		}*/

		if (isHttps) {
			SSL_shutdown(ssl);
			SSL_free(ssl);
		}

		printf("Closed HTTP client connection\n");
	}

	printf("Stopped server on port %d\n", port);
}

void* HttpsServerThread(void* data)
{
	RunServer((ServerMemory*)data, PORT_HTTPS, true);
	return nullptr;
}

int main(int argc, char* argv[])
{
	if (ServerMemory::BUFFER_LENGTH > SSIZE_MAX) {
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
	httpMemory->Init();
	ServerMemory* httpsMemory = (ServerMemory*)((char*)allocatedMemory + sizeof(ServerMemory));
	httpsMemory->Init();
	printf("Allocated %zu bytes (%.03f MB) for HTTP and HTTPS servers\n", allocatedMemorySize,
		(float)allocatedMemorySize / MEGABYTES(1));

	logState_ = (LogState*)((char*)allocatedMemory + 2 * sizeof(ServerMemory));

	pthread_t thread;
	pthread_create(&thread, NULL, HttpsServerThread, (void*)httpsMemory);

	RunServer(httpMemory, PORT_HTTP, false);

	pthread_kill(thread, 15);
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