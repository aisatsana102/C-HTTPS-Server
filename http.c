/*##########################
##                        ##
##                        ##
##########################*/

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/stat.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>


#include "http.h"
#include "extensions.h"



const char *GetMimeType(const char *path) {
	const char *ext = strchr(path, '.');
	if (!ext) return "text/plain";
	
	ext++;
	
	for (int i = 0; extensions[i].ext != 0; i++) {
		if (strcasecmp(ext, extensions[i].ext) == 0) {
			return extensions[i].fileType;
		}
	}

	return "text/plain";
}


const char* GetHTTPStatusMessage(int status) {
	switch(status) {
		case HTTP_OK: return HTTP_MSG_OK;
		case HTTP_BAD_REQUEST: return HTTP_MSG_BAD_REQUEST;
		case HTTP_NOT_FOUND: return HTTP_MSG_NOT_FOUND;
		case HTTP_METHOD_NOT_ALLOWED: return HTTP_MSG_METHOD_NOT_ALLOWED;
		case HTTP_INTERNAL_ERROR: return HTTP_MSG_INTERNAL_ERROR;
		default: return "Unkown status.";
	}
}

void WriteError(SSL *ssl, int status) {
	char response[1024];
	snprintf(response, sizeof(response),
	"HTTP/1.1 %d %s\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"%d %s",
	status, GetHTTPStatusMessage(status),
	status, GetHTTPStatusMessage(status));
	
	SSL_write(ssl, response, strlen(response));
}

int ParseRequestLine(const char *request, HTTPRequest *req) {
	if (sscanf(request, "%15s %1023s %15s", req -> method, req -> path, req -> httpVersion) != 3) {
		return 0;
	}
	if (strncmp(req -> httpVersion, "HTTP/", 5) != 0) {
		return 0;
	}
	if (strstr(req -> path, "..") != NULL) {
		return 0;
	}
	return 1;
}

void HandleGet(SSL *ssl, const char *path) {
	char fullPath[MAX_PATH_LEN];
	if (strcmp(path, "/") == 0) {
		snprintf(fullPath, sizeof(fullPath), "www/index.html");
	} else {
		snprintf(fullPath, sizeof(fullPath), "www%s", path);	
	}

	FILE *fp = fopen(fullPath, "rb");
	if (!fp) {
		WriteError(ssl, HTTP_NOT_FOUND);
		return;
	}
	
	// Get file size.
	struct stat st;
	stat(fullPath, &st);
	size_t fileSize = st.st_size;

	// Read File Content.
	char *fileBuffer = malloc(fileSize);
	if (!fileBuffer) {
		WriteError(ssl, HTTP_INTERNAL_ERROR);
		fclose(fp);
		return;
	}
	if (fread(fileBuffer, 1, fileSize, fp) != fileSize) {
		perror("Failed to read file.");	
		WriteError(ssl, HTTP_INTERNAL_ERROR);
		free(fileBuffer);
		fclose(fp);
	}

	fclose(fp);

	const char *ext = strchr(fullPath, '.');
	const char *contentType = GetMimeType(fullPath);
	printf("Serving file: %s with Content-Type: %s\n", fullPath, contentType);
	

	char header[512];
	snprintf(header, sizeof(header),
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: %s\r\n"
		"Connection: close\r\n"
		"\r\n",
		fileSize, contentType);
	SSL_write(ssl, header, strlen(header));
	SSL_write(ssl, fileBuffer, fileSize);
	free(fileBuffer);
}	

void HandleRequest(SSL *ssl, const char *rawRequest) {
	HTTPRequest req = {0};

	if (!ParseRequestLine(rawRequest, &req)) {
		WriteError(ssl, HTTP_BAD_REQUEST);
		return;
	}
	if (strcmp(req.method, "GET") == 0) {
		HandleGet(ssl, req.path);
	} else if (strcmp(req.method, "PUT") == 0 || strcmp(req.method, "POST") == 0) {
		WriteError(ssl, HTTP_METHOD_NOT_ALLOWED);
	} else {
		WriteError(ssl, HTTP_METHOD_NOT_ALLOWED);
	}
}
