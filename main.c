/*####################################################
##                                                  ##
##              HTTPS Server in C                   ##
##              By William Hocking                  ##
##                                                  ##
####################################################*/

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

// HTTP Constants
#define HTTP_OK                 200
#define HTTP_BAD_REQUEST        400
#define HTTP_NOT_FOUND          404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_INTERNAL_ERROR     500

// HTTP Message Macros
#define HTTP_MSG_OK             "OK"
#define HTTP_MSG_BAD_REQUEST    "Bad Request"
#define HTTP_MSG_NOT_FOUND      "Not Found"
#define HTTP_MSG_METHOD_NOT_ALLOWED "Method Not Allowed"
#define HTTP_MSG_INTERNAL_ERROR "Internal Server Error"

// Max length macros
#define MAX_REQUEST_SIZE 8192
#define MAX_PATH_LEN 1024

// Other macros
#define DEFAULT_PORT 4433
#define BACKLOG_QUEUE 10

 struct {
         char *ext;
         char *fileType;
} extensions[] = {
          {"gif", "image/gif" },  {"jpg", "image/jpg" }, {"jpeg","image/jpeg"},
          {"png", "image/png" },  {"ico", "image/ico" },  {"zip", "image/zip" },
          {"gz",  "image/gz"  },  {"tar", "image/tar" },  {"htm", "text/html" },
          {"html","text/html" },  {0,0}
};


const char *GetMimeType(const char *path) {
	const char *ext = strrchr(path, '.');
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
	switch (status) {
		case HTTP_OK: return HTTP_MSG_OK;
		case HTTP_BAD_REQUEST: return HTTP_MSG_BAD_REQUEST;
		case HTTP_NOT_FOUND: return HTTP_MSG_NOT_FOUND;
		case HTTP_METHOD_NOT_ALLOWED: return HTTP_MSG_METHOD_NOT_ALLOWED;
		case HTTP_INTERNAL_ERROR: return HTTP_MSG_INTERNAL_ERROR;
		default: return "Unknown status.";
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

void HandleGet(SSL *ssl, const char *path) {
	char fullPath[MAX_PATH_LEN];
	if (strcmp(path, "/") == 0) {
		snprintf(fullPath, sizeof(fullPath), "www/index.html");
	} else {
		snprintf(fullPath, sizeof(fullPath), "www%s", path);
	}

	FILE *fp = fopen(fullPath, "rb");
	printf("%s", fullPath);
	if (!fp) {
		WriteError(ssl, HTTP_NOT_FOUND);
		return;
	}
	printf("Resolved path: %s\n", fullPath);
	// Get file size
	struct stat st;
	stat(fullPath, &st);
	size_t fileSize = st.st_size;

	// Read file content
	char *fileBuffer = malloc(fileSize);
	if (!fileBuffer) {
		WriteError(ssl, HTTP_INTERNAL_ERROR);
		fclose(fp);
		return;
	}
	if (fread(fileBuffer, 1, fileSize, fp) != fileSize) {
 		perror("Failed to read file");
        	WriteError(ssl, HTTP_INTERNAL_ERROR);
        	free(fileBuffer);
        	fclose(fp);
    		return;
	}
	fclose(fp);

	// Get content type from file extension
	const char *ext = strrchr(fullPath, '.');
	const char *contentType = GetMimeType(fullPath);
	printf("Serving file: %s with Content-Type: %s\n", fullPath, contentType);
	
	// Send HTTP headers
	char header[512];
	snprintf(header, sizeof(header),
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: %s\r\n"
		"Connection: close\r\n"
		"\r\n",
		fileSize, contentType);
	SSL_write(ssl, header, strlen(header));

	// Send file content
	SSL_write(ssl, fileBuffer, fileSize);
	free(fileBuffer);
}

void HandleRequest(SSL *ssl, const char *request) {
    char method[16] = {0};
    char path[MAX_PATH_LEN] = {0};
    char protocol[16] = {0};

    // Parse request line
    if (sscanf(request, "%15s %1023s %15s", method, path, protocol) != 3) {
        WriteError(ssl, HTTP_BAD_REQUEST);
        return;
    }

    // Verify protocol (optional but recommended)
    if (strncmp(protocol, "HTTP/", 5) != 0) {
        WriteError(ssl, HTTP_BAD_REQUEST);
        return;
    }

    // Validate method
    if (strcmp(method, "GET") == 0) {
        // Sanitize path
        if (strstr(path, "..") != NULL) {  // Basic path traversal protection
            WriteError(ssl, HTTP_BAD_REQUEST);
            return;
        }
        
        HandleGet(ssl, path);
    }
    else if (strcmp(method, "PUT") == 0 || strcmp(method, "POST") == 0) { 
        WriteError(ssl, HTTP_METHOD_NOT_ALLOWED);
    }
    else {
        WriteError(ssl, HTTP_METHOD_NOT_ALLOWED);
    }
}


int main(int argc, char **argv) {
	int serverSocket, clientSocket;
	
	struct sockaddr_in serverAddr, clientAddr;
	socklen_t clientLen = sizeof(clientAddr);
	char request[MAX_REQUEST_SIZE];

	serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket < 0) {
		perror("Failed to create socket.\n");
		exit(EXIT_FAILURE);
	}

	int opt = 1;
	setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));	

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_port = htons(DEFAULT_PORT);

	if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
		perror("Bind Failed\n");
		exit(EXIT_FAILURE);
	}
	
	if (listen(serverSocket, BACKLOG_QUEUE) < 0) {
		perror("Listen failed.\n");
		exit(EXIT_FAILURE);
	}

	printf("Server running on port %d\n", DEFAULT_PORT);
	
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Ensure certificate is read. Exit on failure.
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
    		ERR_print_errors_fp(stderr);
    		exit(EXIT_FAILURE);
	}
	// Ensure private key is read. Exit on failure.
	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
    		ERR_print_errors_fp(stderr);
   		exit(EXIT_FAILURE);
	}

	while (1) {
		clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientLen);
		if (clientSocket < 0) {
			perror("Accept failed.\n");
			continue;
		}
			

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, clientSocket);
		
		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			SSL_free(ssl);
			close(clientSocket);
			continue;
		}

		ssize_t bytesRead = SSL_read(ssl, request, sizeof(request) - 1);
		if (bytesRead < 0) {
			perror("SSL Read failed.\n");
			SSL_free(ssl);
			close(clientSocket);
			continue;
		}
		request[bytesRead] = '\0';
		HandleRequest(ssl, request);
		
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(clientSocket);
	}
	
	SSL_CTX_free(ctx);
	EVP_cleanup();
	return 0;
}
